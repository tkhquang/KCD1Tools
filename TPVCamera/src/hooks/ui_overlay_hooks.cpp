/**
 * @file hooks/ui_overlay_hooks.cpp
 * @brief KCD1 overlay/apse detection via the CryEngine action-filter worker.
 *
 * KCD2 drove overlay_state().active from a HideOverlays/ShowOverlays pair whose entry AOBs get 0 matches on
 * KCD1 1.9.7. KCD1 has no equivalent central overlay pair, but every blocking apse/UI screen instead enables
 * a NAMED action filter on CActionMapManager, and in plain gameplay NO filter is enabled. All
 * EnableFilter/DisableFilter calls funnel through one worker, sub_1804FCC0C, so this hooks that worker and
 * sets overlay_state().active while an apse filter ("only_ui" = inventory/codex/menu, "only_map" = world map,
 * "only_dialog" = dialogue) is held. Covering dialogue here matches KCD2, where the overlay spans inventory,
 * map, dialog screen and codex, so the default SuppressTPVState="Overlay" hides the TPV offset in dialogue too.
 * The unit keeps the KCD2 file + initialize_ui_overlay_hooks() API and the overlay_state() output, so
 * game_state.cpp / camera_hook.cpp / tpv_camera.cpp are unchanged between the two builds; only the internal
 * hook mechanism differs (resolved at runtime by the OverlayHide AOB cascade, mirroring the menu/onaction hooks). The
 * separate Dialogue game-state bit is still classified by active-camera RTTI (C_CameraDialog) in game_state.cpp.
 */

#include "ui_overlay_hooks.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace TPVCamera
{

    // Action-filter enable/disable worker sub_1804FCC0C. enable_raw is a
    // 64-bit register slot whose low byte is the enable flag (!=0 enable, 0 disable); the upper bytes are
    // unused by the engine, so they are forwarded verbatim. name is the filter name (a null/empty name is the
    // engine "all filters" branch). The return value is propagated unchanged (EnableFilter/DisableFilter
    // return it to their callers).
    using ActionFilterWorkerFunc = void *(__fastcall *)(void *mgr, const char *name, std::int64_t enable_raw,
                                                        unsigned int a4, char a5);

    static ActionFilterWorkerFunc s_worker_original = nullptr;

    // Apse filters whose held state means "a blocking apse/UI screen is up". One refcount per filter, written
    // on the input/main thread by the detour and read by publish_overlay; relaxed atomics suffice (a one-frame
    // stale signal is harmless). Refcounts (not bools) mirror the engine: a screen enables on open and disables
    // on close, and nested enables of the same filter stay balanced.
    static constexpr std::array<std::string_view, 4> k_overlay_filters = {
        Constants::ACTION_FILTER_ONLY_UI,     // inventory / codex / in-game menu overlay
        Constants::ACTION_FILTER_ONLY_MAP,    // world map
        Constants::ACTION_FILTER_ONLY_DIALOG, // dialogue (matches KCD2: the overlay covers the dialog screen)
        Constants::ACTION_FILTER_ONLY_MENU,   // main menu / frontend (so TPV never applies to the menu camera)
    };
    static std::atomic<int> s_filter_counts[k_overlay_filters.size()]{};

    /**
     * @brief Recompute overlay_state().active from the tracked refcounts: active while any apse filter is held.
     */
    static void publish_overlay()
    {
        bool any = false;
        for (const std::atomic<int> &count : s_filter_counts)
        {
            if (count.load(std::memory_order_relaxed) > 0)
            {
                any = true;
                break;
            }
        }
        overlay_state().active.store(any, std::memory_order_relaxed);
    }

    /**
     * @brief Update the apse refcounts from one filter enable/disable event. Separated from the SEH wrapper so
     *        this frame holds no unwinding objects; the engine-owned name string is screened before use.
     */
    static void update_overlay_from_filter(const char *name, bool enable)
    {
        // Null/empty name = the engine "all filters" branch (enable/disable every filter at once). On a
        // disable-all, clear our refcounts so the overlay does not latch; an enable-all never raises an apse
        // screen, so it is ignored (treating it as "everything up" would falsely report overlay in gameplay).
        if (name == nullptr || !DMK::Memory::plausible_userspace_ptr(reinterpret_cast<uintptr_t>(name)) ||
            name[0] == '\0')
        {
            if (!enable)
            {
                for (std::atomic<int> &count : s_filter_counts)
                {
                    count.store(0, std::memory_order_relaxed);
                }
                publish_overlay();
            }
            return;
        }

        const std::string_view name_view(name);
        for (size_t i = 0; i < k_overlay_filters.size(); ++i)
        {
            if (k_overlay_filters[i] == name_view)
            {
                if (enable)
                {
                    s_filter_counts[i].fetch_add(1, std::memory_order_relaxed);
                }
                else
                {
                    // Decrement but clamp at 0 so an unmatched disable cannot drive the count negative.
                    int prev = s_filter_counts[i].load(std::memory_order_relaxed);
                    while (prev > 0 &&
                           !s_filter_counts[i].compare_exchange_weak(prev, prev - 1, std::memory_order_relaxed))
                    {
                    }
                }
                publish_overlay();
                break;
            }
        }
    }

    /**
     * @brief Action-filter worker detour: latch the apse overlay state, then always forward to the original so
     *        the engine's filter handling is untouched. A fault while reading the event is swallowed and the
     *        original still runs (its return value is propagated unchanged).
     */
    static void *__fastcall action_filter_worker_detour(void *mgr, const char *name, std::int64_t enable_raw,
                                                        unsigned int a4, char a5)
    {
        __try
        {
            update_overlay_from_filter(name, (enable_raw & 0xFF) != 0);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
        return s_worker_original ? s_worker_original(mgr, name, enable_raw, a4, a5) : nullptr;
    }

    bool initialize_ui_overlay_hooks()
    {
        DMK::Logger &logger = DMK::Logger::get_instance();

        // Fail closed if the resolved entry leads with a call/breakpoint byte; a sibling mod's E9 jump-hook
        // does not trip this gate, so layering still works.
        const DMK::HookConfig hook_config{.prologue_policy = DMK::InlineProloguePolicy::Fail};

        try
        {
            const uintptr_t module_base = module_info().base;
            if (module_base == 0)
            {
                throw std::runtime_error("module base unknown");
            }
            // OverlayHide is the action-filter worker runtime AOB cascade (k_actionFilterWorkerCandidates); a
            // total cascade miss fails closed.
            const uintptr_t worker_addr = anchor_address(AnchorId::OverlayHide);
            if (worker_addr == 0)
            {
                throw std::runtime_error("OverlayHide cascade unresolved (action-filter worker)");
            }

            DMK::HookManager &hook_manager = DMK::HookManager::get_instance();
            auto result = hook_manager.create_inline_hook(
                "ActionFilterWorker", worker_addr, reinterpret_cast<void *>(action_filter_worker_detour),
                reinterpret_cast<void **>(&s_worker_original), hook_config);

            if (!result.has_value())
            {
                throw std::runtime_error("Failed to create action-filter worker hook: " +
                                         std::string(DMK::Hook::error_to_string(result.error())));
            }

            logger.info("UIOverlayHook: hooked action-filter worker at {} (overlay/apse detection enabled)",
                        DMK::Format::format_address(worker_addr));
            return true;
        }
        catch (const std::exception &e)
        {
            logger.error("UIOverlayHook: Initialization failed: {}", e.what());
            return false;
        }
    }

} // namespace TPVCamera
