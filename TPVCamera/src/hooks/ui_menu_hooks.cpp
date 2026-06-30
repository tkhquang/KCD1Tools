/**
 * @file hooks/ui_menu_hooks.cpp
 * @brief KCD1 in-game menu open/close detection via the wh::guimodule menu toggle.
 *
 * KCD2 hooked two separate vtable functions (MenuOpen / MenuClose) whose entry AOBs get 0 matches on KCD1.
 * KCD1 instead funnels every in-game-menu open/close through ONE toggle, sub_1805B84CC(this, char display)
 * -- the "DisplayIngameMenu" convergence (found via the C_UIMenuEvents registry). This hooks it and latches
 * display into is_game_menu_open(). Resolved at runtime by the MenuOpen AOB cascade (mirrors the other hooks).
 * The API matches KCD2 so the call sites (game_state.cpp, tpv_camera.cpp) are unchanged between the builds.
 */

#include "ui_menu_hooks.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <atomic>
#include <stdexcept>

namespace TPVCamera
{

    // wh::guimodule in-game menu toggle: void(this, char display). display = 1 opens the menu, 0 closes it.
    using MenuToggleFunc = void(__fastcall *)(void *this_ptr, char display);

    static MenuToggleFunc s_menu_toggle_original = nullptr;
    static std::atomic<bool> s_is_menu_open(false);

    /**
     * @brief Menu-toggle detour: latch the requested open/close state, then call the original exactly once.
     * @details No SEH frame and no C++ try: the detour only logs (no-throw) and stores a mod-owned atomic, so
     *          it performs no foreign-memory dereference and cannot throw. The original is invoked outside any
     *          guard so the engine function runs exactly once. The toggle itself no-ops on an unchanged state,
     *          but `display` is the requested state either way, so the latch always tracks the menu.
     */
    static void __fastcall menu_toggle_detour(void *this_ptr, char display)
    {
        const bool open = display != 0;
        (void)DMK::Logger::get_instance().log_noexcept(
            DMK::LogLevel::Debug, open ? "UIMenuHook: in-game menu opening" : "UIMenuHook: in-game menu closing");
        s_is_menu_open.store(open, std::memory_order_relaxed);

        if (s_menu_toggle_original)
        {
            s_menu_toggle_original(this_ptr, display);
        }
    }

    bool initialize_ui_menu_hooks()
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
            // MenuOpen is the menu open/close toggle runtime AOB cascade (k_menuToggleCandidates); a total
            // cascade miss fails closed.
            const uintptr_t toggle_addr = anchor_address(AnchorId::MenuOpen);
            if (toggle_addr == 0)
            {
                throw std::runtime_error("MenuOpen cascade unresolved (menu toggle)");
            }

            DMK::HookManager &hook_manager = DMK::HookManager::get_instance();
            auto result = hook_manager.create_inline_hook(
                "MenuToggle", toggle_addr, reinterpret_cast<void *>(menu_toggle_detour),
                reinterpret_cast<void **>(&s_menu_toggle_original), hook_config);

            if (!result.has_value())
            {
                throw std::runtime_error("Failed to create menu toggle hook: " +
                                         std::string(DMK::Hook::error_to_string(result.error())));
            }

            logger.info("UIMenuHook: hooked in-game menu toggle at {} (menu detection enabled)",
                        DMK::Format::format_address(toggle_addr));
            return true;
        }
        catch (const std::exception &e)
        {
            logger.error("UIMenuHook: Initialization failed: {}", e.what());
            return false;
        }
    }

    bool is_game_menu_open() noexcept
    {
        return s_is_menu_open.load(std::memory_order_relaxed);
    }

} // namespace TPVCamera
