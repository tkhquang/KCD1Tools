/**
 * @file render/engine_silhouette.cpp
 * @brief The CHudSilhouettes parameters, the mask-pass state override, the outline-copy hook and the state report.
 */

#include "render/engine_silhouette.hpp"
#include "aob_resolver.hpp"
#include "config.hpp"
#include "constants.hpp"
#include "global_state.hpp"
#include "rtti_types.hpp"
#include "engine/engine_env.hpp"
#include "engine/seh.hpp"
#include "render/herb_outline.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace HenrySenses
{
    namespace
    {
        using SetPostEffectParamFn =
            void(__fastcall *)(std::uintptr_t engine, const char *name, float value, bool force);

        /**
         * @brief HudSilhouettes_Type of the binocular mode, whose composite strength is a fixed 0.8.
         * @details Type 1 scales the strength by HudSilhouettes_Amount, which Render clamps to 1, so its peak is 0.264.
         */
        constexpr int BINOCULAR_TYPE = 0;
        /// The parameter change below which a write is skipped.
        constexpr float PARAM_EPSILON = 0.001f;

        /**
         * @struct EffectParams
         * @brief One set of the three CHudSilhouettes parameters.
         */
        struct EffectParams
        {
            float amount{1.0f};
            float fill_str{0.15f};
            int type{1};
        };

        using RenderCustomSceneFn = void(__fastcall *)(std::uintptr_t renderer);

        /**
         * @struct MaskStateLayout
         * @brief The renderer members the mask-pass override writes, decoded from the game's code at install.
         * @details The layout keeps the gRenDev slot rather than the renderer. An ASI loads before the renderer
         *          exists, and the slot holds null until the renderer starts, so the detour reads it on every call.
         */
        struct MaskStateLayout
        {
            /// The gRenDev slot in the game image, which holds the CD3D9Renderer the hook expects in rcx.
            std::uintptr_t renderer_slot{0};
            /// m_RP.m_ForceStateOr: FX_CommitStates ORs it into every committed render state.
            std::ptrdiff_t force_state_or{0};
            /// m_RP.m_PersFlags2.
            std::ptrdiff_t pers_flags2{0};
            /// The PersFlags2 bit that adds %_RT_SAMPLE5 to the custom render pass.
            std::uint32_t sample5_bit{0};
        };

        /// How long the teardown waits for a render-thread call of the hook to return.
        constexpr DWORD MASK_RUNDOWN_TIMEOUT_MS = 3000;
        /// Settle time after the counter reads zero, for a call that took the patch jump but did not count itself yet.
        constexpr DWORD MASK_ENTRY_WINDOW_MS = 50;

        /// The original FX_RenderCustomScene and the renderer layout, both published before the hook is enabled.
        RenderCustomSceneFn s_render_custom_scene_original = nullptr;
        MaskStateLayout s_mask_layout{};
        /// The hook exists and the teardown must drain it.
        std::atomic<bool> s_mask_hooked{false};
        /// The hook is enabled, so the override reaches the mask pass.
        std::atomic<bool> s_mask_live{false};
        std::atomic<bool> s_mask_armed{false};
        /// What the next mask pass applies, published by the main-thread tick.
        std::atomic<bool> s_mask_see_through{false};
        std::atomic<bool> s_mask_no_near_fade{false};
        std::atomic<int> s_mask_in_flight{0};
        std::atomic<std::uint64_t> s_mask_calls{0};
        std::atomic<std::uint64_t> s_mask_overrides{0};

        /**
         * @brief FX_RenderCustomScene detour: draws the HUD silhouette mask with the mod's state override.
         * @details For this call only, it adds GS_NODEPTHTEST to the renderer's ForceStateOr, so the CustomRenderPass
         *          ignores the scene depth and the mask holds whole silhouettes (see-through). It also sets the
         *          PersFlags2 bit that selects the %_RT_SAMPLE5 permutation, whose SilhoueteVisionOptimised skips the
         *          fade of objects nearer than 1.5 m to the camera. Both members are restored before the detour returns,
         *          so no other pass sees them.
         * @param renderer The CD3D9Renderer.
         */
        void __fastcall render_custom_scene_detour(std::uintptr_t renderer) noexcept
        {
            s_mask_in_flight.fetch_add(1, std::memory_order_acq_rel);
            s_mask_calls.fetch_add(1, std::memory_order_relaxed);
            // The slot lies in the game image, which stays mapped, so a plain read is safe. It holds null until the
            // renderer starts.
            const std::uintptr_t current =
                *reinterpret_cast<const volatile std::uintptr_t *>(s_mask_layout.renderer_slot);
            const bool armed = s_mask_armed.load(std::memory_order_acquire) && renderer != 0 && renderer == current;
            const bool see_through = armed && s_mask_see_through.load(std::memory_order_relaxed);
            const bool no_near_fade = armed && s_mask_no_near_fade.load(std::memory_order_relaxed);
            if (!see_through && !no_near_fade)
            {
                s_render_custom_scene_original(renderer);
                s_mask_in_flight.fetch_sub(1, std::memory_order_acq_rel);
                return;
            }

            auto *const force_or = reinterpret_cast<volatile std::uint32_t *>(renderer + s_mask_layout.force_state_or);
            auto *const pers_flags2 = reinterpret_cast<volatile std::uint32_t *>(renderer + s_mask_layout.pers_flags2);
            const std::uint32_t saved_force_or = *force_or;
            const bool had_sample5 = (*pers_flags2 & s_mask_layout.sample5_bit) != 0;
            if (see_through)
            {
                *force_or = saved_force_or | constants::GS_NODEPTHTEST;
            }
            if (no_near_fade)
            {
                *pers_flags2 = *pers_flags2 | s_mask_layout.sample5_bit;
            }

            s_render_custom_scene_original(renderer);

            // Only the members this call changed go back, so a change the original made to the other one stays.
            if (see_through)
            {
                *force_or = saved_force_or;
            }
            if (no_near_fade && !had_sample5)
            {
                *pers_flags2 = *pers_flags2 & ~s_mask_layout.sample5_bit;
            }
            s_mask_overrides.fetch_add(1, std::memory_order_relaxed);
            s_mask_in_flight.fetch_sub(1, std::memory_order_acq_rel);
        }

        /**
         * @brief Installs the FX_RenderCustomScene hook when the MaskState gate passed.
         * @param hooks The mod's hook set.
         * @return An empty value, or the Error that refused the install.
         */
        [[nodiscard]] DMK::Result<void> install_mask_state_hook(HookSet &hooks)
        {
            if (!feature_ready(Feature::MaskState))
            {
                return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "engine_silhouette/mask_state_gate"});
            }
            const std::optional<std::int64_t> force_or = gated_anchor_value(Feature::MaskState, AnchorId::ForceStateOr);
            const std::optional<std::int64_t> pers_flags2 =
                gated_anchor_value(Feature::MaskState, AnchorId::PersFlags2);
            const std::optional<std::int64_t> sample5 =
                gated_anchor_value(Feature::MaskState, AnchorId::Post3dSample5Bit);
            // The renderer itself is not required here: at a game start the mod loads before it exists.
            const std::uintptr_t renderer_slot = gated_anchor_address(Feature::MaskState, AnchorId::RenDev);
            if (!force_or || !pers_flags2 || !sample5 || renderer_slot == 0)
            {
                return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "engine_silhouette/mask_state_layout"});
            }
            s_mask_layout = MaskStateLayout{
                .renderer_slot = renderer_slot,
                .force_state_or = static_cast<std::ptrdiff_t>(*force_or),
                .pers_flags2 = static_cast<std::ptrdiff_t>(*pers_flags2),
                .sample5_bit = static_cast<std::uint32_t>(*sample5),
            };

            const std::uintptr_t target = gated_anchor_address(Feature::MaskState, AnchorId::RenderCustomScene);
            DMK_TRY(
                created,
                DMK::hook::inline_at(
                    DMK::hook::InlineRequest{
                        .name = "RenderCustomScene",
                        .target = DMK::Address{target},
                    },
                    render_custom_scene_detour
                )
            );
            s_render_custom_scene_original = created.original<RenderCustomSceneFn>();
            // Stored before it is armed: the set owns it through teardown even when the arm fails half-way.
            DMK::hook::Hook &stored = hooks.push(std::move(created));
            s_mask_hooked.store(true, std::memory_order_release);
            s_mask_armed.store(true, std::memory_order_release);
            const DMK::Result<void> enabled = stored.enable();
            s_mask_live.store(stored.is_enabled(), std::memory_order_release);
            if (!enabled)
            {
                return std::unexpected(enabled.error());
            }
            const auto renderer = DMK::memory::read<std::uintptr_t>(DMK::Address{renderer_slot});
            DMK::log().info(
                "EngineSilhouette: mask pass hooked at {} (RVA {:#x}); ForceStateOr +{:#x}, PersFlags2 +{:#x}, SAMPLE5 "
                "bit {:#x}, renderer {}",
                DMK::format::format_address(target),
                target - module_info().base,
                s_mask_layout.force_state_or,
                s_mask_layout.pers_flags2,
                s_mask_layout.sample5_bit,
                renderer && *renderer != 0 ? DMK::format::format_address(*renderer) : std::string{"not created yet"}
            );
            return {};
        }

        using RenderInternalFn = std::uintptr_t(__fastcall *)(
            void *stat_obj,
            void *render_object,
            void *hide_mask,
            void *lod_value,
            const void *pass_info,
            const void *sorter
        );

        /**
         * @brief Stripe count of the static-mesh hook's in-flight counter.
         * @details CStatObj::RenderInternal runs for every static mesh on every 3D-engine job thread, so the count is
         *          striped per thread and stays off one contended cache line.
         */
        constexpr std::size_t COPY_STRIPES = 32;
        constexpr std::size_t CACHE_LINE = 64;

        /**
         * @struct InFlightStripe
         * @brief One cache line of the static-mesh hook's in-flight counter.
         */
        struct InFlightStripe
        {
            std::atomic<int> count{0};
            char padding[CACHE_LINE - sizeof(std::atomic<int>)]{};
        };

        std::array<InFlightStripe, COPY_STRIPES> s_copy_in_flight{};
        RenderInternalFn s_render_internal_original = nullptr;
        /// The hook exists and the teardown must drain it.
        std::atomic<bool> s_copies_hooked{false};
        /// The hook is enabled, so a published copy reaches the frame.
        std::atomic<bool> s_copies_live{false};
        std::atomic<bool> s_copies_armed{false};

        /**
         * @class StripedInFlightScope
         * @brief Counts the calling thread inside the static-mesh render hook for the scope's lifetime.
         */
        class StripedInFlightScope
        {
        public:
            StripedInFlightScope() noexcept
                : m_count(s_copy_in_flight[(GetCurrentThreadId() >> 2) % COPY_STRIPES].count)
            {
                m_count.fetch_add(1, std::memory_order_acq_rel);
            }
            ~StripedInFlightScope() noexcept { m_count.fetch_sub(1, std::memory_order_acq_rel); }
            StripedInFlightScope(const StripedInFlightScope &) = delete;
            StripedInFlightScope &operator=(const StripedInFlightScope &) = delete;

        private:
            std::atomic<int> &m_count;
        };

        /** @brief Reports whether no thread is inside the static-mesh render hook. */
        [[nodiscard]] bool copies_idle() noexcept
        {
            for (const InFlightStripe &stripe : s_copy_in_flight)
            {
                if (stripe.count.load(std::memory_order_acquire) != 0)
                {
                    return false;
                }
            }
            return true;
        }

        /**
         * @brief CStatObj::RenderInternal detour: the original first, then the frame's outline copies.
         * @details The first general-pass static-mesh render of a frame submits the published copies
         *          (herb_outline_on_render). The arguments are engine-owned and valid for the call. [KCD2 P3b also
         *          marks the render object here]
         */
        std::uintptr_t __fastcall detour_render_internal(
            void *stat_obj,
            void *render_object,
            void *hide_mask,
            void *lod_value,
            const void *pass_info,
            const void *sorter
        ) noexcept
        {
            const StripedInFlightScope scope;
            const std::uintptr_t result =
                s_render_internal_original(stat_obj, render_object, hide_mask, lod_value, pass_info, sorter);
            if (s_copies_armed.load(std::memory_order_relaxed))
            {
                herb_outline_on_render(pass_info, sorter);
            }
            return result;
        }

        /**
         * @brief Installs the CStatObj::RenderInternal hook when the OutlineCopies and MaskMaterial gates passed.
         * @details Every copy draws with a mask material, so the hook is useless without one.
         * @param hooks The mod's hook set.
         * @return An empty value, or the Error that refused the install.
         */
        [[nodiscard]] DMK::Result<void> install_outline_copy_hook(HookSet &hooks)
        {
            const std::uintptr_t target = gated_anchor_address(Feature::OutlineCopies, AnchorId::StatObjRenderInternal);
            if (target == 0 || !feature_ready(Feature::MaskMaterial))
            {
                return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "engine_silhouette/outline_copies_gate"});
            }
            DMK_TRY(
                created,
                DMK::hook::inline_at(
                    DMK::hook::InlineRequest{
                        .name = "StatObjRenderInternal",
                        .target = DMK::Address{target},
                    },
                    detour_render_internal
                )
            );
            s_render_internal_original = created.original<RenderInternalFn>();
            // Stored before it is armed: the set owns it through teardown even when the arm fails half-way.
            DMK::hook::Hook &stored = hooks.push(std::move(created));
            s_copies_hooked.store(true, std::memory_order_release);
            s_copies_armed.store(true, std::memory_order_release);
            const DMK::Result<void> enabled = stored.enable();
            s_copies_live.store(stored.is_enabled(), std::memory_order_release);
            if (!enabled)
            {
                return std::unexpected(enabled.error());
            }
            DMK::log().info(
                "EngineSilhouette: static-mesh render hooked at {} (RVA {:#x}); herbs and static objects can be outlined",
                DMK::format::format_address(target),
                target - module_info().base
            );
            return {};
        }

        std::atomic<bool> s_ready{false};
        std::atomic<bool> s_armed{false};
        /// The game's own values, captured at init and put back at shutdown. Main thread after init.
        EffectParams s_original{};
        bool s_original_known = false;
        /// The values this generation applied last, or std::nullopt until the first write.
        std::optional<EffectParams> s_applied;

        /**
         * @brief Finds the CHudSilhouettes instance in the post-effects manager's effect list.
         * @return The effect, or 0.
         */
        [[nodiscard]] std::uintptr_t find_hud_silhouettes() noexcept
        {
            const std::uintptr_t slot = gated_anchor_address(Feature::SilhouetteState, AnchorId::RenDev);
            if (slot == 0)
            {
                return 0;
            }
            const std::array<std::ptrdiff_t, 2> chain{0, constants::RENDERER_POST_EFFECTS_MGR_OFFSET};
            const auto manager = DMK::memory::walk(DMK::Address{slot}, chain);
            if (!manager)
            {
                return 0;
            }
            const auto mgr = DMK::memory::read<std::uintptr_t>(*manager);
            if (!mgr || !DMK::memory::is_plausible_ptr(DMK::Address{*mgr}))
            {
                return 0;
            }
            const auto begin = DMK::memory::read<std::uintptr_t>(
                DMK::Address{*mgr + constants::POST_EFFECTS_MGR_EFFECTS_BEGIN_OFFSET}
            );
            const auto end =
                DMK::memory::read<std::uintptr_t>(DMK::Address{*mgr + constants::POST_EFFECTS_MGR_EFFECTS_END_OFFSET});
            constexpr std::size_t max_effects = 128;
            if (!begin || !end || *end < *begin || (*end - *begin) / sizeof(std::uintptr_t) > max_effects)
            {
                return 0;
            }
            for (std::uintptr_t cursor = *begin; cursor < *end; cursor += sizeof(std::uintptr_t))
            {
                const auto effect = DMK::memory::read<std::uintptr_t>(DMK::Address{cursor});
                if (effect && object_is(GameClass::HudSilhouettes, *effect))
                {
                    return *effect;
                }
            }
            return 0;
        }

        /**
         * @brief Reads the main-thread value of one parameter object of the effect.
         * @tparam T float for a CParamFloat, int for a CParamInt.
         */
        template <typename T>
        [[nodiscard]] std::optional<T> read_effect_param(std::uintptr_t effect, std::ptrdiff_t member) noexcept
        {
            const auto param = DMK::memory::read<std::uintptr_t>(DMK::Address{effect + member});
            if (!param || !DMK::memory::is_plausible_ptr(DMK::Address{*param}))
            {
                return std::nullopt;
            }
            const auto value = DMK::memory::read<T>(DMK::Address{*param + constants::POST_EFFECT_PARAM_VALUE_OFFSET});
            return value ? std::optional<T>{*value} : std::nullopt;
        }

        /**
         * @brief Reads an int CVar value through its data anchor, or std::nullopt.
         * @param feature The feature gate the caller relies on, which must list @p id.
         */
        [[nodiscard]] std::optional<std::int32_t> read_cvar(Feature feature, AnchorId id) noexcept
        {
            const std::uintptr_t address = gated_anchor_address(feature, id);
            if (address == 0)
            {
                return std::nullopt;
            }
            const auto value = DMK::memory::read<std::int32_t>(DMK::Address{address});
            return value ? std::optional<std::int32_t>{*value} : std::nullopt;
        }

        /**
         * @brief Calls I3DEngine::SetPostEffectParam under SEH.
         * @return True when the call returned.
         */
        [[nodiscard]] bool
        call_set_param(std::uintptr_t fn, std::uintptr_t engine, const char *name, float value) noexcept
        {
            __try
            {
                reinterpret_cast<SetPostEffectParamFn>(fn)(engine, name, value, true);
                return true;
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return false;
            }
        }

        /**
         * @brief Writes the parameters of @p wanted that differ from what this generation applied last.
         * @return True when every needed write landed.
         */
        bool apply_params(const EffectParams &wanted) noexcept
        {
            const std::uintptr_t engine = genv_interface(constants::GENV_3DENGINE_OFFSET);
            if (engine == 0 || !object_is(GameClass::ThreeDEngine, engine))
            {
                return false;
            }
            const std::uintptr_t fn = validated_vtable_slot(
                engine,
                constants::ENGINE_3D_VTABLE_SET_POST_EFFECT_PARAM_OFFSET,
                AnchorId::SetPostEffectParam
            );
            if (fn == 0)
            {
                return false;
            }
            const auto changed = [](float a, float b) noexcept { return std::fabs(a - b) > PARAM_EPSILON; };
            bool ok = true;
            if (!s_applied || s_applied->type != wanted.type)
            {
                ok = call_set_param(
                         fn,
                         engine,
                         constants::HUD_SILHOUETTES_TYPE_PARAM,
                         static_cast<float>(wanted.type)
                     ) &&
                     ok;
            }
            if (!s_applied || changed(s_applied->amount, wanted.amount))
            {
                ok = call_set_param(fn, engine, constants::HUD_SILHOUETTES_AMOUNT_PARAM, wanted.amount) && ok;
            }
            if (!s_applied || changed(s_applied->fill_str, wanted.fill_str))
            {
                ok = call_set_param(fn, engine, constants::HUD_SILHOUETTES_FILL_STR_PARAM, wanted.fill_str) && ok;
            }
            if (ok)
            {
                s_applied = wanted;
            }
            return ok;
        }
        /**
         * @brief Reads the game's own parameter values from the effect, once it exists.
         * @details At a game start the mod loads before the post-effects manager creates CHudSilhouettes, so the first
         *          try can fail and later ticks try again. A capture after the mod's first write reads the mod's own
         *          values, so the tries stop at that write.
         * @return True when the values are known.
         */
        bool capture_original_params() noexcept
        {
            if (s_original_known)
            {
                return true;
            }
            if (s_applied)
            {
                return false;
            }
            const std::uintptr_t effect = find_hud_silhouettes();
            if (effect == 0)
            {
                return false;
            }
            const auto amount = read_effect_param<float>(effect, constants::HUD_SILHOUETTES_AMOUNT_OFFSET);
            const auto fill = read_effect_param<float>(effect, constants::HUD_SILHOUETTES_FILL_STR_OFFSET);
            const auto type = read_effect_param<int>(effect, constants::HUD_SILHOUETTES_TYPE_OFFSET);
            if (!amount || !fill || !type)
            {
                return false;
            }
            s_original = EffectParams{*amount, *fill, *type};
            s_original_known = true;
            return true;
        }
    } // namespace

    DMK::Result<void> initialize_engine_silhouette(HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();
        s_ready.store(false, std::memory_order_relaxed);
        s_mask_live.store(false, std::memory_order_relaxed);
        s_copies_live.store(false, std::memory_order_relaxed);
        s_mask_see_through.store(false, std::memory_order_relaxed);
        s_mask_no_near_fade.store(false, std::memory_order_relaxed);
        s_applied.reset();
        s_original_known = false;

        if (!feature_ready(Feature::NativeSilhouette))
        {
            return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "engine_silhouette/gate"});
        }

        // The documented defaults stand in until the effect exists. At a game start the mod loads before it, so
        // publish_silhouette_params() reads the game's values on a later tick, before the mod's first write.
        s_original = EffectParams{};
        if (!capture_original_params())
        {
            logger.info("EngineSilhouette: the effect does not exist yet; its parameters are read once it does");
        }

        if (auto copies = install_outline_copy_hook(hooks); !copies)
        {
            logger.warning(
                "EngineSilhouette: outline copies unavailable ({}); herbs and static objects are not outlined",
                copies.error().message()
            );
        }

        if (auto mask = install_mask_state_hook(hooks); !mask)
        {
            logger.warning(
                "EngineSilhouette: mask-pass override unavailable ({}); outlines stay depth-tested and fade near the "
                "camera",
                mask.error().message()
            );
        }

        s_armed.store(true, std::memory_order_release);
        s_ready.store(true, std::memory_order_release);
        log_engine_silhouette_state();
        return {};
    }

    void disarm_engine_silhouette() noexcept
    {
        s_armed.store(false, std::memory_order_release);
        s_mask_armed.store(false, std::memory_order_release);
        s_copies_armed.store(false, std::memory_order_release);
        s_mask_live.store(false, std::memory_order_release);
        s_copies_live.store(false, std::memory_order_release);
        s_mask_see_through.store(false, std::memory_order_relaxed);
        s_mask_no_near_fade.store(false, std::memory_order_relaxed);
    }

    bool shutdown_engine_silhouette() noexcept
    {
        s_ready.store(false, std::memory_order_release);
        if (!s_mask_hooked.load(std::memory_order_acquire) && !s_copies_hooked.load(std::memory_order_acquire))
        {
            return true;
        }
        // The hooks are disabled, so no new call enters them. Wait for a call already inside to return.
        const auto idle = []() noexcept
        { return s_mask_in_flight.load(std::memory_order_acquire) == 0 && copies_idle(); };
        const ULONGLONG deadline = GetTickCount64() + MASK_RUNDOWN_TIMEOUT_MS;
        for (;;)
        {
            while (!idle() && GetTickCount64() < deadline)
            {
                Sleep(1);
            }
            Sleep(MASK_ENTRY_WINDOW_MS);
            if (idle())
            {
                s_mask_hooked.store(false, std::memory_order_release);
                s_copies_hooked.store(false, std::memory_order_release);
                return true;
            }
            if (GetTickCount64() >= deadline)
            {
                (void)DMK::log().log_noexcept(
                    DMK::LogLevel::Error,
                    "EngineSilhouette: a render thread was still inside a render hook at shutdown"
                );
                return false;
            }
        }
    }

    bool engine_see_through_active() noexcept
    {
        return s_mask_live.load(std::memory_order_acquire) && settings().see_through.load(std::memory_order_relaxed);
    }

    bool engine_silhouette_available() noexcept
    {
        if (!s_ready.load(std::memory_order_acquire))
        {
            return false;
        }
        // Without the state anchors the renderer cannot be checked, so the setter alone decides.
        if (!feature_ready(Feature::SilhouetteState))
        {
            return true;
        }
        const std::optional<std::int32_t> visions = read_cvar(Feature::SilhouetteState, AnchorId::CustomVisionsCvar);
        const std::optional<std::int32_t> game_fx =
            read_cvar(Feature::SilhouetteState, AnchorId::PostProcessGameFxCvar);
        if (!visions || !game_fx || *visions == 0 || *game_fx == 0)
        {
            return false;
        }
        if (*visions != constants::CUSTOM_VISIONS_OPTIMISED)
        {
            return true;
        }
        const std::uintptr_t effect = find_hud_silhouettes();
        if (effect == 0)
        {
            return false;
        }
        const auto tech =
            DMK::memory::read<std::uint8_t>(DMK::Address{effect + constants::HUD_SILHOUETTES_TECH_READY_OFFSET});
        return tech && *tech != 0;
    }

    bool engine_brush_outline_available() noexcept
    {
        return s_copies_live.load(std::memory_order_acquire) && herb_outline_ready() && engine_silhouette_available();
    }

    void publish_silhouette_params(const SilhouetteFrameParams &params) noexcept
    {
        if (!s_armed.load(std::memory_order_acquire))
        {
            return;
        }
        if (!s_original_known && capture_original_params())
        {
            (void)DMK::log().try_log(
                DMK::LogLevel::Info,
                "EngineSilhouette: game params (Amount {:.2f}, FillStr {:.2f}, Type {})",
                s_original.amount,
                s_original.fill_str,
                s_original.type
            );
        }
        // The mask-pass override follows the live highlights. The SAMPLE5 permutation compiles on first use. So it is
        // asked for only while the engine allows shader compilation and r_CustomVisions selects the optimised
        // silhouette shader.
        const bool live = params.intensity > 0.0f;
        const std::optional<std::int32_t> visions = read_cvar(Feature::MaskState, AnchorId::CustomVisionsCvar);
        const std::optional<std::int32_t> allow_compilation =
            read_cvar(Feature::MaskState, AnchorId::ShadersAllowCompilationCvar);
        const bool compile_allowed = allow_compilation == 1;
        s_mask_see_through.store(
            live && settings().see_through.load(std::memory_order_relaxed),
            std::memory_order_relaxed
        );
        s_mask_no_near_fade.store(
            live && visions == constants::CUSTOM_VISIONS_OPTIMISED && compile_allowed,
            std::memory_order_relaxed
        );
        if (params.intensity <= 0.0f)
        {
            // Nothing written yet means the game's own values still stand.
            if (s_applied)
            {
                (void)apply_params(s_original);
            }
            return;
        }
        const EffectParams wanted{
            .amount = s_original.amount,
            .fill_str = std::clamp(params.interior_opacity, 0.0f, 1.0f),
            .type = BINOCULAR_TYPE,
        };
        (void)apply_params(wanted);
    }

    std::uint32_t scale_silhouette_word(std::uint32_t word, float intensity) noexcept
    {
        const float scale = std::clamp(intensity, 0.0f, 1.0f);
        std::uint32_t scaled = word & 0xFFu;
        bool lit = false;
        for (const int shift : {24, 16, 8})
        {
            const auto channel =
                static_cast<std::uint32_t>(std::lround(static_cast<float>((word >> shift) & 0xFFu) * scale));
            lit = lit || channel != 0;
            scaled |= channel << shift;
        }
        return lit ? scaled : 0;
    }

    void restore_silhouette_params() noexcept
    {
        if (!s_applied)
        {
            return;
        }
        if (apply_params(s_original))
        {
            s_applied.reset();
        }
    }

    void log_engine_silhouette_state()
    {
        const std::uintptr_t effect = find_hud_silhouettes();
        const std::optional<std::int32_t> visions = read_cvar(Feature::SilhouetteState, AnchorId::CustomVisionsCvar);
        const std::optional<std::int32_t> game_fx =
            read_cvar(Feature::SilhouetteState, AnchorId::PostProcessGameFxCvar);
        std::optional<std::uint8_t> tech;
        if (effect != 0)
        {
            if (const auto value = DMK::memory::read<std::uint8_t>(
                    DMK::Address{effect + constants::HUD_SILHOUETTES_TECH_READY_OFFSET}
                ))
            {
                tech = *value;
            }
        }
        DMK::log().info(
            "EngineSilhouette: mask pass {} (calls {}, overrides {}, see-through {}, no near fade {})",
            s_mask_live.load(std::memory_order_acquire) ? "hooked" : "not hooked",
            s_mask_calls.load(std::memory_order_relaxed),
            s_mask_overrides.load(std::memory_order_relaxed),
            s_mask_see_through.load(std::memory_order_relaxed),
            s_mask_no_near_fade.load(std::memory_order_relaxed)
        );
        DMK::log().info(
            "EngineSilhouette: CHudSilhouettes={} r_CustomVisions={} r_PostProcessGameFx={} technique={} "
            "game params (Amount {:.2f}, FillStr {:.2f}, Type {}{}); {}",
            DMK::format::format_address(effect),
            visions ? std::to_string(*visions) : std::string{"?"},
            game_fx ? std::to_string(*game_fx) : std::string{"?"},
            tech ? std::to_string(*tech) : std::string{"?"},
            s_original.amount,
            s_original.fill_str,
            s_original.type,
            s_original_known ? "" : ", defaults",
            engine_silhouette_available() ? "silhouettes can render" : "silhouettes cannot render"
        );
    }

} // namespace HenrySenses
