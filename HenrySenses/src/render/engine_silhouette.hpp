/**
 * @file render/engine_silhouette.hpp
 * @brief Native engine silhouettes: the CryEngine 3 CHudSilhouettes post effect, per-object coloured outlines.
 *
 * KCD1 still ships the HUD silhouette pass of CryEngine 3 and keeps it armed (r_CustomVisions 3, r_PostProcessGameFx
 * 1). An entity render proxy whose HUD silhouette word (CRenderProxy + 0xF4, 0xRRGGBBAA) is not zero copies the word
 * into its render parameters on every frame. Every material with a CustomRenderPass technique then files the object
 * as an FB_CUSTOM_RENDER item. CHudSilhouettes draws those items into a half-resolution mask and composites the
 * outline and the fill over the frame. So a highlight is the word alone, written by entity_access.
 *
 * This module owns the effect's parameters. Under the game's HudSilhouettes_Type 1 the composite strength is Amount *
 * 0.264, and Render clamps Amount to 1, so an outline stays faint. A live highlight therefore switches to Type 0 (the
 * binocular mode: strength 0.8) and HudSilhouettes_FillStr sets the fill. With no highlight left, the game's own
 * values come back. The composite is additive, so a fade scales the word's colour (scale_silhouette_word). The
 * parameters go through I3DEngine::SetPostEffectParam on the main thread. [KCD2 revives a removed pipeline stage
 * instead: custom-stage registration, PSO control, the word injection, and its own mask draw and composite.]
 *
 * The stock mask pass is depth-tested and fades objects nearer than 1.5 m. A hook on FX_RenderCustomScene lifts both
 * for the mask draw alone. It adds GS_NODEPTHTEST to the renderer's forced state ([Render] SeeThrough). It also
 * selects the %_RT_SAMPLE5 permutation that skips the near fade, and restores both members afterwards.
 *
 * A second hook, on CStatObj::RenderInternal, submits the outline copies of render/herb_outline once per frame. Both
 * hooks run on render or 3D-engine job threads, so the teardown drains them before the hook set is destroyed.
 */
#ifndef HENRYSENSES_ENGINE_SILHOUETTE_HPP
#define HENRYSENSES_ENGINE_SILHOUETTE_HPP

#include "hooks/hook_set.hpp"

#include <DetourModKit/error.hpp>

#include <cstdint>

namespace HenrySenses
{
    /**
     * @struct SilhouetteFrameParams
     * @brief Per-frame values the main-thread tick publishes to the post effect.
     */
    struct SilhouetteFrameParams
    {
        /// Global highlight intensity in [0, 1] (pulse fade). 0 means no highlight is live.
        float intensity{1.0f};
        /// Opacity of the tint inside every outline, or 0 for edges only.
        float interior_opacity{0.0f};
    };

    /**
     * @brief Captures the game's own parameter values and installs the outline-copy and mask-pass hooks.
     * @details Neither hook needs the renderer to exist, because an ASI loads before the game creates it. A
     *          parameter capture that fails here repeats on later ticks. A hook that cannot install only logs a
     *          warning: the native silhouettes still render without it.
     * @param hooks The mod's hook set, which owns both hooks.
     * @return An empty value when the NativeSilhouette gate passed, or the Error naming the missing anchors.
     */
    [[nodiscard]] DMK::Result<void> initialize_engine_silhouette(HookSet &hooks);

    /**
     * @brief Stops further parameter writes and turns both hooks into pass-throughs, ahead of teardown.
     */
    void disarm_engine_silhouette() noexcept;

    /**
     * @brief Waits (bounded) until no render or job thread is inside either hook.
     * @return True when both hooks drained.
     * @note Call after the hooks were disabled and before they are destroyed.
     */
    [[nodiscard]] bool shutdown_engine_silhouette() noexcept;

    /**
     * @brief Reports whether a silhouette word can render: the effect exists, its technique compiled, and
     *        r_CustomVisions and r_PostProcessGameFx are on.
     * @return True when silhouette words render.
     */
    [[nodiscard]] bool engine_silhouette_available() noexcept;

    /**
     * @brief Reports whether the mask pass ignores the scene depth: the mask-pass hook is enabled and [Render]
     *        SeeThrough is on.
     * @return True when an occluded highlight shows through walls.
     */
    [[nodiscard]] bool engine_see_through_active() noexcept;

    /**
     * @brief Reports whether herbs, static brushes and vegetation-shaded meshes can be outlined through copies.
     * @details The static-mesh render hook is enabled, the copies can submit (herb_outline_ready) and silhouettes
     *          render.
     * @return True when an outline copy reaches the mask.
     */
    [[nodiscard]] bool engine_brush_outline_available() noexcept;

    /**
     * @brief Scales the colour of a silhouette word by an intensity, for a fade.
     * @param word Packed 0xRRGGBBAA.
     * @param intensity In [0, 1].
     * @return The word with R, G and B scaled and A kept, or 0 when every colour byte reaches 0.
     */
    [[nodiscard]] std::uint32_t scale_silhouette_word(std::uint32_t word, float intensity) noexcept;

    /**
     * @brief Applies the per-frame parameters to the post effect.
     * @details A positive intensity selects the binocular mode and the fill. A zero intensity puts the game's own
     *          values back. Writes only the values that changed since the last call.
     * @param params The values.
     * @note Main thread. There SetPostEffectParam applies at once, and on another thread it queues a pointer to the
     *       parameter name.
     */
    void publish_silhouette_params(const SilhouetteFrameParams &params) noexcept;

    /**
     * @brief Puts the game's own parameter values back.
     * @note Main thread, from the main-thread half of shutdown.
     */
    void restore_silhouette_params() noexcept;

    /**
     * @brief Logs the effect, the renderer state and the applied parameters (the state report).
     */
    void log_engine_silhouette_state();

} // namespace HenrySenses

#endif // HENRYSENSES_ENGINE_SILHOUETTE_HPP
