/**
 * @file hooks/interaction_hook.hpp
 * @brief Camera-space interaction: redirect the player look-ray onto the render camera + crosshair.
 *
 * KCD1's player interactor casts its "what am I looking at / press to use" look ray from the EYE along the
 * look direction; it never consults the render camera. In third person the over-the-shoulder camera is
 * offset from the eye, so the screen-centre crosshair and the use-target diverge (worst at close range).
 * This hook wraps the interactor's per-tick selection and transiently overwrites the framework view pose with
 * the rendered camera + crosshair for the duration of that one call, so the look-ray AND the candidate
 * projection both follow the screen centre, then restores the engine view.
 *
 * KCD1: wraps the selection sub_1803E51EC and resolves the view pose through the global-context slot (both
 * resolved at runtime by AOB cascades); see interaction_hook.cpp. Gated by InteractFromCamera + cursor-hidden; a
 * no-op at the menu / in first person. The KCD2 on-screen reticle gate for InteractiveScene usables
 * (shrines/beds/doors) is not ported (its KCD1 analog is unresolved).
 */
#ifndef TPVCAMERA_HOOKS_INTERACTION_HOOK_HPP
#define TPVCAMERA_HOOKS_INTERACTION_HOOK_HPP

#include <DetourModKit/error.hpp>
#include <DetourModKit/hook.hpp>

namespace TPVCamera
{

    /**
     * @brief Installs the interaction look-ray redirect (the interactor selection hook).
     * @details Best-effort: on failure the feature simply no-ops (interaction stays vanilla) and the rest of
     *          the mod is unaffected. KCD1 resolves the targets at runtime via AOB cascades. The hook is pushed
     *          onto @p hooks, which shutdown() retires through the DetourGate.
     * @return An empty Result once the hook is armed, or the typed Error.
     */
    [[nodiscard]] DMK::Result<void> initialize_interaction_hook(DMK::hook::HookStack &hooks);

} // namespace TPVCamera

#endif // TPVCAMERA_HOOKS_INTERACTION_HOOK_HPP
