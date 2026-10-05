/**
 * @file tpv_camera.hpp
 * @brief Mod lifecycle entry points driven by the DetourModKit Session.
 */
#ifndef TPVCAMERA_TPV_CAMERA_HPP
#define TPVCAMERA_TPV_CAMERA_HPP

#include "hooks/hook_set.hpp"

#include <DetourModKit.hpp>
#include <DetourModKit/abi/wheel_host.h>

namespace TPVCamera
{

    /**
     * @brief Initializes the whole mod: config, hooks, and input bindings.
     * @param session The live Session. Its scope() takes the input BindingGuards, so ~Session clears
     *        them first (reverse insertion order) and abandon() retains them untouched on the
     *        process-termination path rather than destroying callbacks under the loader lock. Its ini()
     *        handle loads the INI once every item is bound.
     * @param wheel_host Resident wheel-host table owned by a never-unloaded module, or nullptr.
     * @details Runs off the loader lock: on the bootstrap worker thread in the release ASI, on the loader's
     *          control thread in the dev build. Loads and logs configuration, validates the game module, resolves
     *          the anchors and class identities, installs the camera and UI hooks, starts the input engine, and
     *          enables INI hot-reload.
     *
     *          A mouse-wheel binding makes the input engine take a PERMANENT module keepalive on whichever module
     *          hosts the wheel capture (ModulePinReason::MessageHookKeepalive). In the single-DLL release build
     *          that module is the mod itself, which is never unloaded, so the local MessageHook backend is correct
     *          and @p wheel_host stays nullptr. Under the dev loader the same keepalive would pin the logic DLL
     *          and make it permanently unloadable, so the loader owns a resident host and passes its table here.
     *          Passing the pointer rather than branching on a build macro keeps ONE code path: the value selects
     *          the backend, so dev and release run the same logic.
     * @return An empty Result on success, or the typed Error of the step that failed. The input engine start is
     *         the final fallible step, so a failure never leaves a poller running behind a failed init.
     */
    [[nodiscard]] DMK::Result<void> init(DMK::Session &session, const WheelHostTable *wheel_host = nullptr);

    /**
     * @brief Tears the mod down: joins the mod's workers, hands the per-frame game overrides back, and retires every
     *        hook.
     * @return Retired when every worker joined and every hooked prologue was restored. Busy when a game thread stayed
     *         inside a detour: the hooks stay disabled, and a later call can finish. Failed when a worker did not join
     *         or a hook failed to disable or restore its target: the module must then stay mapped for the process.
     * @details Follows DetourModKit's logic-DLL shutdown order:
     *          - join the mod's workers.
     *          - have the render thread hand its per-frame game overrides back to the engine.
     *          - retire the game-thread detours through the hook set. The set disables every hook, waits until no
     *            game thread is inside a detour, and only then destroys the handles.
     *          The input bindings and config setters are NOT drained here: the release build's ~Session and the dev
     *          build's prepare_logic_dll_unload_all() own that, after this returns. Every step is idempotent, so a
     *          call after Busy resumes the teardown.
     * @note Run it OFF the loader lock. Under the loader lock every join and hook mutation fails closed, which
     *       reports Busy or Failed and changes nothing.
     */
    [[nodiscard]] RetireStatus shutdown();

} // namespace TPVCamera

#endif // TPVCAMERA_TPV_CAMERA_HPP
