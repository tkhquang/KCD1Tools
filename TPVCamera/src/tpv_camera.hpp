/**
 * @file tpv_camera.hpp
 * @brief Mod lifecycle entry points driven by the DetourModKit Session.
 */
#ifndef TPVCAMERA_TPV_CAMERA_HPP
#define TPVCAMERA_TPV_CAMERA_HPP

#include <DetourModKit.hpp>
#include <DetourModKit/abi/wheel_host.h>

#include <cstdint>
#include <string_view>

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

    /// The outcome of shutdown(). Only Retired authorizes unmapping the image that holds the mod's code.
    enum class ShutdownVerdict : std::uint8_t
    {
        /// Workers joined, every hook caller proven quiescent, and every hook backend reclaimed.
        Retired,
        /**
         * @brief A hook could not be disabled, or a game thread was still inside or entering a detour.
         * @details The hooks stay installed (disabled where possible) and their trampolines alive. A later
         *          shutdown() retries.
         */
        CallersActive,
        /// A mod worker did not join and keeps its module reference. Latched.
        WorkerRetained,
        /// DetourModKit retained a hook backend at teardown, so a detour stays reachable. Latched.
        HookRetained,
    };

    /// Short label for a ShutdownVerdict, for log lines.
    [[nodiscard]] std::string_view to_string(ShutdownVerdict verdict) noexcept;

    /**
     * @brief Tears the mod down: stops the INI watcher and the overlay worker, retires every hook, and resets the
     *        game interface.
     * @return The teardown verdict. Anything but Retired means code in this image can still run, so the module
     *         hosting it must NOT be unloaded.
     * @details Follows DetourModKit's logic-DLL shutdown order: stop and join the mod's workers, have the render thread
     *          hand its per-frame game overrides back to the engine (game-thread cleanup completes before its route
     *          is retired), then retire the external callback sources (the game-thread detours) through the
     *          DetourGate, which disables every hook, proves its callers quiescent, and only then destroys it. The
     * input bindings and config setters are NOT drained here: the release build's ~Session and the dev build's
     *          prepare_logic_dll_unload_all() own that, after this returns. Idempotent and retryable: a step that
     *          completed is not repeated, and a CallersActive verdict resumes from the hook retirement.
     * @note Run it OFF the loader lock. Under the loader lock every join and hook mutation fails closed, which
     *       reports WorkerRetained or CallersActive and changes nothing.
     */
    [[nodiscard]] ShutdownVerdict shutdown();

} // namespace TPVCamera

#endif // TPVCAMERA_TPV_CAMERA_HPP
