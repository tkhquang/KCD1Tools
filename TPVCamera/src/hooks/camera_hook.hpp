/**
 * @file hooks/camera_hook.hpp
 * @brief Header for the third-person camera (frustum-builder offset approach).
 *
 * Renders a third-person view by offsetting the game view camera's matrix at the
 * frustum builder (CCamera::UpdateFrustumPlanes), before the cull planes are
 * computed, so the rendered view and its culling move together. Every gameplay
 * camera (first person, combat, mount) funnels into that builder for the active
 * CView. Because the player's look/aim channel is never touched, aiming and
 * interaction keep working off the first-person frame. A companion hook on the
 * head-visibility setter keeps the player head rendered from behind, and an
 * input-dispatcher hook powers the free-look orbit.
 */
#ifndef KCD1_TPVCAMERA_CAMERA_HOOK_HPP
#define KCD1_TPVCAMERA_CAMERA_HOOK_HPP

#include <DetourModKit/error.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace TPVCamera
{

    // Input binding names shared by the registration site (tpv_camera.cpp, through DMK::config::hold_combo)
    // and the per-frame zoom query, so every site agrees on the exact spelling. The zoom holds are queried
    // per frame in the frustum-builder detour to drive the follow distance; the orbit hold is edge-driven
    // (its callback engages/releases free-look directly on the key edges), not polled.
    inline constexpr const char *k_zoom_in_binding = "camera_zoom_in";
    inline constexpr const char *k_zoom_out_binding = "camera_zoom_out";
    inline constexpr const char *k_orbit_hold_binding = "orbit_hold";

    /**
     * @brief Installs the third-person camera hooks.
     * @details Hooks the frustum builder (resolved by AOB) and offsets the game view
     *          camera matrix to sit behind the player while leaving the look orientation
     *          and the eye-frame pose untouched. Also hooks the head-visibility setter so
     *          the first-person rig keeps the player head while the offset is active, and
     *          the input dispatcher for free-look orbit. The detours fast-path out while
     *          the offset is toggled off, so they are harmless when the view is first-person.
     *          Every hook is owned by the DetourGate, which retires it at shutdown.
     * @param module_base Base address of the target game module.
     * @param module_size Size of the target game module in bytes.
     * @return An empty Result once the frustum hook is armed (the best-effort head/input hooks only warn), or
     *         the frustum hook's typed Error, which init() surfaces unchanged.
     */
    [[nodiscard]] DMK::Result<void> initialize_camera(uintptr_t module_base, size_t module_size);

    /**
     * @brief Resolves the zoom hold bindings to BindingTokens and publishes them for the per-frame query.
     * @details BindingToken acquisition is control-plane work, and a token goes stale whenever its binding
     *          reshapes (an INI rebind or a consume-flag change), so call this after the input engine starts and
     *          again after every INI reload. Until the first publish the detour uses the name-based query.
     * @note Setup/control-plane only: it allocates. Never call it from a detour or an input callback.
     */
    void refresh_zoom_binding_tokens() noexcept;

    /**
     * @brief Drops the published zoom BindingTokens. Call at teardown, after the detours are quiescent.
     */
    void release_zoom_binding_tokens() noexcept;

    /**
     * @brief Asks the render thread to hand every per-frame game override back to the engine, and waits for it.
     * @details The next frustum-builder call restores the keyboard move field and the game's intended head
     *          visibility on the render thread (the thread the engine drives both on), then leaves the view to the
     *          game until the hooks are retired. Call at teardown, before the DetourGate retires the hooks.
     * @param budget Bound on the wait for the render thread to run that frame.
     * @return True once the render thread acknowledged; false when no frame ran within @p budget.
     * @note Setup/control-plane only: it waits.
     */
    [[nodiscard]] bool release_camera_on_game_thread(std::chrono::milliseconds budget) noexcept;

    /**
     * @brief Fallback for release_camera_on_game_thread() when the render thread ran no frame in time.
     * @details Hands the keyboard move field back from the calling thread. A no-op once the render thread released
     *          the overrides. Call only after the DetourGate proved the detours quiescent: it touches state the
     *          render thread owns while the detours can run.
     */
    void release_camera_overrides() noexcept;

} // namespace TPVCamera

#endif // KCD1_TPVCAMERA_CAMERA_HOOK_HPP
