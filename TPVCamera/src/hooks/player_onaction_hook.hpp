/**
 * @file player_onaction_hook.hpp
 * @brief Hooks the player OnAction / global action dispatcher and latches movement-input intent.
 *
 * On KCD2 this hooks the action dispatcher (the C++ source of Lua Player:OnAction), which fires for every
 * action-map action with its name and post-action-map value. Latching the movement-input magnitude lets the
 * orbit move-detection key on it instead of body-position speed, so the camera-relative heading is not
 * falsely released when a wall arrests the body.
 *
 * KCD1: the action dispatcher's profiler string is stripped from retail 1.9.7, so it was located via the
 * surviving "OnAction" Lua string (sub_1801FF740) and hooked (see the .cpp). Besides the move-intent MAGNITUDE
 * (orbit move-detection), it also latches the SIGNED move vector and the sprint-held state so the orbit
 * "follow the stick" sprint can face the body at the actual move direction (KCD1 sprint is forward-only in the
 * body facing). The API matches KCD2 so the shared call sites are unchanged between the two builds.
 */
#ifndef TPVCAMERA_PLAYER_ONACTION_HOOK_HPP
#define TPVCAMERA_PLAYER_ONACTION_HOOK_HPP

#include <cstdint>

namespace TPVCamera
{

    /**
     * @brief Installs the player OnAction / action-dispatcher hook from the pre-resolved anchor.
     * @return true if the dispatcher was located and hooked. KCD1: always false (stubbed).
     * @note Call after resolve_all_anchors(); the hook target is read via anchor_address().
     */
    [[nodiscard]] bool initialize_player_onaction_hook();

    /** @brief Whether the OnAction hook resolved (callers use the input signal only when true). KCD1: false. */
    [[nodiscard]] bool player_onaction_available();

    /**
     * @brief Largest movement-input magnitude across all directions and devices, >= 0.
     * @details KCD1: always 0 (the hook is unavailable), so the orbit move-detection falls back to the body's
     *          horizontal speed.
     */
    [[nodiscard]] float player_onaction_move_magnitude();

    /**
     * @brief Force-clears every latched movement magnitude to 0 and returns the largest value that was set.
     * @details KCD1: no latch exists, so this is a no-op that returns 0. Kept for API parity with KCD2.
     * @return The largest magnitude that was latched at the moment of the reset (KCD1: always 0).
     */
    float player_onaction_reset();

    /**
     * @brief Latched SIGNED GAMEPAD movement-input vector in the body-local frame (+forward, +right).
     * @details Uses ONLY the gamepad analog axes (xi_movey/xi_movex, or the movement_y/movement_x aliases);
     *          keyboard digital move keys are deliberately excluded. The orbit "follow the stick" sprint is a
     *          GAMEPAD-specific workaround: gamepad sprint forces forward-only (discarding the lateral), so the
     *          body is faced at the stick direction to redirect it. KEYBOARD sprint preserves the input
     *          direction, so the base body-turn already handles it and a redirect would double-apply
     *          (world_move = body + input) and run the character backwards. Returning false for keyboard-only
     *          movement keeps keyboard/mouse orbit on the base path. Sign: +forward is forward, +lateral is right.
     * @return true if a non-negligible GAMEPAD movement input is currently latched (false for keyboard-only).
     */
    [[nodiscard]] bool player_onaction_gamepad_move_vector(float &forward, float &lateral);

    /** @brief Whether the sprint action is currently held (latched from the action dispatcher). KCD1 only. */
    [[nodiscard]] bool player_onaction_sprint_active();

    /**
     * @brief Requests that the GAMEPAD move axes be collapsed to pure-forward on the dispatch path while set.
     * @details Full-turn orbit only: for a backward-hemisphere stick the camera detour faces the body at the
     *          camera, but KCD1's gamepad sprint will not force a backward input forward, so the raw back-input
     *          would sprint AWAY from the camera. While this is set (and sprint is actually held) the dispatcher
     *          detour forwards the forward axis (xi_movey/movement_y) as full forward and the lateral axis
     *          (xi_movex/movement_x) as zero, so the forced-forward sprint runs along the faced (stick)
     *          direction. The SIGNED latch keeps the REAL stick (so the body-turn angle is unaffected -- no
     *          feedback); only the value forwarded to the engine is collapsed. The camera detour clears this
     *          every frame the redirect is inactive, and player_onaction_reset() clears it on orbit-off, so it
     *          cannot strand; the sprint-held gate in the detour is a further failsafe. KCD1 only.
     */
    void player_onaction_set_force_forward(bool on);

    /**
     * @brief Latched SIGNED KEYBOARD movement-input vector in the body-local frame (+forward, +right), 0 if no
     *        keyboard move key is held. Uses ONLY the digital move keys (moveforward/back/left/right). Used by the
     *        keyboard turn-and-run to face the body at the move direction. KCD1 only.
     * @return true if a non-negligible keyboard movement input is currently latched.
     */
    [[nodiscard]] bool player_onaction_keyboard_move_vector(float &forward, float &lateral);

    /**
     * @brief The player's wh::entitymodule::C_PlayerInput pointer (the action dispatcher's `self`), cached from
     *        the hook, or 0 if not yet seen. The keyboard turn-and-run writes its body-relative move-input field
     *        (+0x58 x / +0x5C y) to force pure-forward (overrides the held digital keys, no HUD glyph flip). The
     *        caller MUST validate the vtable before writing. KCD1 only.
     */
    [[nodiscard]] uintptr_t player_onaction_player_input();

} // namespace TPVCamera

#endif // TPVCAMERA_PLAYER_ONACTION_HOOK_HPP
