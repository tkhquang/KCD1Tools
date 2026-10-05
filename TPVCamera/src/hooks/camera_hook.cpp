/**
 * @file camera_hook.cpp
 * @brief Third-person camera implemented at the camera frustum builder.
 *
 * Hooks CCamera::UpdateFrustumPlanes, the function that turns a camera's 3x4 matrix
 * into world-space cull planes. By offsetting the game view camera's matrix HERE,
 * before the cull planes are computed from it, the camera renders behind the player
 * AND the frustum culls from the same offset position, so nearby geometry is not
 * wrongly hidden. Offsetting only the rendered matrix afterwards (at the view
 * convergence point on return) leaves the frustum culling from the eye, which was the
 * source of the "items not shown up close" artifact.
 *
 * Every gameplay camera (first person, combat through its private inner camera, mount)
 * funnels into this builder for the active CView, so one hook covers them all. The
 * builder is shared by shadow, reflection, and portal cameras too, so the detour gates
 * to the game view by checking that the CView embedding the camera carries the CView
 * vtable.
 *
 * Gameplay still reads the player look-dir/eye channel, not this render camera, so aim
 * and interaction keep working off the native frame; only the rendered sink moves. A
 * companion hook on the head-visibility setter keeps the player head rendered from
 * behind. The offset is suppressed while the game is in any state listed in SuppressTPVState (by
 * default the pause menu and blocking overlays), so that context renders from the game's own camera.
 */

#include "camera_hook.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "config.hpp"
#include "global_state.hpp"
#include "game_state.hpp"
#include "game_structures.hpp"
#include "offset_heal.hpp"
#include "math_utils.hpp"
#include "physics_raycast.hpp"
#include "render_occlusion.hpp"
#include "rtti_types.hpp"
#include "hooks/ui_menu_hooks.hpp"
#include "hooks/player_onaction_hook.hpp"
#include "presets/preset_runtime.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <intrin.h>
#include <memory>
#include <numbers>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace TPVCamera
{

    // CCamera::UpdateFrustumPlanes(camera /*rcx*/): camera object starts with the 3x4 matrix,
    // followed by the projection params; this builds the world cull planes. Offsetting the matrix
    // here, before the cull planes are computed, moves the rendered view AND its culling together.
    using FrustumBuildFunc = uintptr_t(__fastcall *)(uintptr_t camera);

    // Eases the camera collision distance toward @p target: a fast pull-IN (so a wall is never clipped) and the
    // slower configured return-OUT, which stops the camera pumping when an edge-grazing ray hit alternates
    // near/far frame to frame. Snaps to the target on the first valid frame. Shared by the per-frame easing and
    // the static-world throttle bypass so the two cannot drift.
    static void ease_collision_toward(CameraState &cam, float target, float delta_time, float return_speed)
    {
        if (!cam.collision_valid)
        {
            cam.collision_distance = target;
            cam.collision_valid = true;
            return;
        }
        constexpr float k_pull_in_speed = 25.0f; // near-instant but still smooth
        const float speed = (target < cam.collision_distance) ? k_pull_in_speed : return_speed;
        const float blend = (speed > 0.0f) ? (1.0f - std::exp(-speed * delta_time)) : 1.0f;
        cam.collision_distance += (target - cam.collision_distance) * blend;
    }

    // Head-visibility setter: SetHeadHidden(this /*rcx*/, bool hide_head /*dl*/, char flags /*r8b*/).
    // hide_head == false keeps the head rendered.
    using SetHeadVisibilityFunc = void(__fastcall *)(uintptr_t entity, bool hide_head, char flags);

    // Generic input-event dispatcher: void __fastcall(controller /*rcx*/, event /*rdx*/,
    // char /*r8b*/). Every input event funnels through here; hooking it lets free-look
    // capture mouse-look deltas and freeze the player by not dispatching while orbiting.
    using InputDispatchFunc = void(__fastcall *)(uintptr_t controller, uintptr_t input_event, char flag);

    // wh::engine3d::C_CameraObserver update (vtable slot CAMERA_OBSERVER_VTABLE_UPDATE_SLOT): bool __fastcall(observer
    // /*rcx*/, Vec3 *position /*rdx*/, bool *position_valid /*r8*/, Vec3 *direction /*r9*/, bool *direction_valid,
    // float *fov). It copies the system view camera's translation, forward column and field of view.
    using CameraObserverUpdateFunc = bool(__fastcall *)(uintptr_t observer, float *position, bool *position_valid,
                                                        float *direction, bool *direction_valid, float *fov);

    // IActor::IsThirdPerson (C_Player vtable, the slot AnchorId::IsThirdPersonSlot reads from its call sites):
    // bool __fastcall(actor /*rcx*/). One function shared by every actor class; it answers true for any actor that is
    // not the local player.
    using IsThirdPersonFunc = bool(__fastcall *)(uintptr_t actor);

    // IGameObjectExtension::HandleEvent (C_Player vtable, the slot AnchorId::HandleEventSlot reads from the
    // camera-changed event's sender): void __fastcall(extension /*rcx*/, const SGameObjectEvent *event /*rdx*/).
    using HandleEventFunc = void(__fastcall *)(uintptr_t extension, const void *event);

    // CAnimatedCharacter::UpdatePhysicalEntityMovement: char __fastcall(animchar /*rcx*/, QuatT *movement /*rdx*/).
    // The frame's movement is a rotation (x, y, z, w) followed by a translation (x, y, z). The translation is requested
    // from physics as a velocity and the rotation is composed into the body.
    using UpdatePhysEntMovementFunc = char(__fastcall *)(uintptr_t animchar, float *movement);

    // Trampoline slots. Each install stores its slot with release order before the hook arms. Each detour reads its
    // slot with acquire order, so a detour never chains through a slot it cannot see.
    static std::atomic<FrustumBuildFunc> s_frustum_build_original{nullptr};
    static std::atomic<SetHeadVisibilityFunc> s_set_head_visibility_original{nullptr};
    static std::atomic<InputDispatchFunc> s_input_dispatch_original{nullptr};
    static std::atomic<CameraObserverUpdateFunc> s_camera_observer_update_original{nullptr};
    static std::atomic<IsThirdPersonFunc> s_is_third_person_original{nullptr};
    static std::atomic<UpdatePhysEntMovementFunc> s_phys_ent_movement_original{nullptr};

    // Native turn-in-place animation. The game is kept in first person, where the body follows the look and
    // C_PlayerMovementAction (the free-roam locomotion action) never plays its turn fragments. The body follows the
    // look while the player's LockBodyTurn count (C_Player vtable slot 126) is 0, and the action holds one LockBodyTurn
    // reference in third person. The IsThirdPerson detour answers "third person" for s_native_turn_actor (0 = off) at
    // exactly two of that action's call sites:
    //   - the idle LockBodyTurn sync (s_lock_sync_return), which then takes the action's reference so the body stops
    //     following the look;
    //   - the turn trigger (s_turn_trigger_return, only while s_native_turn_trigger is set), after which the game turns
    //     once the look leads the body by more than 35 degrees. The turn-decision hook below replaces that decision
    //     with its own start angle and with turns that finish facing the look.
    // Both are required: the trigger alone never frees the body, and the sync alone freezes it with no turn to follow.
    // Every other caller keeps the first-person answer, among them the first-person view effects (bow-draw zoom and aim
    // sensitivity, the horse camera), the pose aligner and the animation-event audio. The return addresses are written
    // once at install, before the hook arms. The actor and the trigger flag are published by the frustum detour each
    // game-view frame. s_native_turn_armed is set only once the hook is armed. The trampoline pointer itself is never
    // cleared, because an armed (or pinned) hook still routes calls through it. The teardown hand-off
    // (release_camera_on_game_thread) switches the feature off on the game thread before the hooks are retired.
    static uintptr_t s_turn_trigger_return = 0;
    static uintptr_t s_lock_sync_return = 0;
    static std::atomic<bool> s_native_turn_armed{false};
    static std::atomic<uintptr_t> s_native_turn_actor{0};
    static std::atomic<bool> s_native_turn_trigger{false};
    // C_Player::HandleEvent, the SGameObjectEvent vtable and the camera-changed event's id and target/flags word, all
    // resolved and validated at install. The feature is not armed without them: a switch-off could not reach an idle
    // action, which would keep its reference (body not following the look).
    static uintptr_t s_player_handle_event = 0;
    static uintptr_t s_game_object_event_vtable = 0;
    static uint32_t s_camera_changed_event_id = 0;
    static uint32_t s_camera_changed_event_flags = 0;
    // C_Player's LockBodyTurn reference-count offset (AnchorId::LockBodyTurnCount), read only for the log; 0 when it
    // did not resolve.
    static ptrdiff_t s_lock_body_turn_count_offset = 0;

    // Turn decision: the mid hook on ComputeMoveState's `seta cl` (see resolve_turn_decision_layout). On its own the
    // game starts a turn past 35 degrees and stops it as soon as the gap is back under 35, so the body always rests
    // about 35 degrees short of the look. The hook starts a turn past s_turn_start_angle (NativeTurnAngle, radians), or
    // past k_turn_settle_angle once the look has rested for s_turn_settle_delay (NativeTurnSettleDelay). It then keeps
    // the turn on until the body is within k_turn_finish_angle of the look, or until the gap changes sign (he faces
    // it). s_turn_continuing, s_turn_last_sign and the rest state carry the decision from frame to frame. Only the hook
    // updates them, on whichever job worker updates the player that frame, one frame after another; a feature switch
    // in update_native_turn only resets them. The hook runs on every idle frame with a gap, so a player frame without
    // it (s_turn_decision_missed, raised by the movement detour) means the action left its idle decision (he walked, an
    // interaction or a script took over, turns were off) and the decision starts over. Breaks are counted in frames,
    // so a long frame is not a break. Without the movement detour the break falls back to wall-clock time: more than
    // k_turn_decision_break_ms since s_turn_decision_tick.
    // The look counts as resting while the gap stays within k_turn_rest_drift of its value when the rest began. While
    // he is not turning only the look changes the gap, and a cumulative bound (not a per-frame rate) keeps a slow pan
    // from counting as rest. A turn that sets the game's spin latch is refused for that frame (see
    // would_set_spin_latch). One frame later the game holds the new sign, and the turn can start. The action's field
    // offsets the hook reads are resolved from the game's code at install and written before the hook arms.
    constexpr float k_turn_finish_angle = 0.07f; // rad (4 deg)
    constexpr float k_turn_settle_angle = 0.21f; // rad (12 deg)
    constexpr float k_turn_rest_drift = 0.0175f; // rad (1 deg)
    constexpr uint64_t k_turn_decision_break_ms = 150;
    static std::atomic<float> s_turn_start_angle{0.61086524f};
    static std::atomic<float> s_turn_settle_delay{0.8f}; // seconds, 0 = no settle turns
    static std::atomic<bool> s_turn_continuing{false};
    static std::atomic<float> s_turn_last_sign{0.0f};
    static std::atomic<float> s_turn_rest_gap{0.0f};
    static std::atomic<uint64_t> s_turn_rest_since{0};
    static std::atomic<uint64_t> s_turn_decision_tick{0};
    static std::atomic<bool> s_turn_decision_missed{false};
    static std::atomic<bool> s_turn_steps_hooked{false}; // the movement detour is armed: breaks are counted in frames
    static ptrdiff_t s_spin_latch_offset = 0;
    static ptrdiff_t s_installed_state_offset = 0;
    static ptrdiff_t s_last_sign_offset = 0;

    // Turn steps in place. A turn fragment's root motion walks the body 5-20 cm, which leaves a still camera off centre
    // (and shifts a camera that follows it). The movement detour drops the horizontal part of the player's movement on
    // the frames the movement action is in its idle/turn decision, from the first turn frame through a tail after the
    // last one: a turn cut short at the look still sends a step, for at most one frame, while the game blends to idle.
    // The tail lasts k_turn_step_tail_frames decision frames or k_turn_step_tail_ms, whichever is longer, so neither a
    // long frame nor a high frame rate cuts it short, and it ends on the first frame without a decision.
    // s_turn_decision_seen is set by the decision hook and taken by the movement detour, which CAnimatedCharacter's
    // update calls right after the action's update on the same thread, so the flag is exact per frame: the frame he
    // starts walking, or anything else takes the action over, his movement goes through untouched. s_turn_decided_tick
    // is when the hook last chose to turn (GetTickCount64, 0 = tail ended). s_player_animchar is the player's
    // CAnimatedCharacter, published by the frustum detour while the native turn is on (0 otherwise).
    // s_movement_type_offset is CAnimatedCharacter's movement request type, resolved at install before the detour
    // arms.
    constexpr int k_turn_step_tail_frames = 3;
    constexpr uint64_t k_turn_step_tail_ms = 300;
    static std::atomic<bool> s_turn_decision_seen{false};
    static std::atomic<int> s_turn_tail_frames{0};
    static std::atomic<uint64_t> s_turn_decided_tick{0};
    static std::atomic<uintptr_t> s_player_animchar{0};
    static ptrdiff_t s_movement_type_offset = 0;

    // Crouched animations (see Constants::CROUCHED_IDLE_PLAYER_ANIMATION). The game looks a clip's animation up by the
    // 64-bit hash of its name. The hook on that lookup (detour_crouched_animation) swaps the hash of each player clip
    // for its NPC twin while the native turn is on. The hashes come from the game's own name hash at install, and the
    // install writes them before the hook arms.
    struct AnimationSwap
    {
        std::uint64_t player = 0;
        std::uint64_t npc = 0;
    };
    static std::array<AnimationSwap, 2> s_crouched_swaps{};

    // The first-person eye position of the last game-view frame that rendered the third-person offset, published by the
    // frustum detour for the camera-observer detour. The components are separate atomics: a reader racing a writer can
    // mix two consecutive frames' eyes, which differ by a frame of movement and do not matter to the AI. s_ai_eye_valid
    // is released after the components and cleared when the offset disengages.
    static std::atomic<float> s_ai_eye_x{0.0f};
    static std::atomic<float> s_ai_eye_y{0.0f};
    static std::atomic<float> s_ai_eye_z{0.0f};
    static std::atomic<bool> s_ai_eye_valid{false};

    /**
     * @brief The zoom hold bindings resolved to BindingTokens for the per-frame query.
     * @details Acquired on the control plane (refresh_zoom_binding_tokens: after the input engine starts and after
     *          every INI reload, the only places their bindings reshape) and published whole, so the render thread
     *          never resolves a binding name itself. A token left stale by a reshape reads "not held" (fail closed)
     *          until the reload callback republishes, a window of a few milliseconds.
     */
    struct ZoomBindingTokens
    {
        DMK::input::BindingToken zoom_in;
        DMK::input::BindingToken zoom_out;
    };
    static std::atomic<std::shared_ptr<const ZoomBindingTokens>> s_zoom_tokens;

    // Teardown hand-off (release_camera_on_game_thread). The control thread raises s_release_requested; the next
    // game-view frustum build on the render thread (shadow and reflection builds only wait) hands every per-frame
    // override back to the engine, the native turn switch-off included, latches s_release_done, and from then on
    // leaves the view to the game until the hooks are retired.
    static std::atomic<bool> s_release_requested{false};
    static std::atomic<bool> s_release_done{false};

    // Resolved SSystemGlobalEnvironment (g_env) base, set once at init (runtime AOB cascade; 0 if it does not
    // resolve). Reused by the player/animchar walks; p_physical_world is g_env + PHYSICAL_WORLD_OFFSET.
    static uintptr_t s_genv_runtime = 0;

    // Latched from the head-visibility setter (or adopted from the player's stored setter
    // arguments, see adopt_head_state) so the per-frame re-assert can drive the head without
    // waiting for the game to call the setter again (toggling the offset does not make the
    // game call it, so without the re-assert the head would stay hidden after an FPV/TPV
    // switch). The setter only ever runs for the player (it toggles the FirstPersonView
    // rig), so the entity is the player. s_head_was_active tracks the offset's active state
    // across frames so the head is restored to the game's intended value exactly once when
    // the offset turns off.
    static std::atomic<uintptr_t> s_head_entity{0};
    static std::atomic<uint8_t> s_head_flags{0};
    static std::atomic<bool> s_game_intended_hide_head{false};
    static std::atomic<bool> s_head_was_active{false};

    // The offset's effective active state (effective_tpv && should_apply_view), published by the
    // frustum detour each frame. The head-visibility detour and the free-look input gate read it so
    // they mirror the live offset state without recomputing the whole forced-view policy themselves.
    static std::atomic<bool> s_offset_active{false};

    // First-person fallback, published by the offset each frame: true while the camera has no room behind the player
    // (the arm is shorter than HeadClearance) and sits at the eye, so the head must be hidden like in first person or
    // the view would be inside it. Read by the head re-assert and the head-visibility detour.
    static std::atomic<bool> s_head_fallback{false};

    // Published by the frustum detour each game-view frame: true while the game is showing the OS cursor
    // (a UI is up). The free-look input gate reads it to FREEZE the orbit - hold its angles and ignore
    // mouse-look - while any cursor UI is open (menu, inventory, loot/trade, dialogue), so the camera
    // does not turn from cursor motion and resumes from the same angle when the cursor hides. The orbit
    // hook captures raw mouse UPSTREAM of the engine's own input freeze, so it needs this explicit gate.
    static std::atomic<bool> s_cursor_shown{false};

    // Camera-relative movement (toggle orbit). The character's horizontal speed is derived from its body
    // world position each frame (device-agnostic: no hardcoded movement keys). Crossing the START speed
    // from idle aligns the heading to the camera once; it returns to idle only below the lower STOP speed
    // (hysteresis, so a momentary dip cannot re-trigger the align). k_orbit_aim_level_speed eases the look
    // pitch toward level per second while orbiting.
    // Movement-INPUT thresholds (device-agnostic xi_move axis magnitude, ~0..1.4), used in place of the
    // body-position speed when the action-dispatch hook resolved. The input stays nonzero while a movement
    // key is held even if a wall arrests the body, so the heading is not falsely released on a collision stop.
    constexpr float k_orbit_move_input_start = 0.15f;
    constexpr float k_orbit_move_input_stop = 0.05f;
    constexpr float k_orbit_aim_level_speed = 8.0f;
    // Sprint "follow the stick" decides back-pedal vs redirect by the move-input ANGLE, not the forward sign. A
    // strafe sits at ~90 deg with the forward axis hovering near zero (thumb noise), so a forward-sign threshold
    // toggles back-pedal in and out right next to pure-sideways - which snapped the body to the captured forward
    // heading mid-strafe (the flicker / "auto-turns forward"). Only a CLEARLY-backward push (within ~45 deg of
    // straight back, i.e. |angle| past this) back-pedals; everything forward of it redirects, so stick noise
    // never flips it. 135 deg leaves a 45 deg margin from pure-sideways.
    constexpr float k_orbit_sprint_backpedal_angle = std::numbers::pi_v<float> * 0.75f; // 135 deg, in radians

    // Exponential ease rate (1/sec) for the KEYBOARD turn-and-run facing. Keyboard move input is digital, so the
    // move angle jumps in 45/90 deg steps (W -> W+D) and snaps the body 1 frame to the next. Easing the move-input
    // angle at this rate (~0.2s settle) smooths it; higher = snappier, lower = floatier. Gamepad is analog and not
    // eased (its angle already changes smoothly). Eases the move angle only (not the camera heading), so there is
    // no continuous-align feedback.
    constexpr float k_orbit_turn_run_ease = 14.0f;

    // Camera settle-hold (post-move-stop). KCD1 does not pin the look yaw (apply_orbit_aim_control writes only the
    // pitch), so the eye-look is dragged 1:1 by the body; when a camera-relative
    // run stops, the engine keeps rotating the standing body for a short, INTERMITTENT window (a stop / idle
    // turn) and the eye-look follows. The rig re-couples to the eye-look the instant move-orbit ends, so without
    // a hold it follows that turn and the camera drifts. (KCD2 pins the look yaw directly, so it never sees this
    // post-stop drift and needs no settle hold; this is a KCD1-only workaround.) While the hold is active the
    // world-stable (look-cancelling) derivation is kept alive - the camera holds its world yaw, decoupled from
    // the look - until the look stops slewing, then the orbit angle is baked and free-look re-couples with no
    // jump. The hold ends when the look has been still for k_orbit_settle_still_frames consecutive frames AND at
    // least k_orbit_settle_min_hold has elapsed (so a brief still BEFORE a late stop-turn cannot end it early),
    // or k_orbit_settle_max_hold as a safety cap. A look that never moves (a straight run that stops square to
    // the camera) settles immediately, so the hold is invisible.
    constexpr float k_orbit_settle_still_rate = 20.0f; // deg/sec; below this the eye-look is "still"
    constexpr int k_orbit_settle_still_frames = 4;     // consecutive still frames to call the look settled
    constexpr float k_orbit_settle_min_hold = 0.12f;   // sec; minimum hold before a still-streak can end it
    constexpr float k_orbit_settle_max_hold = 1.0f;    // sec; safety cap (look never settles)

    // Orbit angle low-pass. The engine smooths native look DOWNSTREAM of the input dispatch the orbit
    // hook captures and blocks, so free-look applies the raw per-frame mouse deltas and reads as jittery.
    // orbit_smoothing (0..1) maps to a frame-rate-independent catch-up speed between these bounds: higher
    // smoothing -> lower speed -> more lag (smoother); 0 disables the filter (snap to the raw target).
    constexpr float k_orbit_smooth_min_speed = 6.0f;  // strength 1.0: heavy smoothing
    constexpr float k_orbit_smooth_max_speed = 40.0f; // strength near 0: barely-there smoothing

    // Aim-basis low-pass (AimBasisSmoothing). Maps the 0..1 strength to a frame-rate-independent slerp
    // catch-up speed: higher strength -> lower speed -> more damping (and slightly laggier aim). The window
    // is faster than the orbit low-pass so even at full strength the camera still tracks genuine aim turns
    // closely while shedding the high-frequency view-shake.
    constexpr float k_basis_smooth_min_speed = 8.0f;  // strength 1.0: heaviest damping
    constexpr float k_basis_smooth_max_speed = 60.0f; // strength near 0: barely-there damping

    // Maximum aim-convergence toe-in. The off-axis camera toes in toward the aim focus point by
    // atan(|OffsetRight| / (focus_distance + follow_distance)); that angle is ALSO the residual crosshair
    // error for any target past the focus. Bounding it stops a small follow distance combined with a
    // shoulder offset from swinging the rendered look far off the aim line (the crosshair drifts left, so
    // the real aim lands to the right). 0.14054 = tan(8 deg); 8 deg leaves typical over-the-shoulder
    // framing unchanged (FollowDistance 5, OffsetRight 1 toes in only ~5.7 deg) and turns the pathological
    // FollowDistance 0.5 / OffsetRight 1 case from ~45 deg down to 8 deg.
    constexpr float k_tan_max_convergence = 0.14054f;

    /**
     * @brief Whether the third-person offset should be applied right now.
     * @details Suppressed (forced first-person) while the game is in any state listed in SuppressTPVState,
     *          so that context renders from the game's own untouched camera. This is a HARD gate: it
     *          overrides cam.applying, so the player cannot toggle third-person back on while a listed state
     *          lasts (unlike the edge-triggered ForcedFPVState policy), and the prior view resumes when the
     *          state ends. Menu and Overlay are read from the LIVE UI signals, so they suppress the same
     *          frame the screen opens and release the same frame it closes; every other state (Combat, Mount,
     *          Dialogue, Minigame, Aiming, Crouch) is matched against the debounced game-state mask, so a
     *          brief flicker does not pop the view. Read directly from the live config, so it is independent
     *          of EnableStateBehavior. Called from the render thread (the frustum detour) and the
     *          input-dispatch thread (the free-look gate); every read is atomic, so the cross-thread call is
     *          safe.
     */
    [[nodiscard]] static bool should_apply_view()
    {
        const uint32_t suppress = settings().suppress_tpv_mask.load(std::memory_order_relaxed);
        if (suppress == 0)
        {
            return true;
        }
        // Menu / Overlay use the live UI signals so suppression is instant (no debounce frame of TPV in a UI).
        if ((suppress & state_bit(GameState::Menu)) != 0 && is_game_menu_open())
        {
            return false;
        }
        if ((suppress & state_bit(GameState::Overlay)) != 0 && overlay_state().active.load(std::memory_order_relaxed))
        {
            return false;
        }
        // Any other listed state is matched against the debounced mask published each game-view frame.
        constexpr uint32_t k_ui_bits = state_bit(GameState::Menu) | state_bit(GameState::Overlay);
        const uint32_t gameplay = suppress & ~k_ui_bits;
        if (gameplay != 0 && (gameplay & game_state_mask().load(std::memory_order_relaxed)) != 0)
        {
            return false;
        }
        return true;
    }

    // ITimer::GetFrameStartTime and ITimer::GetFrameTime (see constants.hpp): the engine frame clock.
    using TimerGetFrameStartTimeFunc = const std::int64_t *(__fastcall *)(uintptr_t timer, int which);
    using TimerGetFrameTimeFunc = float(__fastcall *)(uintptr_t timer, int which);

    /**
     * @brief One engine frame as the frame clock reports it.
     */
    struct EngineFrame
    {
        /// UI-clock frame-start stamp, identical for every read within one frame.
        std::int64_t start_stamp;
        /// Seconds the world advanced this frame.
        float seconds;
    };

    /**
     * @brief Reads the engine frame clock through the g_env timer.
     * @details The timer is confirmed by its RTTI name and both vtable slots must point into the game image
     *          before either is called; the frame time must come back finite and non-negative. The game clock
     *          reads 0 while the game timer is paused (the pause menu), and the UI clock's frame time stands in
     *          then: nothing in the world moves, so its lack of smoothing cannot show, and the view still eases
     *          into and out of the menu. Runs under the frustum detour's SEH frame, which contains a fault in
     *          either engine call.
     * @return The frame, or std::nullopt when the clock cannot be trusted.
     */
    [[nodiscard]] static std::optional<EngineFrame> read_engine_frame()
    {
        const ModuleInfo &mod = module_info();
        if (s_genv_runtime == 0 || mod.base == 0)
        {
            return std::nullopt;
        }
        const auto timer = DMK::memory::read<uintptr_t>(DMK::Address{s_genv_runtime + Constants::GENV_TIMER_OFFSET});
        if (!timer || !DMK::memory::is_plausible_ptr(DMK::Address{*timer}))
        {
            return std::nullopt;
        }
        const auto vtable = DMK::memory::read<uintptr_t>(DMK::Address{*timer});
        if (!vtable || !vtable_is(GameClass::Timer, *vtable))
        {
            return std::nullopt;
        }
        const auto start_fn =
            DMK::memory::read<uintptr_t>(DMK::Address{*vtable + Constants::ITIMER_VTABLE_GET_FRAME_START_TIME_OFFSET});
        const auto time_fn =
            DMK::memory::read<uintptr_t>(DMK::Address{*vtable + Constants::ITIMER_VTABLE_GET_FRAME_TIME_OFFSET});
        const auto in_image = [&mod](const auto &fn) { return fn && *fn >= mod.base && *fn < mod.base + mod.size; };
        if (!in_image(start_fn) || !in_image(time_fn))
        {
            return std::nullopt;
        }

        const std::int64_t *stamp_slot =
            reinterpret_cast<TimerGetFrameStartTimeFunc>(*start_fn)(*timer, Constants::ETIMER_UI);
        const auto stamp = DMK::memory::read<std::int64_t>(DMK::Address{reinterpret_cast<uintptr_t>(stamp_slot)});
        if (!stamp)
        {
            return std::nullopt;
        }
        const auto get_frame_time = reinterpret_cast<TimerGetFrameTimeFunc>(*time_fn);
        float seconds = get_frame_time(*timer, Constants::ETIMER_GAME);
        if (!(seconds > 0.0f))
        {
            seconds = get_frame_time(*timer, Constants::ETIMER_UI);
        }
        if (!std::isfinite(seconds) || seconds < 0.0f)
        {
            return std::nullopt;
        }
        return EngineFrame{*stamp, seconds};
    }

    /**
     * @brief Seconds the camera's per-frame integrators and easings advance on this frustum build, clamped.
     * @details The game view's frustum is built twice per frame (the projection setup, then the final rebuild).
     *          The frame's time is spent on the first build and the second advances by 0; the engine's
     *          frame-start stamp tells the two apart.
     *
     *          The duration is the engine's own game frame time, not the wall-clock gap between two builds. The
     *          engine averages its frame time over the last quarter second and moves the whole world by that
     *          average, so everything it animates advances by a near-constant step per frame. The raw gap between
     *          two builds carries the full frame-to-frame variance instead (about a tenth of a frame on average,
     *          up to half a frame). A rate-driven motion paced on it, the gamepad orbit most of all, then turns by
     *          an uneven step each frame against an evenly moving world, which reads as micro-stutter in a slow
     *          pan. Pacing on the engine clock keeps the camera in step with the world. The wall-clock gap is the
     *          fallback whenever the engine clock cannot be read, and it keeps running every call so that
     *          fallback always measures from the previous build.
     */
    [[nodiscard]] static float frame_delta()
    {
        static std::chrono::steady_clock::time_point s_last_time = std::chrono::steady_clock::now();
        const auto now = std::chrono::steady_clock::now();
        const float wall_delta = std::chrono::duration<float>(now - s_last_time).count();
        s_last_time = now;

        const std::optional<EngineFrame> frame = read_engine_frame();

        // Report which clock paces the camera once per switch, so a log shows whether the engine clock resolved.
        enum class ClockSource
        {
            None,
            Engine,
            Wall,
        };
        static ClockSource s_clock_source = ClockSource::None;
        const ClockSource clock_source = frame.has_value() ? ClockSource::Engine : ClockSource::Wall;
        if (clock_source != s_clock_source)
        {
            s_clock_source = clock_source;
            const char *const clock_name =
                frame.has_value() ? "engine frame clock" : "wall clock (engine clock unavailable)";
            (void)DMK::log().try_log(DMK::LogLevel::Debug, "Camera: pacing on the {}", clock_name);
        }

        if (frame.has_value())
        {
            static std::int64_t s_last_stamp = 0;
            if (frame->start_stamp == s_last_stamp)
            {
                return 0.0f; // second build of the same frame: the frame's time was already spent
            }
            s_last_stamp = frame->start_stamp;
            return std::clamp(frame->seconds, 0.0f, 0.1f);
        }
        return std::clamp(wall_delta, 0.0f, 0.1f);
    }

    /**
     * @brief Resolves the live CCryAction (game-framework) singleton base build-agnostically; 0 if not live.
     * @details The CCryAction singleton's module-relative offset is build-specific (it moves between game
     *          builds), so it is reached purely at runtime through the g_pGameFramework .data slot resolved by
     *          the CryActionFramework RIP-relative AOB cascade, never a hard-coded module offset. The slot's
     *          value is the CCryAction object pointer; it is null until the framework is constructed (0 is
     *          returned then and the caller retries next frame) and 0 is also returned when the Framework gate
     *          failed. Render-thread safe: gated_anchor_address() is a lock-free read of a value resolved once at
     *          init, and the slot deref is a guarded read.
     */
    static uintptr_t resolve_cry_action() noexcept
    {
        const uintptr_t fw_slot = gated_anchor_address(Feature::Framework, AnchorId::CryActionFramework);
        if (fw_slot == 0)
        {
            return 0;
        }
        const auto cry_action = DMK::memory::read<uintptr_t>(DMK::Address{fw_slot});
        return (cry_action && DMK::memory::is_plausible_ptr(DMK::Address{*cry_action})) ? *cry_action : 0;
    }

    /**
     * @brief Resolves the live C_Player via the CCryAction framework each frame (validated by its vtable); 0 on
     *        failure.
     * @details Walks CCryAction (resolve_cry_action(): the g_pGameFramework slot) -> p_action_game -> C_Player,
     *          then confirms C_Player by its main vtable. Resolving FRESH every frame - rather than trusting a
     *          mirrored pointer that goes null/stale across view transitions and reloads - is what keeps the
     *          move-detection and body-turn locked onto the CURRENT player. Every read is a DetourModKit guarded
     *          read, so a stale link reports a miss instead of faulting. Each live base the walk resolves is
     *          published to its self-heal group (note_*_base); the scheduler, ticked once per frame by the
     *          frustum detour, owns when the syscall-heavy scans actually run.
     */
    static uintptr_t resolve_c_player() noexcept
    {
        const ModuleInfo &mod = module_info();
        if (mod.base == 0)
        {
            return 0;
        }
        // KCD1: CCryAction is the game-framework singleton, reached at runtime through the g_pGameFramework
        // .data slot (CryActionFramework AOB cascade) so it survives a game rebuild that relocates it. Confirmed
        // by the C_Player vtable below. No g_env / p_game / GetIGameFramework walk.
        const uintptr_t cry_action = resolve_cry_action();
        if (cry_action == 0)
        {
            return 0;
        }
        // Publish the chain root for the CCryAction -> CActionGame heal group. The scheduler owns the cadence and
        // the latch: its gate stays shut (silently) until the slot holds a constructed CActionGame, so the offset
        // is nominal until then and fixed afterwards. A layout shift here would silently break every walk below,
        // which is why it is the first group registered.
        note_framework_base(cry_action);
        RuntimeOffsets &offsets = runtime_offsets();

        const auto p_action_game =
            DMK::memory::read<uintptr_t>(DMK::Address{cry_action + offsets.ccryaction_actiongame.load().value});
        if (!p_action_game || !DMK::memory::is_plausible_ptr(DMK::Address{*p_action_game}))
        {
            return 0;
        }
        note_action_game_base(*p_action_game);

        // Read the local actor through the self-healed local-actor offset, then confirm it is a real C_Player
        // by its vtable. C_Player is found THROUGH this offset, so the offset cannot be healed from a resolved
        // C_Player; instead, when the cached slot holds a populated object that is NOT a C_Player (the
        // signature of a CActionGame layout drift), the local-actor heal group is asked to recover it.
        auto player =
            DMK::memory::read<uintptr_t>(DMK::Address{*p_action_game + offsets.cactiongame_local_actor.load().value});
        const auto is_c_player = [](const DMK::Result<uintptr_t> &candidate) noexcept
        {
            if (!candidate || !DMK::memory::is_plausible_ptr(DMK::Address{*candidate}))
            {
                return false;
            }
            const auto vt = DMK::memory::read<uintptr_t>(DMK::Address{*candidate});
            return vt.has_value() && vtable_is(GameClass::Player, *vt);
        };
        const bool player_valid = is_c_player(player);
        if (!player_valid && player && DMK::memory::is_plausible_ptr(DMK::Address{*player}))
        {
            // The cached slot holds a populated object that is NOT a C_Player: the signature of a CActionGame
            // layout drift, and ALSO the transient seen while the real player is still seating in during a
            // load. Open the local-actor heal group's gate and let the scheduler recover the offset on its own
            // cadence; it scans CActionGame for the C_Player slot and latches once it resolves. The read above
            // then succeeds on a later frame and this branch stops being entered (the natural stop). The
            // request is idempotent, so a frame that re-enters here simply re-asserts it: the scheduler, not
            // this call site, owns the "do not scan every frame" rate limit and the never-give-up retry.
            request_local_actor_recovery();
        }
        if (!player_valid)
        {
            return 0;
        }

        // A real C_Player is in hand (vtable validated above): publish it for the player-rooted heal groups, so
        // the per-frame aim and body-turn walks read the recovered offsets on a drifted build.
        note_player_base(*player);

        // Log the resolved C_Player and the static CCryAction only when the player pointer CHANGES (once on
        // first resolve, and again after a reload / new player) so the address is available for external
        // tooling without flooding the log.
        {
            static uintptr_t s_logged_player{0};
            if (*player != s_logged_player)
            {
                s_logged_player = *player;
                (void)DMK::log().try_log(DMK::LogLevel::Debug, "C_Player resolved={} (CCryAction={})",
                                         DMK::format::format_address(*player), DMK::format::format_address(cry_action));
            }
        }

        // The player resolves once the game is in-world (window at its final resolution); let the overlay
        // wait on this so it never sizes itself to the transient loading window.
        game_world_ready().store(true, std::memory_order_relaxed);

        return *player;
    }

    /**
     * @brief Resolves the player look controller and drives the real aim while orbiting: eases the PITCH
     *        toward level and/or sets the YAW (heading).
     * @details Walks the player look chain (CCryAction via resolve_cry_action() -> p_action_game -> C_Player ->
     *          look controller; see constants.hpp) and validates C_Player by its vtable. The look quaternion the
     *          cameras read is RE-DERIVED from the controller's scalar pitch every frame, so writing that scalar
     *          (not the derived quat, which is overwritten) is what actually moves the eye and the character
     *          head. The mod redirects the look input while orbiting, so the writes stick; on any failure it
     *          returns without writing and the camera-side level blend still levels the view.
     *
     *          Every read is a guarded read and every store goes through DMK::memory::write_in_place, the library's
     *          per-frame data write: a guarded copy that changes NO page protection and fails closed with
     *          WriteFaulted when the target is not already writable. That is the right primitive for a value
     *          written every frame through a RESOLVED address (a pointer chain that can go stale between
     *          frames), and it is why this function needs no SEH wrapper of its own: a stale chain reports a
     *          fault instead of raising one. It is also an out-of-line library call, so the consume-once store
     *          the engine reads on its own thread cannot be elided.
     *
     *          The look yaw is never written: the movement-frame heading is steered by the body-turn override
     *          (apply_orbit_body_turn) alone, because KCD moves the player relative to the body, not the look.
     * @param pitch_ease Per-frame fraction to move the look pitch toward level, in (0, 1].
     */
    static void apply_orbit_aim_control(float pitch_ease) noexcept
    {
        const ModuleInfo &mod = module_info();
        if (mod.base == 0)
        {
            return;
        }
        // KCD1: CCryAction is the game-framework singleton, reached at runtime through the g_pGameFramework
        // .data slot (CryActionFramework AOB cascade) so it survives a game rebuild that relocates it. Confirmed
        // by the C_Player vtable below. No g_env / p_game / GetIGameFramework walk.
        const uintptr_t cry_action = resolve_cry_action();
        if (cry_action == 0)
        {
            return;
        }
        // Publish the chain root for its heal group, as the resolver does.
        note_framework_base(cry_action);

        const RuntimeOffsets &offsets = runtime_offsets();
        const auto p_action_game =
            DMK::memory::read<uintptr_t>(DMK::Address{cry_action + offsets.ccryaction_actiongame.load().value});
        if (!p_action_game || !DMK::memory::is_plausible_ptr(DMK::Address{*p_action_game}))
        {
            return;
        }
        const auto c_player =
            DMK::memory::read<uintptr_t>(DMK::Address{*p_action_game + offsets.cactiongame_local_actor.load().value});
        if (!c_player || !DMK::memory::is_plausible_ptr(DMK::Address{*c_player}))
        {
            return;
        }
        // Confirm this is really C_Player (its main vtable) before trusting the controller offset.
        const auto vt = DMK::memory::read<uintptr_t>(DMK::Address{*c_player});
        if (!vt || !vtable_is(GameClass::Player, *vt))
        {
            return;
        }
        // This offset decides where a WRITE lands, so demand a Confirmed heal rather than accepting the retained
        // nominal: on a genuinely drifted C_Player the store would land in whatever member now occupies the slot.
        // A miss simply skips the aim control for the frame (fail closed); the camera-side level blend still
        // levels the view.
        const auto look_controller_offset = offsets.c_player_look_controller.authorized();
        if (!look_controller_offset)
        {
            return;
        }
        const auto controller = DMK::memory::read<uintptr_t>(DMK::Address{*c_player + *look_controller_offset});
        if (!controller || !DMK::memory::is_plausible_ptr(DMK::Address{*controller}))
        {
            return;
        }
        // Ease the SCALAR pitch toward 0 (level). Both synchronized copies are written so any internal
        // current/target smoothing also settles at level. A sane pitch is within about +/- 1.6 rad; a
        // wild or non-finite value means the layout drifted, so that write is skipped.
        const DMK::Address pitch_addr{*controller + Constants::LOOK_CONTROLLER_PITCH_OFFSET};
        const auto pitch_value = DMK::memory::read<float>(pitch_addr);
        if (pitch_value && *pitch_value > -3.2f && *pitch_value < 3.2f)
        {
            const float levelled = *pitch_value * (1.0f - pitch_ease);
            (void)DMK::memory::write_in_place<float>(pitch_addr, levelled);
            (void)DMK::memory::write_in_place<float>(
                DMK::Address{*controller + Constants::LOOK_CONTROLLER_PITCH2_OFFSET}, levelled);
        }
    }

    /**
     * @brief Forces the player BODY to face a world yaw, making movement+facing camera-relative.
     * @details The look controller (apply_orbit_aim_control) is aim-only: writing its yaw steers the
     *          movement frame but does not turn the body. The body heading is owned by the engine's
     *          animated-character layer. This replicates CAnimatedCharacter::ForceOverrideRotation
     *          (main vtable slot 95): set the override-active byte and store a yaw-only world quat
     *          (XYZW, rotation about +Z); the animated-character update copies it into the entity
     *          rotation for the frame, replacing the animation-derived facing, then clears the active
     *          byte. It is consume-once, so this is called every frame while the heading is held.
     *
     *          Resolution mirrors apply_orbit_aim_control: CCryAction -> p_action_game -> C_Player (validated
     *          vtable) -> C_AnimatedHuman -> CAnimatedCharacter, validated by the animchar vtable before any
     *          write. The quat is written before the active byte so the game never observes active==1 with a
     *          torn/stale quat. See constants.hpp (ANIMCHAR_*, C_PLAYER_ANIMATED_HUMAN_OFFSET) for the offsets.
     */
    static void apply_orbit_body_turn(float target_yaw) noexcept
    {
        const ModuleInfo &mod = module_info();
        const uintptr_t c_player = resolve_c_player();
        if (mod.base == 0 || c_player == 0)
        {
            return;
        }

        // C_Player -> C_AnimatedHuman (+0x2F8) -> CAnimatedCharacter (+0x20). Both offsets decide where a WRITE
        // lands, so each must be a Confirmed heal rather than a retained nominal; on a drifted layout the quat
        // would otherwise be stored over whatever member now occupies the slot. A miss skips the body turn for
        // the frame (fail closed).
        const RuntimeOffsets &offsets = runtime_offsets();
        const auto animated_human_offset = offsets.c_player_animated_human.authorized();
        const auto animchar_offset = offsets.animated_human_animchar.authorized();
        if (!animated_human_offset || !animchar_offset)
        {
            return;
        }

        // One guarded walk instead of a read-and-screen per hop: walk() reads each hop under the same fault
        // guard, screens it against the plausibility floor, and reports the failing hop index on a miss.
        const std::array<std::ptrdiff_t, 3> animchar_chain{*animated_human_offset, *animchar_offset, 0};
        const auto anim_char = DMK::memory::walk(DMK::Address{c_player}, animchar_chain);
        if (!anim_char || !DMK::memory::is_plausible_ptr(*anim_char))
        {
            return;
        }
        // Validate the animchar vtable before touching its override fields; a mismatch means the layout
        // drifted, so skip this frame.
        const auto avt = DMK::memory::read<uintptr_t>(*anim_char);
        if (!avt || !vtable_is(GameClass::AnimatedCharacter, *avt))
        {
            return;
        }

        // Yaw-only world quat (XYZW): rotation about +Z by target_yaw == {0, 0, sin(y/2), cos(y/2)}. The four
        // components are contiguous and written as ONE guarded store, so the quat cannot straddle a protection
        // boundary mid-write and there is no per-component call. DMK::memory::write_in_place is the per-frame data
        // write: guarded, no protection change, and it fails closed instead of faulting the host when the
        // resolved chain has gone stale - which is why this function needs no SEH wrapper of its own.
        const float half = target_yaw * 0.5f;
        const std::array<float, 4> quat{0.0f, 0.0f, std::sin(half), std::cos(half)};
        static_assert(Constants::QUAT_X_OFFSET == 0 && Constants::QUAT_Y_OFFSET == 4 && Constants::QUAT_Z_OFFSET == 8 &&
                          Constants::QUAT_W_OFFSET == 12,
                      "The quat components must be contiguous XYZW floats for the single-store write.");
        if (!DMK::memory::write_in_place<std::array<float, 4>>(
                anim_char->offset(Constants::ANIMCHAR_OVERRIDE_ROT_QUAT_OFFSET), quat))
        {
            return;
        }
        // Set the active byte LAST so the animated-character update (a separate consumer) never reads
        // active==1 with a half-written quat. The release fence orders the quat store before the active
        // store explicitly rather than relying on the target's store-store ordering; on x86 it lowers to a
        // compiler barrier with no runtime cost.
        std::atomic_thread_fence(std::memory_order_release);
        (void)DMK::memory::write_in_place<unsigned char>(
            anim_char->offset(Constants::ANIMCHAR_OVERRIDE_ROT_ACTIVE_OFFSET), 1);
    }

    /**
     * @brief Writes the player's body-relative move input (C_PlayerInput +0x58 x, +0x5C y), validated by the
     *        C_PlayerInput class identity. Keyboard movement is digital edge-events the engine holds internally;
     *        writing this field each frame OVERRIDES the held keys, and because it is a FIELD write (not an xi_*
     *        action) it does NOT flip the HUD device glyphs. Guarded reads and one guarded store, so a stale
     *        C_PlayerInput reports a miss instead of faulting.
     */
    static void write_player_input_move(uintptr_t player_input, float x, float y) noexcept
    {
        const ModuleInfo &mod = module_info();
        if (mod.base == 0 || player_input == 0 || !DMK::memory::is_plausible_ptr(DMK::Address{player_input}))
        {
            return;
        }
        const auto vtable = DMK::memory::read<uintptr_t>(DMK::Address{player_input});
        if (!vtable || !vtable_is(GameClass::PlayerInput, *vtable))
        {
            return;
        }
        // Ensure this is the PLAYER's C_PlayerInput (its +0x10 backref is C_Player), not some other instance,
        // before writing its move field.
        const auto owner =
            DMK::memory::read<uintptr_t>(DMK::Address{player_input + Constants::C_PLAYERINPUT_PLAYER_BACKREF_OFFSET});
        if (!owner || *owner != resolve_c_player())
        {
            return;
        }
        static_assert(Constants::C_PLAYERINPUT_MOVE_Y_OFFSET == Constants::C_PLAYERINPUT_MOVE_X_OFFSET + 4,
                      "The move input must be contiguous {x, y} floats for the single-store write.");
        const std::array<float, 2> move{x, y};
        (void)DMK::memory::write_in_place<std::array<float, 2>>(
            DMK::Address{player_input + Constants::C_PLAYERINPUT_MOVE_X_OFFSET}, move);
    }

    /**
     * @brief Keyboard turn-and-run move-input override. When active, writes the caller-computed body-relative move
     *        vector (x = strafe, y = forward) into C_PlayerInput so the held keyboard keys run in the body-faced
     *        direction and sprint engages (KCD drops sprint on non-forward input). The caller computes the vector
     *        per frame (pure-forward while turning, the real keys rotated by the eased facing while disengaging),
     *        so when inactive there is nothing to restore - the engine drives the keyboard move input normally.
     */
    static void apply_keyboard_move_override(bool active, float x, float y) noexcept
    {
        static bool s_prev = false;
        const uintptr_t player_input = player_onaction_player_input();
        if (active)
        {
            write_player_input_move(player_input, x, y);
        }
        else if (s_prev)
        {
            // Falling edge: the override stopped this frame. Write the REAL keys (0,0 if released) ONCE so the
            // move field is not stranded at the last override value - otherwise the character never stops.
            // After this the engine drives the keyboard move input normally.
            float real_fwd = 0.0f;
            float real_lat = 0.0f;
            (void)player_onaction_keyboard_move_vector(real_fwd, real_lat);
            write_player_input_move(player_input, real_lat, real_fwd);
        }
        s_prev = active;
    }

    // Turn-in-place pivot hold tuning. A native turn step is the body rotating TOWARD the look (faster than
    // k_turn_hold_yaw_rate) while it trails the look by more than k_turn_hold_min_gap, moving no faster than
    // k_turn_hold_max_speed and with no movement input. Its displacement, and that of the step's foot settle for
    // k_turn_hold_settle after the rotation stops, is held off the pivot. A body that moves faster than
    // k_turn_hold_follow_speed without being held is really moving, and the hold eases back onto it at
    // k_turn_hold_release_rate. A per-frame jump beyond k_turn_hold_teleport is a teleport or a load, not a step, and
    // drops the hold. The hold never exceeds k_turn_hold_max. With the turn steps kept in place
    // (detour_phys_ent_movement) there is normally nothing to hold; this keeps the camera still when that hook is
    // unavailable.
    constexpr float k_turn_hold_yaw_rate = 0.26f;    // rad/s (15 deg/s)
    constexpr float k_turn_hold_min_gap = 0.17f;     // rad (10 deg)
    constexpr float k_turn_hold_max_speed = 1.2f;    // m/s
    constexpr float k_turn_hold_follow_speed = 0.3f; // m/s
    constexpr float k_turn_hold_settle = 0.35f;      // seconds
    constexpr float k_turn_hold_teleport = 0.25f;    // meters per frame
    constexpr float k_turn_hold_max = 0.5f;          // meters
    constexpr float k_turn_hold_release_rate = 8.0f; // 1/s

    /**
     * @brief Keeps the pivot still while the body turns in place, returning the horizontal offset to hold off it.
     * @details A native turn-in-place animation carries root motion: the body steps 5-20 cm while it turns, and the
     *          rig anchors to the body, so the camera shifts with every turn unless the step is held off. The
     *          displacement of a turn step is absorbed into a hold the caller subtracts from its anchor, so the camera
     *          stays where it was during and after the turn. A turn step is recognised by its signature: the body
     *          rotates toward the look it trails, at step speed, with no movement input. Running to a stop, a
     *          scripted move or a push does not match it, so the camera follows them, and any such movement also
     *          eases the hold back onto the body. Standing still keeps the hold. Without the look the rotation alone
     *          is used. Normally the steps are kept in place (detour_phys_ent_movement) and the hold stays near zero;
     *          it is the fallback for when that hook is unavailable.
     * @param cam Camera state holding the tracker and the hold.
     * @param body_origin The entity world origin this frame.
     * @param body_yaw The entity world yaw this frame (radians).
     * @param look_yaw The look yaw this frame (radians), used only when @p look_valid.
     * @param look_valid Whether @p look_yaw was read.
     * @param delta_time Frame time in seconds.
     * @return The horizontal offset (z = 0) to subtract from the anchor.
     */
    static Vector3 hold_turn_in_place_pivot(CameraState &cam, const Vector3 &body_origin, float body_yaw,
                                            float look_yaw, bool look_valid, float delta_time)
    {
        if (!cam.turn_track_valid)
        {
            cam.turn_track_x = body_origin.x;
            cam.turn_track_y = body_origin.y;
            cam.turn_track_yaw = body_yaw;
            cam.turn_track_valid = true;
            cam.turn_hold_x = 0.0f;
            cam.turn_hold_y = 0.0f;
            cam.turn_hold_timer = 0.0f;
            return Vector3{0.0f, 0.0f, 0.0f};
        }
        const float step_x = body_origin.x - cam.turn_track_x;
        const float step_y = body_origin.y - cam.turn_track_y;
        const float step = std::sqrt(step_x * step_x + step_y * step_y);
        const float turn = std::remainder(body_yaw - cam.turn_track_yaw, 2.0f * DirectX::XM_PI);
        cam.turn_track_x = body_origin.x;
        cam.turn_track_y = body_origin.y;
        cam.turn_track_yaw = body_yaw;
        if (step > k_turn_hold_teleport)
        {
            cam.turn_hold_x = 0.0f;
            cam.turn_hold_y = 0.0f;
            cam.turn_hold_timer = 0.0f;
            return Vector3{0.0f, 0.0f, 0.0f};
        }

        const float speed = delta_time > 1e-4f ? step / delta_time : 0.0f;
        const bool native_turn = s_native_turn_actor.load(std::memory_order_relaxed) != 0;
        const bool move_input =
            !player_onaction_available() || player_onaction_move_magnitude() > k_orbit_move_input_stop;
        const bool in_place = native_turn && !move_input && speed < k_turn_hold_max_speed;
        bool toward_look = true;
        if (look_valid)
        {
            const float gap = std::remainder(look_yaw - body_yaw, 2.0f * DirectX::XM_PI);
            toward_look = std::fabs(gap) > k_turn_hold_min_gap && turn * gap > 0.0f;
        }
        if (in_place && toward_look && std::fabs(turn) > k_turn_hold_yaw_rate * delta_time)
        {
            cam.turn_hold_timer = k_turn_hold_settle;
        }
        else
        {
            cam.turn_hold_timer = std::max(0.0f, cam.turn_hold_timer - delta_time);
        }

        if (in_place && cam.turn_hold_timer > 0.0f)
        {
            cam.turn_hold_x += step_x;
            cam.turn_hold_y += step_y;
        }
        else if (!native_turn || speed > k_turn_hold_follow_speed)
        {
            // Real movement (or the feature off). Keyed on the body's speed rather than the movement-input latch, which
            // a combat action-map swap can strand above zero with the keys up.
            const float keep = std::exp(-k_turn_hold_release_rate * delta_time);
            cam.turn_hold_x *= keep;
            cam.turn_hold_y *= keep;
        }
        const float held = std::sqrt(cam.turn_hold_x * cam.turn_hold_x + cam.turn_hold_y * cam.turn_hold_y);
        if (held > k_turn_hold_max)
        {
            const float scale = k_turn_hold_max / held;
            cam.turn_hold_x *= scale;
            cam.turn_hold_y *= scale;
        }
        return Vector3{cam.turn_hold_x, cam.turn_hold_y, 0.0f};
    }

    /**
     * @brief Rebuilds the look orientation from its heading and the scalar pitch, without the stale roll.
     * @details The raw look quat can carry a stale roll angle (see LOOK_CONTROLLER_QUAT_OFFSET).
     *          C_CameraFirstPerson::Update never renders that quat directly. It takes only the heading of the look
     *          forward vector and combines it with the scalar pitch that C_Player vtable slot 58 returns
     *          (controller + LOOK_CONTROLLER_PITCH2_OFFSET), so the roll never reaches the first-person view. This
     *          helper builds RotZ(heading) * RotX(pitch) from the same two inputs, which gives a level aim with no
     *          view shake. The game's own third-person camera renders the raw quat instead.
     * @param look Look quat read from the controller.
     * @param pitch Scalar look pitch in radians, 0 = level.
     * @return Roll-free look orientation.
     */
    [[nodiscard]] static Quaternion level_look_rotation(const Quaternion &look, float pitch) noexcept
    {
        // Heading of forward = look * +Y, the yaw the engine extracts. The engine writes forward.y as
        // 2 * (y * y + w * w) - 1, which holds only at unit length. The homogeneous form below keeps the heading
        // exact for the slightly non-unit quats the caller's sanity check still accepts.
        const float forward_x = 2.0f * (look.x * look.y - look.w * look.z);
        const float forward_y = look.w * look.w - look.x * look.x + look.y * look.y - look.z * look.z;
        const float heading = std::atan2(-forward_x, forward_y);
        const float sin_heading = std::sin(heading * 0.5f);
        const float cos_heading = std::cos(heading * 0.5f);
        const float sin_pitch = std::sin(pitch * 0.5f);
        const float cos_pitch = std::cos(pitch * 0.5f);
        // Expanded product RotZ(heading) * RotX(pitch) in XYZW order.
        return Quaternion{cos_heading * sin_pitch, sin_heading * sin_pitch, sin_heading * cos_pitch,
                          cos_heading * cos_pitch};
    }

    /**
     * @brief Offsets the game view camera matrix behind the player and advances zoom/smoothing.
     * @details Reads the eye anchor and orientation from the untouched CView pose (position at
     *          SVIEWPARAMS_POSITION_OFFSET, quat at SVIEWPARAMS_ROTATION_OFFSET), derives the look
     *          basis from the quat (idempotent across same-frame rebuilds), computes the
     *          third-person pose, then writes the camera matrix translation and (on convergence/
     *          orbit) basis. The caller is about to compute the cull planes from this matrix, so
     *          culling matches the rendered view.
     * @param camera The game view's embedded render camera (matrix at offset 0).
     * @param cview The CView embedding the camera (camera - SVIEWPARAMS_VIEWMATRIX_OFFSET).
     * @param c_player Live C_Player address for the body anchor, or 0 to fall back to the eye anchor.
     * @param delta_time Seconds since the previous game-view frame (shared with the state poll).
     * @param view_blend Smoothstepped first-person(0) -> third-person(1) blend for the view-switch ease.
     */
    static void offset_game_view_camera(uintptr_t camera, uintptr_t cview, uintptr_t c_player, float delta_time,
                                        float view_blend)
    {
        LiveSettings &cfg = settings();
        CameraState &cam = camera_state();

        // Follow distance = configured base (hot-reloadable INI FollowDistance, re-read every
        // frame so an edit applies live) plus the accumulated zoom offset from the hold
        // keys, clamped to the configured window. The holds are queried through the BindingTokens the control
        // plane publishes (refresh_zoom_binding_tokens), the library's per-frame form of the query; before the
        // first publish the name-based query stands in.
        const DMK::input::Input &input = DMK::input::Input::instance();
        const std::shared_ptr<const ZoomBindingTokens> zoom_tokens = s_zoom_tokens.load(std::memory_order_acquire);
        const bool zoom_in_held =
            zoom_tokens ? input.is_active(zoom_tokens->zoom_in) : input.is_active(k_zoom_in_binding);
        const bool zoom_out_held =
            zoom_tokens ? input.is_active(zoom_tokens->zoom_out) : input.is_active(k_zoom_out_binding);
        float zoom_offset = cam.zoom_offset.load(std::memory_order_relaxed);
        const float zoom_step = cfg.zoom_step.load(std::memory_order_relaxed);
        if (zoom_in_held)
        {
            zoom_offset -= zoom_step * delta_time; // zoom in pulls the camera closer
        }
        if (zoom_out_held)
        {
            zoom_offset += zoom_step * delta_time;
        }
        const float base_distance = cfg.follow_distance.load(std::memory_order_relaxed);
        const float distance =
            std::clamp(base_distance + zoom_offset, cfg.follow_distance_min.load(std::memory_order_relaxed),
                       cfg.follow_distance_max.load(std::memory_order_relaxed));
        cam.zoom_offset.store(distance - base_distance, std::memory_order_relaxed);

        // Read the eye anchor and the orientation quat from the untouched CView pose. The basis is
        // derived from the quat (CryEngine column-vector convention: right = quat * +X, forward =
        // quat * +Y, up = quat * +Z). Reading the quat rather
        // than the matrix columns keeps the basis idempotent across the frustum builder's same-frame
        // rebuilds (we overwrite the matrix, never the pose, so the pose stays the clean eye input).
        // The matrix to offset is the camera's 3x4 at offset 0 (cview + SVIEWPARAMS_VIEWMATRIX_OFFSET).
        // The eye pose is read through DMK::memory::read (memcpy semantics into a representation-safe Vector3 /
        // Quaternion): it screens the source against the user-mode window and a wrap guard, reports an
        // access fault as an Error from its own guard, and avoids the type-pun UB of a placement
        // reinterpret_cast read, so a stale/torn cview fails closed here rather than depending solely on the
        // outer detour SEH frame.
        const auto eye_position_read =
            DMK::memory::read<Vector3>(DMK::Address{cview + Constants::SVIEWPARAMS_POSITION_OFFSET});
        const auto eye_rotation_read =
            DMK::memory::read<Quaternion>(DMK::Address{cview + Constants::SVIEWPARAMS_ROTATION_OFFSET});
        if (!eye_position_read || !eye_rotation_read)
        {
            return; // CView pose read faulted; leave the view untouched this frame
        }
        const Vector3 eye_position = *eye_position_read;
        const Quaternion eye_rotation = *eye_rotation_read;
        // FPV-side basis (the engine eye orientation). Kept as the view-blend SOURCE so view_blend 0 leaves
        // the untouched first-person view; the third-person rig basis below is built from a STABLE source.
        const Vector3 eye_forward = eye_rotation.rotate(Vector3{0.0f, 1.0f, 0.0f});
        const Vector3 eye_up = eye_rotation.rotate(Vector3{0.0f, 0.0f, 1.0f});

        // Stable rig basis. The third-person rig (camera = pivot - forward * distance) amplifies any rotation of
        // the basis into a position swing. The EyeHeight body anchor removes the POSITIONAL bob, and this removes
        // the ROTATIONAL component the engine bakes into the eye quat during animations (head-bob and weapon-sway
        // rotation, combat / hit / landing shake). StableAimBasis follows the player's clean look-controller AIM
        // instead, leveled by level_look_rotation. That aim carries none of the engine view-shake and equals the eye
        // quat at rest. AimBasisSmoothing low-passes it. basis_overridden records whether the basis was shaped at
        // all. When neither feature is active the basis stays the raw eye quat, and the orientation path below is
        // byte-identical to the convergence/orbit-only behavior (a fail-safe default).
        Quaternion basis_rotation = eye_rotation;
        bool basis_overridden = false;
        Quaternion look_rotation = eye_rotation;
        bool look_valid = false;
        if (cfg.stable_aim_basis.load(std::memory_order_relaxed) && c_player != 0)
        {
            // Read the look controller through the self-healed offset (seeded from the constant, recovered if
            // the C_Player layout drifts) so the basis tracks the same controller the orbit aim control writes.
            // Read-only here (the basis is derived from the controller's quat and pitch), so the retained nominal is
            // acceptable: worst case on a drifted layout it reads neighboring fields and the sanity checks below
            // reject them. The WRITE path (apply_orbit_aim_control) demands a Confirmed heal.
            const std::ptrdiff_t c_player_look_controller_offset =
                runtime_offsets().c_player_look_controller.load().value;
            const auto controller =
                DMK::memory::read<uintptr_t>(DMK::Address{c_player + c_player_look_controller_offset});
            if (controller && DMK::memory::is_plausible_ptr(DMK::Address{*controller}))
            {
                const auto look_quat =
                    DMK::memory::read<Quaternion>(DMK::Address{*controller + Constants::LOOK_CONTROLLER_QUAT_OFFSET});
                const auto look_pitch =
                    DMK::memory::read<float>(DMK::Address{*controller + Constants::LOOK_CONTROLLER_PITCH2_OFFSET});
                if (look_quat && look_pitch)
                {
                    const Quaternion q = *look_quat;
                    const float n2 = q.x * q.x + q.y * q.y + q.z * q.z + q.w * q.w;
                    // Accept only a finite, ~unit quaternion and a finite pitch within the engine's look clamp, plus
                    // a small margin. A layout drift that feeds garbage falls back to the eye quat and never rotates
                    // the rig by a denormal.
                    if (std::isfinite(n2) && n2 > 0.9f && n2 < 1.1f && std::isfinite(*look_pitch) &&
                        std::fabs(*look_pitch) <= 1.6f)
                    {
                        look_rotation = level_look_rotation(q, *look_pitch);
                        look_valid = true;
                    }
                }
            }
        }
        // Low-pass the basis quaternion toward the target: the leveled look orientation when StableAimBasis resolved
        // it, else the raw eye quat. Snaps on the first engaged frame (basis_quat_valid false) so the camera does not
        // swing in from a stale orientation across a first-person gap. AimBasisSmoothing 0 disables the filter
        // (the target is used directly).
        const float basis_smoothing = std::clamp(cfg.aim_basis_smoothing.load(std::memory_order_relaxed), 0.0f, 1.0f);
        if (look_valid || basis_smoothing > 1e-4f)
        {
            basis_overridden = true;
            const DirectX::XMVECTOR target = (look_valid ? look_rotation : eye_rotation).to_xm_vector();
            DirectX::XMVECTOR result;
            if (!cam.basis_quat_valid)
            {
                result = target; // snap on the first engaged frame so the camera does not swing in from stale
                cam.basis_quat_valid = true;
            }
            else if (basis_smoothing > 1e-4f)
            {
                const DirectX::XMVECTOR current =
                    DirectX::XMVectorSet(cam.basis_quat_x, cam.basis_quat_y, cam.basis_quat_z, cam.basis_quat_w);
                const float speed =
                    k_basis_smooth_max_speed - basis_smoothing * (k_basis_smooth_max_speed - k_basis_smooth_min_speed);
                const float t = 1.0f - std::exp(-speed * delta_time);
                // XMQuaternionSlerp takes the shortest arc, so a quaternion double-cover sign flip never spins the
                // basis the long way.
                result = DirectX::XMQuaternionNormalize(DirectX::XMQuaternionSlerp(current, target, t));
            }
            else
            {
                result = target; // StableAimBasis on, smoothing off: use the look target directly
            }
            cam.basis_quat_x = DirectX::XMVectorGetX(result);
            cam.basis_quat_y = DirectX::XMVectorGetY(result);
            cam.basis_quat_z = DirectX::XMVectorGetZ(result);
            cam.basis_quat_w = DirectX::XMVectorGetW(result);
            basis_rotation = Quaternion{cam.basis_quat_x, cam.basis_quat_y, cam.basis_quat_z, cam.basis_quat_w};
        }
        else
        {
            cam.basis_quat_valid = false; // basis not shaped: the next engage snaps the low-pass
        }

        const Vector3 right = basis_rotation.rotate(Vector3{1.0f, 0.0f, 0.0f});
        const Vector3 forward = basis_rotation.rotate(Vector3{0.0f, 1.0f, 0.0f});
        const Vector3 up = basis_rotation.rotate(Vector3{0.0f, 0.0f, 1.0f});
        GameStructures::Matrix34f *matrix = reinterpret_cast<GameStructures::Matrix34f *>(camera);
        // Per-preset FOV, smoothly crossing the "off" boundary. SetFrustum writes the render CCamera's FOV
        // scalar at camera+0x30 right before this builder, plus the cull-frustum edge vectors at camera+0x50 /
        // +0x58 / +0x60 / +0x68 / +0x70 (all proportional to 1/tan(fov/2), with +0x60 the tan term itself). So
        // camera+0x30 read here is the live GAME FOV (radians). cfg.fov is the per-preset TARGET in degrees
        // (0 = use the game FOV). We ease a rendered FOV toward (target>0 ? target : game FOV) with a 2-stage
        // critically-damped ease at the preset-blend rate, so turning a preset's FOV on/off GLIDES through the
        // game FOV instead of snapping across 0. We write it (rescaling the edges by tan(new/2)/tan(game/2) so
        // culling matches) only while a preset wants a FOV or is still easing back; once settled at the game FOV
        // we pass through, so the game's own dynamic FOV keeps working. TPV only.
        const float game_fov = *reinterpret_cast<const float *>(
            camera + Constants::CCAMERA_PROJECTION_FOV_OFFSET); // radians, freshly set by SetFrustum
        if (view_blend > 0.0f && game_fov > 0.05f && game_fov < 3.0f)
        {
            const float fov_target_degrees = cfg.fov.load(std::memory_order_relaxed);
            const float desired_fov =
                (fov_target_degrees > 0.0f) ? DMK::math::degrees_to_radians(fov_target_degrees) : game_fov;
            const float speed = cfg.preset_blend_speed.load(std::memory_order_relaxed);
            if (!cam.fov_ease_valid) // first engaged frame after a first-person gap: snap, no ease across the gap
            {
                cam.fov_ease_stage1 = desired_fov;
                cam.fov_ease_applied = desired_fov;
                cam.fov_ease_valid = true;
            }
            else
            {
                const float alpha = (speed > 0.0f) ? (1.0f - std::exp(-speed * 1.6f * delta_time)) : 1.0f;
                cam.fov_ease_stage1 +=
                    (desired_fov - cam.fov_ease_stage1) * alpha; // 2-stage critically-damped, like the preset blend
                cam.fov_ease_applied += (cam.fov_ease_stage1 - cam.fov_ease_applied) * alpha;
            }
            // Override while a preset wants a FOV or while still easing back toward the game FOV; otherwise pass
            // through (preset off + settled) so the game keeps its own FOV (including any dynamic FOV).
            if ((fov_target_degrees > 0.0f || std::fabs(cam.fov_ease_applied - game_fov) > 0.005f) &&
                cam.fov_ease_applied > 0.05f && cam.fov_ease_applied < 3.0f)
            {
                const float ratio = std::tan(cam.fov_ease_applied * 0.5f) / std::tan(game_fov * 0.5f);
                *reinterpret_cast<float *>(camera + Constants::CCAMERA_PROJECTION_FOV_OFFSET) =
                    cam.fov_ease_applied; // projection FOV (radians)
                *reinterpret_cast<float *>(camera + Constants::CCAMERA_CULL_EDGE_0_OFFSET) *=
                    ratio; // cull edges (proportional to 1/tan)
                *reinterpret_cast<float *>(camera + Constants::CCAMERA_CULL_EDGE_1_OFFSET) *= ratio;
                *reinterpret_cast<float *>(camera + Constants::CCAMERA_CULL_TAN_OFFSET) /=
                    ratio; // = tan term (inverse)
                *reinterpret_cast<float *>(camera + Constants::CCAMERA_CULL_EDGE_3_OFFSET) *= ratio;
                *reinterpret_cast<float *>(camera + Constants::CCAMERA_CULL_EDGE_4_OFFSET) *= ratio;
            }
        }
        // First-person camera position - the blend source for the view-switch ease. Sourced from the
        // untouched eye pose (cview + SVIEWPARAMS_POSITION_OFFSET, same as eye_position above), NOT the
        // matrix translation this function overwrites, so a second same-frame frustum rebuild does not
        // compound the FPV->TPV lerp (the same idempotency the rotation basis and the TPV anchor rely on).
        // The engine builds the matrix translation from this eye pose, so at view_blend 0 the matrix is
        // left exactly first person.
        const Vector3 fpv_position = eye_position;

        // Over-the-shoulder lateral offset along the eye-right axis, applied to the non-orbit follow
        // pose. During free-look it is folded into the orbit start offset (below) so it revolves with
        // the ring, which keeps engaging free-look continuous.
        const Vector3 lateral_offset = right * cfg.offset_right.load(std::memory_order_relaxed);

        // Anchor the rig to a STABLE point. The first-person eye (eye_position, read from CView+0x14)
        // carries head-bob, breathing and weapon-sway, so anchoring the third-person camera to it
        // shakes the whole view. Instead anchor to the player BODY origin - column 3 of the entity
        // world matrix at OFFSET_ENTITY_WORLD_MATRIX_MEMBER (Matrix34, translation at m[*][3]) - which
        // does not bob - lifted by EyeHeight to roughly eye level along world up. Falls back to the eye
        // anchor when the feature is off (EyeHeight <= 0) or the entity/world matrix is unavailable, so
        // a missing player or a layout drift degrades to the previous behaviour rather than misplacing
        // the camera.
        const Vector3 world_up{0.0f, 0.0f, 1.0f};
        const float eye_height = cfg.eye_height.load(std::memory_order_relaxed);
        // Read the player body world origin once. It feeds the stable anchor (below) AND the
        // device-agnostic movement speed used by the camera-relative move alignment; body_valid gates both.
        Vector3 body_origin{0.0f, 0.0f, 0.0f};
        float body_yaw = 0.0f;
        bool body_valid = false;
        {
            // Resolve the entity FRESH from the live C_Player every frame (rather than trusting a mirrored
            // pointer that goes null/stale across view transitions and reloads), which is what keeps the
            // move-detection (hence the camera-relative body-turn and the body anchor) locked onto the
            // CURRENT player. On a failed walk body_valid stays false and the camera degrades to the eye anchor.
            uintptr_t entity_addr = 0;
            if (c_player != 0)
            {
                const auto ent = DMK::memory::read<uintptr_t>(
                    DMK::Address{c_player + runtime_offsets().c_player_entity.load().value});
                if (ent && DMK::memory::is_plausible_ptr(DMK::Address{*ent}))
                {
                    entity_addr = *ent;
                }
            }
            if (entity_addr != 0 && DMK::memory::is_plausible_ptr(DMK::Address{entity_addr}))
            {
                const auto world_matrix = DMK::memory::read<GameStructures::Matrix34f>(
                    DMK::Address{entity_addr + Constants::OFFSET_ENTITY_WORLD_MATRIX_MEMBER});
                if (world_matrix)
                {
                    body_origin = Vector3{world_matrix->m[0][3], world_matrix->m[1][3], world_matrix->m[2][3]};
                    // Forward is column 1; yaw in the engine convention forward = (-sin yaw, cos yaw).
                    body_yaw = std::atan2(-world_matrix->m[0][1], world_matrix->m[1][1]);
                    body_valid = true;
                }
            }
        }
        // Held off the anchor while the body steps through a native turn-in-place animation, so the camera does not
        // shift with the turn. The look yaw comes from the look quat, or from the eye quat, whose yaw is the look yaw
        // in first person.
        Vector3 turn_hold{0.0f, 0.0f, 0.0f};
        if (body_valid)
        {
            const Vector3 look_fwd = (look_valid ? look_rotation : eye_rotation).rotate(Vector3{0.0f, 1.0f, 0.0f});
            const bool look_yaw_valid = look_fwd.x * look_fwd.x + look_fwd.y * look_fwd.y > 1e-6f;
            const float look_yaw = look_yaw_valid ? std::atan2(-look_fwd.x, look_fwd.y) : 0.0f;
            turn_hold = hold_turn_in_place_pivot(cam, body_origin, body_yaw, look_yaw, look_yaw_valid, delta_time);
        }
        const Vector3 anchor_origin = body_origin - turn_hold;
        // Publish the live REAL eye height (FP eye above the body root) for the overlay read-out and as the
        // dynamic-eye-sync source. eye_position carries head bob; body_origin is the bob-free feet origin.
        if (body_valid)
        {
            cam.real_eye_height.store(eye_position.z - body_origin.z, std::memory_order_relaxed);
        }
        // The eye anchor (EyeHeight 0, or no body) takes the turn hold too, so switching anchor mode with a hold in
        // place does not jump; the hold then eases out as usual.
        Vector3 anchor_base = eye_position - turn_hold;
        if (body_valid && eye_height > 0.0f)
        {
            float effective_eye_height = eye_height;
            bool sync_engaged = false; // true while actively re-anchoring (vs. just using the configured height)
            if (cfg.dynamic_eye_sync.load(std::memory_order_relaxed))
            {
                // Re-anchor the eye HEIGHT to the real FP eye when a low pose (kneel / pray, and other poses
                // EyeHeight does not model) drops it OUT OF RANGE of the configured height - where a fixed
                // height floats the camera too high. Within the threshold (head bob / a minor pose change) keep
                // the steady bob-free height; in the re-anchored low poses we accept the bob (they are mostly
                // stationary). Ease so the swap slides; eye_sync_valid resets on suppression so re-engaging snaps.
                constexpr float k_oor_threshold = 0.25f; // meters: a genuine pose drop, not head bob
                constexpr float k_sync_rate = 9.0f;      // ease rate, 1/sec (frame-rate independent below)
                const float real_eye_height = eye_position.z - body_origin.z;
                sync_engaged = std::fabs(real_eye_height - eye_height) > k_oor_threshold;
                const float target_eye_height = sync_engaged ? real_eye_height : eye_height;
                if (!cam.eye_sync_valid)
                {
                    cam.eye_sync_applied = target_eye_height;
                    cam.eye_sync_valid = true;
                }
                else
                {
                    const float k = 1.0f - std::exp(-k_sync_rate * delta_time);
                    cam.eye_sync_applied += (target_eye_height - cam.eye_sync_applied) * k;
                }
                effective_eye_height = cam.eye_sync_applied;
            }
            else
            {
                cam.eye_sync_valid = false; // feature off -> the next engage snaps to the current pose
            }
            // Publish for the overlay status line (actively re-anchoring vs. using the configured height).
            cam.eye_sync_engaged.store(sync_engaged, std::memory_order_relaxed);
            cam.eye_sync_effective.store(effective_eye_height, std::memory_order_relaxed);
            anchor_base = anchor_origin + world_up * effective_eye_height;
        }
        else
        {
            cam.eye_sync_engaged.store(false, std::memory_order_relaxed);
        }
        const Vector3 pivot = anchor_base + world_up * cfg.offset_up.load(std::memory_order_relaxed);

        // Free-look orbit angles (degrees), accumulated by the input hook while the key is
        // held. On release they ease back to center. Read here so the render reflects them.
        const bool orbit_held = cam.orbit_active.load(std::memory_order_relaxed);

        // Gamepad right-stick orbit: integrate the latched stick DEFLECTION by RATE into the SAME orbit
        // accumulator the mouse writes, so the stick orbits the camera (yaw) and raises/lowers it (pitch) like
        // the mouse. Done here (not in the input hook) because the stick reports a HELD position, so it needs
        // delta_time to be a frame-rate-independent turn rate and to keep moving while held steady. Yaw matches
        // the mouse (stick-right orbits right); the right-stick Y reads OPPOSITE the mouse look delta, so it is
        // negated below (stick-up raises the camera, like the mouse). GamepadOrbitSpeed X/Y (deg/sec at full stick,
        // one rate per axis so each can be inverted with a negative value) sets the rate - a SEPARATE knob from the
        // mouse's OrbitSensitivity X/Y, because a relative mouse (delta) and an absolute stick (rate) cannot share
        // one linear scale; the pitch is clamped to the same limits.
        // Gated on the cursor-shown freeze (a UI up holds
        // still, mirroring the mouse path); when not orbiting or frozen the latch is cleared so re-engaging with
        // the stick centred does not jump.
        if (orbit_held && !s_cursor_shown.load(std::memory_order_relaxed))
        {
            const float pad_yaw = cam.orbit_pad_yaw.load(std::memory_order_relaxed);
            const float pad_pitch = cam.orbit_pad_pitch.load(std::memory_order_relaxed);
            if (pad_yaw != 0.0f || pad_pitch != 0.0f)
            {
                const float step_x = cfg.gamepad_orbit_speed_x.load(std::memory_order_relaxed) * delta_time;
                const float step_y = cfg.gamepad_orbit_speed_y.load(std::memory_order_relaxed) * delta_time;
                cam.orbit_yaw.store(cam.orbit_yaw.load(std::memory_order_relaxed) - pad_yaw * step_x,
                                    std::memory_order_relaxed);
                const float pitch = cam.orbit_pitch.load(std::memory_order_relaxed) - pad_pitch * step_y;
                cam.orbit_pitch.store(std::clamp(pitch, cfg.orbit_pitch_min.load(std::memory_order_relaxed),
                                                 cfg.orbit_pitch_max.load(std::memory_order_relaxed)),
                                      std::memory_order_relaxed);
            }
        }
        else
        {
            cam.orbit_pad_yaw.store(0.0f, std::memory_order_relaxed);
            cam.orbit_pad_pitch.store(0.0f, std::memory_order_relaxed);
        }

        // Wrap the accumulated yaw into [-180, 180] for the orbit math. The orbit is periodic in yaw,
        // so this is invisible while orbiting, but on release it lets the camera ease back to centre
        // along the SHORTEST path (<= 180 deg) in one smooth pass instead of un-spinning every full
        // revolution the player made. The re-based value is only stored back on release (below), so the wrap
        // here stays render-thread-local while held. The raw accumulator itself is written by the mouse path
        // on the input thread and by the gamepad integration above on the render thread; only one input device
        // drives orbit at a time in practice, so the relaxed load here does not race a meaningful write (and a
        // dropped sub-degree delta in the unlikely simultaneous case is harmless, never torn).
        float orbit_yaw_deg = std::remainder(cam.orbit_yaw.load(std::memory_order_relaxed), 360.0f);
        float orbit_pitch_deg = cam.orbit_pitch.load(std::memory_order_relaxed);

        // While moving with a captured heading, the camera holds its WORLD yaw and the body turns UNDER it.
        // Derive the rig's orbit angle as (camera_world_yaw - current_body_forward_yaw), where camera_world_yaw =
        // the captured heading plus any orbit the player has added since capture. On the capture frame the body
        // has not turned yet, so this equals the pre-move orbit (no snap); as the eye+body rotate to the heading
        // the angle eases to the residual orbit, so the camera POSITION is identical across the turn (no pop).
        // forward is this frame's rig basis forward (the stable-aim or smoothed basis when active, else the raw
        // eye look); char_forward_yaw below derives from the SAME forward that positions the camera, so the two
        // cancel and the held world yaw is independent of which source forward tracks. cam.orbit_yaw stays the
        // raw input accumulator throughout; the rendered angle is baked back only on release/stop so free-look resumes
        // from exactly where the moving camera was. orbit_moving implies the key was held, so this also runs on
        // the release frame (orbit_moving is cleared at end of frame), giving the bake-on-release below.
        const bool move_orbit = cam.orbit_moving && cam.orbit_target_valid;
        // Settle-hold: keep the world-stable derivation running past the move-stop while the eye-look is still
        // slewing (the engine's intermittent stop/idle body-turn), so the rig does not re-couple to the look and
        // drift before it settles. Mutually exclusive with move_orbit (it begins only after orbit_moving clears).
        const bool settle_orbit = cam.orbit_settle_hold && cam.orbit_target_valid && !move_orbit;
        if (move_orbit || settle_orbit)
        {
            const float char_forward_yaw = std::atan2(-forward.x, forward.y);
            const float raw_user_since_deg =
                cam.orbit_yaw.load(std::memory_order_relaxed) - cam.orbit_yaw_at_capture_deg;
            // In continuous-align (GTA) mode the user's orbit-since-capture STEERS the run: it drives
            // body_target_yaw (the look + body heading) below, and the camera follows that heading (the
            // derived rig angle cancels to ~0, keeping the camera behind). Smooth that steering input when
            // OrbitSmoothing is on so the turn is fluid instead of tracking the raw per-frame mouse deltas;
            // the SAME smoothed value is reused for body_target_yaw below so the camera stays behind the body.
            // Hold mode keeps the raw value (its orbit-around rides the snapped rig offset, left instant);
            // only continuous-align steering is smoothed.
            const float orbit_smoothing = std::clamp(cfg.orbit_smoothing.load(std::memory_order_relaxed), 0.0f, 1.0f);
            // Smooth the steering only while ACTIVELY move-orbiting; during the settle hold the player has
            // stopped (no steering input), so use the raw orbit-since-capture - a low-pass would only lag the hold.
            const bool steer_smooth =
                move_orbit && cfg.orbit_continuous_align.load(std::memory_order_relaxed) && orbit_smoothing > 1e-4f;
            if (!steer_smooth || !cam.orbit_steer_valid)
            {
                cam.orbit_steer_smooth = raw_user_since_deg; // snap: smoothing off / hold mode, or first move frame
                cam.orbit_steer_valid = true;
            }
            else
            {
                const float speed =
                    k_orbit_smooth_max_speed - orbit_smoothing * (k_orbit_smooth_max_speed - k_orbit_smooth_min_speed);
                const float ease = 1.0f - std::exp(-speed * delta_time);
                cam.orbit_steer_smooth += std::remainder(raw_user_since_deg - cam.orbit_steer_smooth, 360.0f) * ease;
            }
            const float user_orbit_since_deg = steer_smooth ? cam.orbit_steer_smooth : raw_user_since_deg;
            orbit_yaw_deg = std::remainder(
                DMK::math::radians_to_degrees(cam.orbit_target_yaw - char_forward_yaw) + user_orbit_since_deg, 360.0f);

            // Settle-hold lifecycle: while holding, watch the eye-look slew and END the hold once the look has
            // been still for k_orbit_settle_still_frames frames AND past the minimum hold (so a brief still BEFORE
            // a late stop-turn cannot end it early), or at the safety cap. On end, bake the rendered (world-stable)
            // angle into the accumulator so free-look re-couples from exactly here - no jump. orbit_yaw_deg holds
            // the look-cancelling angle, so even an instant look jump bakes consistently. A look that never moves
            // settles at the minimum hold, so the hold is invisible for a straight run that stops square.
            if (settle_orbit)
            {
                const float slew_deg = std::fabs(std::remainder(
                    DMK::math::radians_to_degrees(char_forward_yaw - cam.orbit_settle_look_prev), 360.0f));
                cam.orbit_settle_look_prev = char_forward_yaw;
                cam.orbit_settle_elapsed += delta_time;
                const float slew_rate = (delta_time > 1e-5f) ? (slew_deg / delta_time) : 0.0f;
                cam.orbit_settle_still = (slew_rate < k_orbit_settle_still_rate) ? (cam.orbit_settle_still + 1) : 0;
                const bool settled = cam.orbit_settle_still >= k_orbit_settle_still_frames &&
                                     cam.orbit_settle_elapsed >= k_orbit_settle_min_hold;
                if (settled || cam.orbit_settle_elapsed >= k_orbit_settle_max_hold)
                {
                    cam.orbit_yaw.store(orbit_yaw_deg, std::memory_order_relaxed); // bake the settled rig angle
                    cam.orbit_settle_hold = false;
                }
            }
        }
        else
        {
            cam.orbit_steer_valid = false; // not move-orbiting / settling: the next engage snaps the steer low-pass
        }

        if (!orbit_held)
        {
            // Orbit toggle released. When a move-orbit was active, orbit_yaw_deg already holds the rendered
            // (world-stable) angle derived above, not the raw input accumulator, so the ease-back below starts
            // from where the camera actually is rather than jumping by the orbit held at capture. The single
            // store at the end of this block persists the re-based (and, with a return speed, eased) angle.
            const float return_speed = cfg.orbit_return_speed.load(std::memory_order_relaxed);
            if (return_speed > 0.0f)
            {
                // Ease back to the centre: directly behind and level (hardcoded 0, 0).
                const float init_yaw = 0.0f;
                const float init_pitch = 0.0f;
                const float ease = 1.0f - std::exp(-return_speed * delta_time);
                orbit_yaw_deg -= std::remainder(orbit_yaw_deg - init_yaw, 360.0f) * ease; // shortest path to centre
                orbit_pitch_deg -= (orbit_pitch_deg - init_pitch) * ease;
            }
            // Store the re-based (and, with a return speed, eased) angles so the next frame resumes from the
            // short-path value; also runs with return_speed == 0 so the held-spin accumulator is bounded the
            // moment the key is released.
            cam.orbit_yaw.store(orbit_yaw_deg, std::memory_order_relaxed);
            cam.orbit_pitch.store(orbit_pitch_deg, std::memory_order_relaxed);
        }

        // Temporal low-pass on the orbit angle. orbit_yaw_deg / orbit_pitch_deg above are the raw target
        // (the accumulated mouse input, or the eased return / world-stable move derivation); the rig is
        // built from a smoothed copy that eases toward it each frame so free-look is not as jittery as the
        // unfiltered per-frame deltas (the engine's own look smoothing runs past the dispatch we block).
        // orbit_smoothing 0 = off (snap, raw). Snap on the first engaged frame (orbit_render_valid false) so
        // the camera does not slide in from centre. SNAP ALSO while move-orbiting (a movement key is driving
        // the camera-relative turn): there orbit_yaw_deg is the WORLD-STABLE derivation that cancels the body
        // turn to keep the camera planted, so it must track the body 1:1 - smoothing it would lag the
        // cancellation and swing the camera on the move-start, when it should be instant. The target writes
        // above always use the unsmoothed value, so the accumulator and the return/move logic are unaffected;
        // only the idle (standing free-look) rendered angle is low-passed.
        const float orbit_smoothing = std::clamp(cfg.orbit_smoothing.load(std::memory_order_relaxed), 0.0f, 1.0f);
        // SNAP while move-orbiting OR settling: in both, orbit_yaw_deg is the WORLD-STABLE derivation that cancels
        // the body/look heading to keep the camera planted, so it must track the look 1:1 - low-passing it would
        // lag the cancellation and swing the camera (the very drift the settle hold exists to prevent).
        if (orbit_smoothing <= 1e-4f || !cam.orbit_render_valid || move_orbit || settle_orbit)
        {
            cam.orbit_yaw_render = orbit_yaw_deg;
            cam.orbit_pitch_render = orbit_pitch_deg;
            cam.orbit_render_valid = true;
        }
        else
        {
            const float smooth_speed =
                k_orbit_smooth_max_speed - orbit_smoothing * (k_orbit_smooth_max_speed - k_orbit_smooth_min_speed);
            const float smooth_ease = 1.0f - std::exp(-smooth_speed * delta_time);
            // Shortest-path ease on yaw so a wrap (e.g. -179 -> +179) eases the short way, not all the way round.
            cam.orbit_yaw_render += std::remainder(orbit_yaw_deg - cam.orbit_yaw_render, 360.0f) * smooth_ease;
            cam.orbit_pitch_render += (orbit_pitch_deg - cam.orbit_pitch_render) * smooth_ease;
        }
        const float render_yaw_deg = cam.orbit_yaw_render;
        const float render_pitch_deg = cam.orbit_pitch_render;

        // "Orbiting" while EITHER the raw target or the still-easing rendered angle is off-centre, so the
        // orbit block keeps running until the smoothed angle has fully settled back (otherwise a release
        // would cut the rig straight to centre before the low-pass finishes).
        const bool orbiting = orbit_yaw_deg < -0.05f || orbit_yaw_deg > 0.05f || orbit_pitch_deg < -0.05f ||
                              orbit_pitch_deg > 0.05f || render_yaw_deg < -0.05f || render_yaw_deg > 0.05f ||
                              render_pitch_deg < -0.05f || render_pitch_deg > 0.05f;

        // Ease the orbit "level" blend toward 1 ONLY while the orbit key is held, and back to 0 on
        // release. While held the orbit is built from a LEVEL reference (so a steep look does not tip it
        // near the overhead pole); easing in/out keeps engaging and releasing smooth. Keying this on
        // orbit_held alone (not on "orbiting") is deliberate: with OrbitReturnSpeed 0 the angles "stay"
        // and "orbiting" latches true forever, so keying off it would pin the camera to the level
        // reference and lock out look pitch (only the head would move, the view would not). De-leveling
        // on release instead lets any retained orbit angle ride as a rigid offset on top of the real
        // look (the level_blend 0 path follows pitch), so vertical control is preserved in every preset.
        {
            constexpr float k_orbit_level_speed = 8.0f;
            const float level_target = orbit_held ? 1.0f : 0.0f;
            const float level_ease = 1.0f - std::exp(-k_orbit_level_speed * delta_time);
            cam.orbit_level_blend += (level_target - cam.orbit_level_blend) * level_ease;
        }

        // The real aim is driven AFTER the orbit look is finalized (below), so the heading can be aligned
        // to the camera's forward direction on the idle -> moving edge.

        // Centered base (no shoulder), straight back from the pivot. The shoulder is re-applied
        // below. The orbit rotation is applied on top, not folded into this base, so the orbit
        // stays instantly responsive and never accumulates into the follow position. The follow
        // is instant: the anchor is the de-bobbed body origin, so there is no shake to smooth out.
        const Vector3 centered_position = pivot - forward * distance;

        // Final camera position with the fixed shoulder applied (the normal, non-orbit pose).
        Vector3 camera_position = centered_position + lateral_offset;

        // Aim focus point. The off-axis (shoulder/height) camera looks at a point on the aim line so the
        // screen-centre crosshair lands on what the player points at: focus_point = anchor + forward *
        // focus_distance, and the camera toes in toward it by ~ shoulder / focus_distance.
        //
        // focus_distance auto-tracks the live follow distance, deliberately NOT the per-frame scene depth.
        // Driving the toe-in from a raycast hit distance is what made the camera rotate toward whatever sat
        // under the crosshair - the "magnet" on hover, the shake on a swing, the orbit jitter. The toe-in
        // is ~ shoulder / distance, so any change in the hovered depth rotates the whole view, and no filter
        // can remove a rotation the mechanism is built to produce. Tying the focus to the follow distance
        // (which changes only, and slowly, when the player zooms) keeps it decoupled from the scene, so it
        // is stable by construction: the convergence scales with the zoom (closer follow -> nearer focus)
        // and the player never has to set a second distance by hand. The focus is built from anchor_base
        // (the de-bobbed body anchor), not the bobbing first-person eye, so head-bob and weapon-sway never
        // reach it. The convergence moves only the RENDERED look; the game's own interaction ray is never
        // touched.
        // AimFocusDistance pins the convergence depth (0 = auto: track the live follow distance, as the
        // comment above describes). Then bound the toe-in: a small follow distance with a shoulder offset
        // would otherwise converge so steeply that the crosshair misses everything past the near focus
        // (the ~45 deg case at FollowDistance 0.5, OffsetRight 1.0). Raise focus_distance so the toe-in
        // atan(|offset_right| / (focus_distance + distance)) stays within k_tan_max_convergence.
        float focus_distance = cfg.aim_focus_distance.load(std::memory_order_relaxed);
        if (focus_distance <= 0.0f)
        {
            focus_distance = distance;
        }
        const float shoulder_abs = std::abs(cfg.offset_right.load(std::memory_order_relaxed));
        if (shoulder_abs > 1e-4f)
        {
            const float min_reach = shoulder_abs / k_tan_max_convergence; // lower bound on focus_distance + distance
            focus_distance = std::max(focus_distance, min_reach - distance);
        }
        const bool have_focus = focus_distance > 0.0f;
        const Vector3 focus_point = anchor_base + forward * focus_distance;

        // Converge the look on the focus point so the off-axis (shoulder/height) camera keeps the
        // screen-centre crosshair on the aim target: the camera looks straight at the focus point, so
        // the shoulder/height offset no longer makes the crosshair miss. The orbit below carries this
        // converged look RIGIDLY (it rotates with the rig), so the crosshair holds its screen position
        // while free-looking instead of re-aiming at the far focus point each frame.
        Vector3 look_forward = forward;
        bool rebuild_basis = false;
        if (have_focus)
        {
            const Vector3 to_focus = focus_point - camera_position;
            if (to_focus.magnitude() > 1e-4f)
            {
                look_forward = to_focus.normalized();
                rebuild_basis = true;
            }
        }

        // Static follow angle: orbit the RESTING camera around the pivot by FollowYaw / FollowPitch
        // (degrees; 0,0 = directly behind and level). Positive yaw swings the camera to one side, positive
        // pitch raises it. The offset AND the converged look rotate TOGETHER (same convention as the
        // free-look orbit below), so the over-the-shoulder framing and crosshair hold while the camera
        // circles you. The free-look orbit then rotates further on top of this resting angle.
        {
            const float follow_yaw = cfg.follow_yaw.load(std::memory_order_relaxed);
            const float follow_pitch = cfg.follow_pitch.load(std::memory_order_relaxed);
            if (follow_yaw < -0.05f || follow_yaw > 0.05f || follow_pitch < -0.05f || follow_pitch > 0.05f)
            {
                Vector3 off = camera_position - pivot;
                const float yaw = DMK::math::degrees_to_radians(follow_yaw);
                const float cy = std::cos(yaw);
                const float sy = std::sin(yaw);
                auto yaw_about_z = [cy, sy](const Vector3 &v)
                { return Vector3{v.x * cy - v.y * sy, v.x * sy + v.y * cy, v.z}; };
                off = yaw_about_z(off);
                look_forward = yaw_about_z(look_forward);

                const float pitch = DMK::math::degrees_to_radians(follow_pitch);
                if (pitch < -1e-5f || pitch > 1e-5f)
                {
                    const float azimuth = std::atan2(off.y, off.x);
                    const Vector3 axis{std::sin(azimuth), -std::cos(azimuth), 0.0f};
                    const float cp = std::cos(pitch);
                    const float sp = std::sin(pitch);
                    auto rotate_about_axis = [&axis, cp, sp](const Vector3 &v)
                    {
                        const Vector3 cross = axis.cross(v);
                        const float dot = axis.x * v.x + axis.y * v.y + axis.z * v.z;
                        return v * cp + cross * sp + axis * (dot * (1.0f - cp));
                    };
                    off = rotate_about_axis(off);
                    look_forward = rotate_about_axis(look_forward);
                }

                camera_position = pivot + off;
                if (look_forward.magnitude_squared() > 1e-6f)
                {
                    look_forward = look_forward.normalized();
                }
                rebuild_basis = true;
            }
        }

        // Free-look orbit: rigidly rotate the WHOLE non-orbit rig (the camera's offset from the pivot
        // AND the converged look direction) around the pivot - yaw about world up, then pitch about the
        // heading's horizontal right axis. Because the offset (shoulder + height + distance) and the
        // aim-convergence toe-in rotate TOGETHER, the over-the-shoulder framing and the crosshair keep
        // their screen positions while the camera circles the player, and there is no far focus anchor
        // that blows up near the front. Yaw is unbounded so full spins work; the target elevation is
        // clamped away from the pole and the same clamped delta rotates the look so the two agree. At
        // zero angle the rotation is identity (continuous engage); looking at the ground still circles
        // the player (the offset's elevation is preserved) and mouse up/down raises/lowers the camera.
        if (orbiting || cam.orbit_level_blend > 0.001f)
        {
            const float level_blend = cam.orbit_level_blend;

            // ACTUAL base: the live follow offset and converged look - encodes the player's look pitch.
            const Vector3 actual_offset = camera_position - pivot;
            const Vector3 actual_look = look_forward;

            // LEVEL base: as if the player looked straight ahead. A steep up/down look otherwise puts the
            // orbit near the overhead pole where the rotation gets messy, so while orbiting the rig is
            // blended to this level reference. The height stays in the pivot, so the level camera sits at
            // eye level straight behind the heading with the shoulder, and the look converges on the
            // level aim line so the crosshair stays compensated.
            Vector3 level_fwd{forward.x, forward.y, 0.0f};
            if (level_fwd.magnitude_squared() > 1e-6f)
            {
                level_fwd = level_fwd.normalized();
            }
            else
            {
                level_fwd = world_up.cross(right).normalized(); // straight down/up: recover heading from right
            }
            const Vector3 level_right = level_fwd.cross(world_up).normalized();
            const Vector3 level_offset =
                level_fwd * (-distance) + level_right * cfg.offset_right.load(std::memory_order_relaxed);
            Vector3 level_look = have_focus ? (pivot + level_fwd * focus_distance) - (pivot + level_offset)
                                            : level_offset * -1.0f; // no focus: look at the pivot
            level_look = (level_look.magnitude_squared() > 1e-6f) ? level_look.normalized() : level_fwd;

            // Blend actual -> level by the eased level_blend (0 = follow pose, 1 = leveled). At 0 this is
            // exactly the non-orbit pose, so engaging/leaving free-look is continuous; the blend carries
            // the transition smoothly instead of snapping between the steep and level poses.
            const Vector3 offset0 = actual_offset + (level_offset - actual_offset) * level_blend;
            Vector3 base_look = actual_look + (level_look - actual_look) * level_blend;
            base_look = (base_look.magnitude_squared() > 1e-6f) ? base_look.normalized() : actual_look;

            float radius = offset0.magnitude();
            if (radius < 1e-3f)
            {
                radius = distance; // degenerate (camera at the pivot): nothing to rotate about
            }
            const float base_elevation = std::asin(std::clamp(offset0.z / radius, -1.0f, 1.0f));
            const float elevation =
                std::clamp(base_elevation + DMK::math::degrees_to_radians(render_pitch_deg), -1.45f, 1.45f);
            const float yaw_delta = DMK::math::degrees_to_radians(render_yaw_deg);
            const float pitch_delta = elevation - base_elevation;

            // Yaw about world up (Z): applied to both the offset and the look so they swing together.
            const float cy = std::cos(yaw_delta);
            const float sy = std::sin(yaw_delta);
            auto yaw_about_z = [cy, sy](const Vector3 &v)
            { return Vector3{v.x * cy - v.y * sy, v.x * sy + v.y * cy, v.z}; };
            Vector3 new_offset = yaw_about_z(offset0);
            Vector3 new_look = yaw_about_z(base_look);

            // Pitch about the horizontal right axis of the yawed heading (Rodrigues). The axis
            // (sin az, -cos az, 0) is the one about which a positive pitch_delta raises the camera.
            if (pitch_delta < -1e-5f || pitch_delta > 1e-5f)
            {
                const float azimuth = std::atan2(new_offset.y, new_offset.x);
                const Vector3 pitch_axis{std::sin(azimuth), -std::cos(azimuth), 0.0f};
                const float cp = std::cos(pitch_delta);
                const float sp = std::sin(pitch_delta);
                auto rotate_about_axis = [&pitch_axis, cp, sp](const Vector3 &v)
                {
                    const Vector3 cross = pitch_axis.cross(v);
                    const float dot = pitch_axis.x * v.x + pitch_axis.y * v.y + pitch_axis.z * v.z;
                    return v * cp + cross * sp + pitch_axis * (dot * (1.0f - cp));
                };
                new_offset = rotate_about_axis(new_offset);
                new_look = rotate_about_axis(new_look);
            }

            camera_position = pivot + new_offset;
            if (new_look.magnitude_squared() > 1e-6f)
            {
                look_forward = new_look.normalized();
            }
            rebuild_basis = true;
        }

        // Camera-relative movement (toggle orbit): on the idle -> moving edge CAPTURE the camera heading, then
        // HOLD it while moving. The body turn (apply_orbit_body_turn) pins the body to that heading, which is
        // what makes locomotion camera-relative in EVERY direction (KCD moves relative to the body rotation):
        // W runs away from the camera, A/D strafe to the sides, S backs toward it. It is re-applied every frame
        // because the engine consumes a single write, like the pitch leveling. Released when movement stops.
        bool do_align = false;
        // Camera-relative movement, keyed on the device-agnostic action-input intent
        // (player_onaction_move_magnitude, from the action dispatcher). The input is nonzero the instant a movement
        // key is pressed - BEFORE the body accelerates - so the heading captures immediately and the
        // character turns to the camera direction without first moving the old way; and it stays nonzero while
        // a key is held against a wall, so the heading is not falsely released on a collision arrest. The
        // body-position speed is deliberately NOT used (it lags the intent and reads zero when arrested), so
        // the feature requires the action hook - if it did not resolve, camera-relative movement stays off
        // (free-look still works).
        if (orbit_held && body_valid && player_onaction_available())
        {
            bool moving = cam.orbit_moving;
            const float move_magnitude = player_onaction_move_magnitude();
            // Re-arm guard: a genuine release (magnitude below the stop threshold) must be observed since orbit
            // engaged before a move-start is honoured. A stranded latch - a held-move release swallowed on a
            // combat action-map swap (see player_onaction_reset) - reads > 0 with the keys up; without this guard
            // it would re-trip orbit_moving the instant orbit restores and drive the body-turn with no input (the
            // post-combat self-rotation). Arming only on a sub-stop reading means a fresh, observed press engages it.
            static bool s_stale_suppress_logged = false;
            if (move_magnitude < k_orbit_move_input_stop)
            {
                cam.orbit_move_armed = true;
                s_stale_suppress_logged = false;
            }
            if (!moving && move_magnitude > k_orbit_move_input_start)
            {
                if (cam.orbit_move_armed)
                {
                    moving = true;
                    do_align = true;               // idle -> moving edge: capture the camera heading
                    cam.orbit_settle_hold = false; // a fresh move re-captures the heading; drop any pending settle
                    // Diagnostic: what tripped the body-turn. move_magnitude near 1.0 with a movement key/stick =
                    // genuine locomotion; a smaller or unexpected value while the player is only free-looking
                    // points at game-driven movement (finishing-move / combat footwork) being mistaken for intent.
                    // state is the debounced GameState mask (see game_state.hpp) so we can tell whether a combat /
                    // aiming / cinematic state was active when the body-turn engaged.
                    DMK::log().trace(
                        "Orbit: move-orbit START (body-turn engaging) -- move_magnitude={:.2f}, continuous_align={}, "
                        "state_mask=0x{:X}",
                        move_magnitude, cfg.orbit_continuous_align.load(std::memory_order_relaxed),
                        game_state_mask().load(std::memory_order_relaxed));
                }
                else if (!s_stale_suppress_logged)
                {
                    // Unarmed (no release seen since orbit engaged) yet reading as movement: a stranded latch.
                    // Suppress the body-turn re-trip and log it once - the diagnostic for the post-combat case.
                    DMK::log().trace(
                        "Orbit: suppressed a stale move re-trip (magnitude {:.2f}, no release observed since orbit "
                        "engaged; likely a movement latch stranded by a combat action-map swap)",
                        move_magnitude);
                    s_stale_suppress_logged = true;
                }
            }
            else if (moving && move_magnitude < k_orbit_move_input_stop)
            {
                // Release the latch the instant the movement keys are let go (no debounce tail), so stopping
                // and then rotating is immediately pure free-look and the character does not keep turning to
                // the camera. No bridge is needed the way body-speed required: the action input stays nonzero
                // while any key is held (diagonals, overlapping key-switches), so a drop to zero is a genuine
                // stop; a full release-then-repress simply re-captures the heading on the new press, which is
                // the correct behaviour.
                moving = false;
                if (cam.orbit_target_valid)
                {
                    // Do NOT bake the orbit angle here. The engine keeps rotating the standing body (and the
                    // eye-look that tracks it 1:1 on KCD1) for a short, intermittent window after a camera-relative
                    // run stops; re-coupling the rig to that still-slewing look is what drifts the camera. Begin a
                    // settle hold instead: the world-stable derivation above stays alive (camera decoupled from the
                    // look) until the look settles, then it bakes and re-couples with no jump.
                    // Seed the slew tracker with the current eye-look.
                    cam.orbit_settle_hold = true;
                    cam.orbit_settle_look_prev = std::atan2(-forward.x, forward.y);
                    cam.orbit_settle_elapsed = 0.0f;
                    cam.orbit_settle_still = 0;
                }
                else
                {
                    // No captured heading: nothing was decoupled, so bake the current angle (legacy behaviour).
                    cam.orbit_yaw.store(orbit_yaw_deg, std::memory_order_relaxed);
                }
                DMK::log().trace("Orbit: move-orbit STOP (settle hold begun) -- move_magnitude={:.2f}", move_magnitude);
            }
            cam.orbit_moving = moving;
        }
        else
        {
            cam.orbit_moving = false;
            cam.orbit_move_armed = false;  // require a fresh observed release after re-engaging orbit
            cam.orbit_settle_hold = false; // orbit released / body invalid: drop any pending settle hold
        }

        // Capture the heading on move-start. Use the camera's POSITIONAL world yaw - the eye-look yaw plus
        // the orbit applied this frame - NOT atan2(look_forward). look_forward is the CONVERGED look: with
        // aim-convergence on, the over-the-shoulder camera toes its look INWARD toward the aim point by a
        // shoulder-dependent angle. Capturing that toed-in yaw would rotate the rig by the toe-in on the
        // move transition, shifting the camera sideways toward the shoulder every time you press W. The
        // positional yaw is exactly what the world-stable orbit derivation above renders, so the camera
        // stays put as the body turns. It is also the more intuitive move direction (straight away from the
        // camera rather than toed-in toward the crosshair).
        if (do_align)
        {
            const float eye_forward_yaw = std::atan2(-forward.x, forward.y);
            cam.orbit_target_yaw = eye_forward_yaw + DMK::math::degrees_to_radians(orbit_yaw_deg);
            cam.orbit_target_valid = true;
            // Snapshot the orbit input so further orbiting while moving is measured from here. We do NOT
            // reset the orbit to 0: the world-stable derivation above holds the camera in place while the
            // body turns to this heading, so there is no snap-behind pop.
            cam.orbit_yaw_at_capture_deg = cam.orbit_yaw.load(std::memory_order_relaxed);
        }
        if (!cam.orbit_moving && !cam.orbit_settle_hold)
        {
            cam.orbit_target_valid = false; // keep the captured heading while the settle hold still needs it
        }

        const float pitch_ease = (orbit_held && cfg.orbit_level_aim.load(std::memory_order_relaxed))
                                     ? (1.0f - std::exp(-k_orbit_aim_level_speed * delta_time))
                                     : 0.0f;
        const bool hold_yaw = orbit_held && cam.orbit_moving && cam.orbit_target_valid;
        // Heading fed to the body + movement while moving. CONTINUOUS-ALIGN (GTA style): follow the CURRENT
        // camera world yaw every frame (captured heading + the orbit added since), so orbiting STEERS the run
        // and the rig stays behind the character. Otherwise HOLD the heading captured on move-start (orbit
        // looks around freely while the character keeps its line). The world-stable camera derivation above is
        // the same either way - only this target differs - so in continuous mode the derived orbit angle
        // cancels to ~0 (camera behind the character) while in hold mode it carries the orbit-around offset.
        float body_target_yaw = cam.orbit_target_yaw;
        if (hold_yaw && cfg.orbit_continuous_align.load(std::memory_order_relaxed))
        {
            // Reuse the smoothed steer angle computed in the move-orbit derivation above (when OrbitSmoothing
            // is on) so the body/look heading and the rig agree - the camera follows the smoothed steering
            // and stays behind. With smoothing off this is the raw orbit-since-capture. The smoothed value is
            // only current once the move-orbit block above has run for it (cam.orbit_steer_valid); on the
            // idle->moving capture frame that block did NOT run (move_orbit read the pre-update orbit_moving,
            // which was still false), so fall back to the raw orbit-since-capture - ~0 on the capture frame
            // because orbit_yaw_at_capture_deg was just snapshotted - instead of a stale smoothed value from a
            // prior move. orbit_smoothing was read for the orbit-angle low-pass above and is constant across
            // the frame, so it is reused here.
            const float user_orbit_since_deg =
                (orbit_smoothing > 1e-4f && cam.orbit_steer_valid)
                    ? cam.orbit_steer_smooth
                    : (cam.orbit_yaw.load(std::memory_order_relaxed) - cam.orbit_yaw_at_capture_deg);
            body_target_yaw = cam.orbit_target_yaw + DMK::math::degrees_to_radians(user_orbit_since_deg);
        }
        if (pitch_ease > 0.0f)
        {
            apply_orbit_aim_control(pitch_ease);
        }
        // Pin the BODY to the camera heading while moving so the character runs camera-relative in EVERY
        // direction. KCD moves the player relative to the ENTITY (body) rotation, NOT the look, so this body
        // override is what redirects locomotion: with the body faced at the camera heading, W runs away from the
        // camera, A/D strafe to the sides and S backs toward it. The body must hold the CAMERA heading, not the
        // input direction: facing it at the movement direction would rotate the move frame and re-apply the input
        // on top of it (world_move = body + input), sending every key the wrong way (A/D -> backward, S ->
        // forward). Held every frame while moving (the override is consume-once); released when movement stops.
        static bool s_body_turn_engaged = false;
        const bool body_turn_active = hold_yaw && cfg.orbit_body_turn.load(std::memory_order_relaxed);
        if (body_turn_active != s_body_turn_engaged)
        {
            s_body_turn_engaged = body_turn_active;
            if (body_turn_active)
            {
                DMK::log().trace("Camera: orbit body-turn ENGAGED (moving; heading locked to camera)");
            }
            else
            {
                DMK::log().trace("Camera: orbit body-turn released");
            }
        }
        bool orbit_force_forward = false;
        static bool s_kbd_angle_valid = false; // keyboard facing-ease state (persists across frames)
        static float s_kbd_angle_eased = 0.0f; // eased keyboard move-input angle (camera-relative)
        float kbd_move_x = 0.0f;               // body-relative move input to write this frame (x = strafe)
        float kbd_move_y = 0.0f;               // body-relative move input to write this frame (y = forward)
        bool kbd_move_write = false;           // whether to override the keyboard move field this frame
        if (body_turn_active)
        {
            float body_yaw_final = body_target_yaw;
            float kbd_redirect_angle = 0.0f;      // keyboard move-input angle to ease toward (see smoothing below)
            bool kbd_redirect_active = false;     // keyboard redirect engaged this frame (digital -> needs easing)
            bool gamepad_redirect_active = false; // gamepad redirect engaged this frame (instant facing, no ease)
            // "Follow the stick" while SPRINTING. KCD1 sprint runs forward-only in the BODY facing, so with the
            // body pinned to the bare camera heading a sprint always runs straight away from the camera and the
            // stick's lateral component is dropped (push forward+right + sprint => runs forward; strafe + sprint
            // => snaps to forward). While sprint is held, rotate the body target by the move-input angle so the
            // forced-forward sprint runs where the stick actually points (camera-relative). Gated on sprint ONLY:
            // for normal movement the engine applies the stick input ON TOP of the body rotation
            // (world_move = body + input), so adding the input angle there would double-apply and send keys the
            // wrong way - sprint is the exception precisely because it discards the lateral input.
            // atan2(lateral, forward) is the input's angle from forward toward +right; increasing the engine yaw
            // turns the facing toward -X (left), so the right-handed input angle is SUBTRACTED.
            const bool sprint_held = player_onaction_available() && player_onaction_sprint_active();
            {
                float move_fwd = 0.0f;
                float move_lat = 0.0f;
                // GAMEPAD analog input ONLY: this redirect is a gamepad-sprint workaround (gamepad sprint forces
                // forward-only). Keyboard sprint preserves the input direction, so the gamepad vector reads zero
                // for keyboard movement and keyboard/mouse orbit stays on the base body-turn path - applying the
                // redirect there would double-apply the input and run the character backwards.
                // Redirect whenever the move-input is NOT clearly backward (|angle| <= the back-pedal angle). A
                // clearly-backward push leaves body_yaw_final at the camera heading so the character back-pedals
                // toward the camera (facing away) rather than spinning 180 deg - KCD1 cannot sprint backwards, so
                // a back input is a plain back-pedal the raw locomotion already carries the right way. Gating on
                // the ANGLE (not the forward sign) keeps a wide margin from pure-sideways, so stick noise never
                // flips a strafe into back-pedal (which read as the body auto-snapping to face forward).
                if (sprint_held && player_onaction_gamepad_move_vector(move_fwd, move_lat))
                {
                    const float input_angle_raw = std::atan2(move_lat, move_fwd);
                    constexpr float k_half_pi = std::numbers::pi_v<float> / 2.0f;
                    // Full-turn mode (INI [Orbit] OrbitSprintFullTurn): face the FULL stick direction for ALL
                    // inputs - a backward push spins the body around to face the camera and runs toward it (no
                    // back-pedal, no +-90 clamp). Default mode: only forward-ish inputs redirect (|angle| within the
                    // back-pedal angle) and the facing is clamped to +-90, so a clearly-backward push back-pedals
                    // (faces away) and a sideways push never leans past pure-sideways.
                    const bool full_turn = cfg.orbit_sprint_full_turn.load(std::memory_order_relaxed);
                    if (full_turn || std::fabs(input_angle_raw) <= k_orbit_sprint_backpedal_angle)
                    {
                        float input_angle = input_angle_raw;
                        if (!full_turn)
                        {
                            input_angle = input_angle_raw > k_half_pi
                                              ? k_half_pi
                                              : (input_angle_raw < -k_half_pi ? -k_half_pi : input_angle_raw);
                        }
                        body_yaw_final = body_target_yaw - input_angle;
                        gamepad_redirect_active = true;
                        if (full_turn)
                        {
                            // Backward hemisphere (|angle| > 90 deg): the body now faces the camera, but KCD1 will
                            // NOT force a backward gamepad stick forward, so the raw back-input would sprint AWAY
                            // from the camera (the bug). Ask the dispatcher detour to collapse the gamepad move
                            // axes to pure-forward (forward axis full, lateral zero) so the forced-forward sprint
                            // runs along the faced (stick) direction - toward the camera for a pure-back push.
                            // Forward/side inputs already force-forward natively, so only the backward hemisphere
                            // needs it. The dispatcher keeps the REAL signed stick, so input_angle_raw above (and
                            // thus this facing) is unaffected - no feedback.
                            orbit_force_forward = std::fabs(input_angle_raw) > k_half_pi;
                        }
                        static int s_sprint_trace = 0;
                        if ((s_sprint_trace++ % 15) == 0)
                        {
                            DMK::log().trace(
                                "Orbit: sprint follow-stick -- fwd={:.2f} lat={:.2f} angle={:.1f}deg full_turn={} "
                                "force_fwd={}",
                                move_fwd, move_lat, input_angle * 57.2957795f, full_turn, orbit_force_forward);
                        }
                    }
                    // else (default mode, clearly backward): leave body_yaw_final = body_target_yaw (back-pedal).
                }
                else if (player_onaction_keyboard_move_vector(move_fwd, move_lat))
                {
                    // KEYBOARD digital move: the engine NEVER force-forwards a held key and DROPS sprint on
                    // non-forward input, so EVERY redirected direction needs the move input forced to pure-forward
                    // (not just backward like the gamepad). Record the move-direction angle with the SAME
                    // full-turn/clamp rule as the gamepad; the eased block below faces the body at it and writes
                    // C_PlayerInput's move field - a field write, so it overrides the held keys and does NOT flip
                    // the HUD glyphs to gamepad. (No analog axes are touched, so the device stays K&M.)
                    const float input_angle_raw = std::atan2(move_lat, move_fwd);
                    constexpr float k_half_pi = std::numbers::pi_v<float> / 2.0f;
                    const bool full_turn = cfg.orbit_sprint_full_turn.load(std::memory_order_relaxed);
                    if (sprint_held && (full_turn || std::fabs(input_angle_raw) <= k_orbit_sprint_backpedal_angle))
                    {
                        float input_angle = input_angle_raw;
                        if (!full_turn)
                        {
                            input_angle = input_angle_raw > k_half_pi
                                              ? k_half_pi
                                              : (input_angle_raw < -k_half_pi ? -k_half_pi : input_angle_raw);
                        }
                        // Defer the facing + move-field write to the eased block below (digital angle jumps need
                        // smoothing); just record the raw target here.
                        kbd_redirect_angle = input_angle;
                        kbd_redirect_active = true;
                        static int s_kbd_trace = 0;
                        if ((s_kbd_trace++ % 15) == 0)
                        {
                            DMK::log().trace(
                                "Orbit: keyboard turn-and-run -- fwd={:.2f} lat={:.2f} angle={:.1f}deg full_turn={}",
                                move_fwd, move_lat, input_angle * 57.2957795f, full_turn);
                        }
                    }
                    // else (default mode, clearly backward): no redirect - the engine carries a plain keyboard
                    // back-pedal toward the camera (facing away), matching the gamepad default backward.
                }
            }
            // Smooth the KEYBOARD turn-and-run facing AND its disengage. Digital keys jump the move angle in
            // 45/90 deg steps, so the facing is eased (the eased ANGLE only - NOT body_target_yaw - so
            // continuous-align stays instant and there is no feedback, unlike the earlier whole-body rate-limit).
            // ENGAGE / direction change: ease toward the move dir and drive pure-forward, so the movement curves
            // smoothly with the body. DISENGAGE (sprint/keys released while still moving): ease the facing back to
            // the camera heading while ROTATING the real keys by the eased facing, so the world movement stays put
            // (no wiggle) and only the body rotates. Gamepad uses its instant facing above and is excluded.
            constexpr float k_pi = std::numbers::pi_v<float>;
            const float kbd_ease = 1.0f - std::exp(-k_orbit_turn_run_ease * delta_time);
            if (gamepad_redirect_active)
            {
                s_kbd_angle_valid = false; // gamepad drives the facing instantly; drop any keyboard ease state
                s_kbd_angle_eased = 0.0f;
            }
            else if (kbd_redirect_active)
            {
                if (!s_kbd_angle_valid)
                {
                    s_kbd_angle_eased = 0.0f; // start from forward (pre-engage facing) so the engage eases too
                    s_kbd_angle_valid = true;
                }
                float delta = kbd_redirect_angle - s_kbd_angle_eased;
                while (delta > k_pi)
                    delta -= 2.0f * k_pi;
                while (delta < -k_pi)
                    delta += 2.0f * k_pi;
                s_kbd_angle_eased += kbd_ease * delta;
                while (s_kbd_angle_eased > k_pi)
                    s_kbd_angle_eased -= 2.0f * k_pi;
                while (s_kbd_angle_eased < -k_pi)
                    s_kbd_angle_eased += 2.0f * k_pi;
                body_yaw_final = body_target_yaw - s_kbd_angle_eased;
                kbd_move_x = 0.0f; // pure forward in the body frame -> the movement curves with the eased facing
                kbd_move_y = 1.0f;
                kbd_move_write = true;
            }
            else
            {
                // Disengage: snap the facing back to the camera heading (body_yaw_final already = body_target_yaw)
                // and let apply_keyboard_move_override restore the real keys. Easing the disengage was tried, but
                // rotating the body back - especially the 180 deg full-turn-backward case - dragged the orbit
                // camera, and a release cutting it off mid-turn left the camera shifted. So the disengage is an
                // instant snap (stable, no camera shift); only the ENGAGE / direction-change is eased.
                s_kbd_angle_valid = false;
                s_kbd_angle_eased = 0.0f;
            }
            apply_orbit_body_turn(body_yaw_final);
        }
        else
        {
            s_kbd_angle_valid = false; // not moving -> reset the keyboard facing ease
            s_kbd_angle_eased = 0.0f;
        }
        // Publish the collapse request to the input-thread dispatcher detour every frame - cleared (false)
        // whenever the full-turn backward redirect is not active - so a stranded flag can never disable normal
        // gamepad strafing/back-pedal. The detour additionally gates the collapse on sprint-held as a failsafe.
        if (player_onaction_available())
        {
            player_onaction_set_force_forward(orbit_force_forward);
        }
        // Keyboard turn-and-run: write the computed body-relative move input to C_PlayerInput (field write ->
        // overrides the held digital keys, no HUD glyph flip). kbd_move_write is set by the facing-ease above
        // (pure-forward while turning, rotated real keys while disengaging); false otherwise so the engine drives.
        apply_keyboard_move_override(kbd_move_write, kbd_move_x, kbd_move_y);

        // Camera collision: keep the view out of world geometry. Cast from the pivot (a safe
        // point inside the player) to the computed camera position; on a hit, pull the camera in
        // to just short of the surface. RWI_OBJTYPES_CAMERA excludes living entities so the ray
        // ignores the player and NPCs and only solid world geometry blocks the view. The camera
        // pulls in instantly (so it never ends up behind a wall) and eases back out once the
        // obstruction clears. The follow distance is carried in collision_distance.
        if (cfg.enable_collision.load(std::memory_order_relaxed))
        {
            const Vector3 to_camera = camera_position - pivot;
            const float desired_distance = to_camera.magnitude();
            if (desired_distance > 1e-3f)
            {
                const Vector3 ray_dir = to_camera / desired_distance;

                // Static-world throttle: camera collision only ever queries STATIC / terrain geometry (movable
                // rigids, the player and NPCs are all excluded), which cannot move while the camera holds still and
                // changes only SLOWLY as the camera moves. So the full result (fan, render occlusion, lateral
                // probe) is recomputed only once the pivot or the desired camera position has moved more than
                // k_collision_recompute_dist; in between it is reused and only the easing runs - which collapses
                // the cost to ~zero while standing AND skips most frames while walking (the dominant cost in dense
                // scenes such as a doorway). The threshold is a MOVEMENT distance, so fast motion still recomputes
                // every frame (responsive) while slow motion reuses for a few frames; the reused target is at most
                // one threshold of camera travel stale, which the easing and the collision standoff (CollisionRadius)
                // absorb, so the camera never visibly clips.
                constexpr float k_collision_recompute_dist = 0.06f;
                const float recompute_d2 = k_collision_recompute_dist * k_collision_recompute_dist;
                const Vector3 throttle_cam = camera_position; // desired (pre-collision); the block overwrites it
                static bool s_collision_throttle_valid = false;
                static Vector3 s_throttle_pivot{};
                static Vector3 s_throttle_cam{};
                static float s_cached_allowed = 0.0f;
                const bool recompute = !s_collision_throttle_valid ||
                                       (pivot - s_throttle_pivot).magnitude_squared() > recompute_d2 ||
                                       (throttle_cam - s_throttle_cam).magnitude_squared() > recompute_d2;
                if (!recompute && cam.collision_valid)
                {
                    // Reuse last frame's allowed distance (the shared easing), then skip the whole fan /
                    // render-occlusion / lateral-probe computation below.
                    const float return_speed = cfg.collision_return_speed.load(std::memory_order_relaxed);
                    ease_collision_toward(cam, s_cached_allowed, delta_time, return_speed);
                    camera_position = pivot + ray_dir * cam.collision_distance;
                    goto collision_done;
                }

                // KCD1 camera collision = an RWI multi-ray FAN (centre + 4 rays offset by the radius) as the
                // collision AUTHORITY. RWI takes objtypes as a plain function ARG so it is provably correct:
                // 0x101 = static|terrain excludes ALL actors (player body/gear, NPCs = ent_living/independent/
                // rigid). When UseSphereCollision is set, the PWI swept SPHERE smooths the fan's world hit
                // (continuous contact distance, no pump in dense geometry). (The KCD2 coverage-walk is still NOT
                // ported on KCD1: the render-coverage raster was not reversed for it.)
                const float collision_radius = cfg.collision_radius.load(std::memory_order_relaxed);
                // UseCoverageCollision is the master switch for the coverage-based heuristics. On KCD1 the coverage
                // raster is not ported, so this only gates the lateral frustum-clearance probe below; the nearest
                // occluder is always the nearest solid world surface (no coverage walk). Render occlusion is
                // INDEPENDENT (its own UseRenderOcclusion toggle below).
                const bool use_coverage = cfg.use_coverage_collision.load(std::memory_order_relaxed);
                // Find the nearest solid world surface along the arm. The coverage of the occluder is NOT measured
                // on KCD1 (the render-coverage raster is not ported), so blocked_cov stays at the not-measured
                // sentinel and is only logged.
                std::optional<RayHit> fan =
                    ray_fan_sweep(pivot, to_camera, collision_radius, Constants::RWI_OBJTYPES_CAMERA,
                                  Constants::RWI_FLAGS_STOP_AT_SOLID);
                const float blocked_cov = -9.0f; // coverage gate not consulted on KCD1; logged as not-measured
                std::optional<RayHit> hit = fan;
                bool from_sphere = false;
                if (cfg.use_sphere_collision.load(std::memory_order_relaxed))
                {
                    // Resolve the player's / actors' physics entities to SKIP on the sphere sweep (the PWI
                    // entTypes field is dead in this fork, so pSkipEnts is the only way to exclude the player; the
                    // probe casts in REVERSE camera->pivot because the pivot is inside the body). Capped at 4.
                    uintptr_t skip_ents[4];
                    const int n_skip = resolve_player_physics_skip(
                        pivot, to_camera, collision_radius, Constants::RWI_OBJTYPES_ALL, Constants::RWI_OBJTYPES_CAMERA,
                        Constants::RWI_FLAGS_STOP_AT_SOLID, skip_ents, 4);
                    const std::optional<RayHit> sphere = sphere_world_sweep(
                        pivot, collision_radius, to_camera, Constants::RWI_OBJTYPES_CAMERA, skip_ents, n_skip);
                    // The FAN is the AUTHORITY (objtypes 0x101 provably excludes all actors). The PWI sphere
                    // queries ent_all (entTypes dead in this fork), so trust it ONLY when it AGREES with the fan's
                    // world surface (within the radius inset). When the fan finds NO world (open space), there is
                    // NO collision - any actor the sphere saw is ignored. The sphere can only SMOOTH the fan's
                    // world hit, never make it closer.
                    if (fan.has_value() && sphere.has_value() &&
                        sphere->m_distance >= fan->m_distance - collision_radius - 0.10f &&
                        sphere->m_distance <= fan->m_distance + 0.05f)
                    {
                        hit = sphere; // sphere agrees with the fan's world surface -> use it (continuous, no pump)
                        from_sphere = true;
                    }
                }

                constexpr float k_collision_hold_seconds = 0.3f; // hold the pull-in across edge hit/miss gaps

                // Nearest SOLID-world block, skin-adjusted. The thin-ray (fan) path subtracts the configured skin.
                float blocking_distance = desired_distance;
                bool blocked = false;
                if (hit.has_value() && hit->m_distance < desired_distance)
                {
                    // The nearest solid blocks, so pull the camera to it. The sphere path already inset by the
                    // radius (no extra skin); the thin-ray (fan) path subtracts the configured skin before the surface.
                    const float skin = from_sphere ? 0.0f : cfg.collision_skin.load(std::memory_order_relaxed);
                    blocking_distance = std::max(0.0f, hit->m_distance - skin);
                    blocked = true;
                }

                // Trace the PHYSICS collision hit (the solid-world fan result) so it can be compared against
                // RenderOcclusion HIT: physics fires on walls / terrain / solid props (objtypes
                // ent_static|ent_terrain), render occlusion on non-physical cloth. Where physics is silent but
                // render fires (or vice versa) is the proof they are complementary, not redundant. Rate-limited
                // to a meaningful change (block-state toggle or distance move > 0.1m) so it never spams a frame.
                {
                    static bool s_phys_blocked = false;
                    static float s_phys_dist = -1.0f;
                    const float dd = blocked ? (hit->m_distance - s_phys_dist) : 0.0f;
                    const bool moved = (dd > 0.1f) || (dd < -0.1f);
                    const bool trace_on = DMK::log().is_enabled(DMK::LogLevel::Trace);
                    if (trace_on && blocked && (blocked != s_phys_blocked || moved))
                    {
                        // The FAN is the collision AUTHORITY: it carries the real collider + surface normal.
                        // (The KCD2 render-octree object identity via render_hit_info is NOT ported on KCD1, so
                        // the trace logs the fan hit fields without the render-node identity.)
                        const RayHit &id_hit = fan.has_value() ? *fan : *hit;
                        const Vector3 &hp = id_hit.m_point;
                        const Vector3 &hn = id_hit.m_normal;
                        const int hit_terrain = id_hit.m_terrain;
                        const uintptr_t collider = id_hit.m_collider;
                        DMK::log().trace("PhysicsCollision HIT: src={} bTerrain={} dist={} of {} cov={} collider={:#x} "
                                         "point=({}, {}, {}) normal=({}, {}, {}) cam=({}, {}, {}) pivot=({}, {}, {})",
                                         from_sphere ? "sphere" : "fan", hit_terrain, hit->m_distance, desired_distance,
                                         blocked_cov, collider, hp.x, hp.y, hp.z, hn.x, hn.y, hn.z, camera_position.x,
                                         camera_position.y, camera_position.z, pivot.x, pivot.y, pivot.z);
                    }
                    s_phys_blocked = blocked;
                    if (blocked)
                    {
                        s_phys_dist = hit->m_distance;
                    }
                }

                // Render-only overhead roofs (tent / awning canopy cloth) carry no ray-collidable physics, so the
                // fan glides through them and the cloth buries the camera on a look-down. Query the render octree
                // along the same arm and clamp below an overhead brush. The radius is the standoff (already applied
                // by render_occlusion_limit), so no skin is subtracted. Gated by UseRenderOcclusion alone - it is
                // INDEPENDENT of UseCoverageCollision (it handles non-physical cloth, not a coverage heuristic). A
                // thin overhead beam is rejected inside render_occlusion_limit by the sightline vertex-count test,
                // not a body-coverage gate (an overhead canopy covers ~0 of the body silhouette).
                if (cfg.use_render_occlusion.load(std::memory_order_relaxed))
                {
                    // Query the render octree only out to where the physics collision already stops the camera: a
                    // roof beyond that point can never be reached, so indoors / near walls (where physics blocks
                    // close) the query box shrinks to the short arm and skips the room's geometry, the bulk of the
                    // render-occlusion cost in dense scenes.
                    const Vector3 occ_arm = ray_dir * blocking_distance;
                    const std::optional<float> roof = render_occlusion_limit(pivot, occ_arm, collision_radius);
                    if (roof.has_value() && roof.value() < blocking_distance)
                    {
                        blocking_distance = std::max(0.0f, roof.value());
                        blocked = true;
                    }
                }

                float allowed_distance;
                if (blocked && blocking_distance < desired_distance)
                {
                    allowed_distance = blocking_distance;
                    cam.collision_hold_timer = k_collision_hold_seconds; // latch on a blocking hit
                }
                else if (cam.collision_valid && cam.collision_hold_timer > 0.0f)
                {
                    // Recently blocked but clear this frame: HOLD the pulled-in distance through the
                    // gap so an edge-grazing hit/miss alternation cannot pump the camera (sawtooth).
                    cam.collision_hold_timer -= delta_time;
                    allowed_distance = cam.collision_distance;
                }
                else
                {
                    allowed_distance = desired_distance; // truly clear: ease back out
                }

                // Lateral / frustum clearance. The pivot->camera probe only sees obstacles ALONG the arm, so a
                // wall BESIDE the camera (a corner, a doorway jamb, a narrow gap) is invisible to it and intrudes
                // into the view. Probe the camera's lateral surroundings (the frustum cross-section: +-right /
                // +-up around the look axis) and pull the camera further in along the arm until any CONVERGING
                // side wall is at least CameraProbeSize away. This is geometric penetration safety, NOT occlusion,
                // so it bypasses the coverage gate (a side wall does not hide the character) and queries static /
                // terrain world only (RWI_OBJTYPES_CAMERA never returns the player or NPCs). A wall the arm runs
                // PARALLEL to (a corridor) cannot be escaped by pulling in, so it is left alone rather than yanking
                // the camera to first person. Bounded passes; only does work when something is within reach.
                const float probe = use_coverage ? cfg.camera_probe_size.load(std::memory_order_relaxed) : 0.0f;
                if (probe > 0.0f && allowed_distance > collision_radius)
                {
                    const Vector3 view = ray_dir * -1.0f; // the camera looks back along the arm toward the pivot
                    Vector3 probe_right = view.cross(Vector3{0.0f, 0.0f, 1.0f});
                    const float rl = probe_right.magnitude();
                    if (rl > 1e-4f)
                    {
                        probe_right = probe_right / rl;
                        const Vector3 probe_up = probe_right.cross(view); // orthonormal (right & view perpendicular)
                        const Vector3 lateral[4] = {probe_right, probe_right * -1.0f, probe_up, probe_up * -1.0f};
                        // Floor the pull-in at the closest USEFUL third-person distance (follow_distance_min). A side
                        // wall grazing the frustum is a SOFTER concern than a direct occluder, so never drag the
                        // camera to near first person (losing the whole view + jamming into the character) just to
                        // hold one off - accept a little intrusion instead. Capped to the incoming allowed_distance
                        // so a tight pull from a real along-arm occluder is never pushed back OUT into it.
                        const float lateral_floor =
                            std::min(allowed_distance, cfg.follow_distance_min.load(std::memory_order_relaxed));
                        for (int pass = 0; pass < 3 && allowed_distance > lateral_floor; ++pass)
                        {
                            const Vector3 cam_test = pivot + ray_dir * allowed_distance;
                            float capped = allowed_distance;
                            for (const Vector3 &side : lateral)
                            {
                                const std::optional<RayHit> h =
                                    ray_world_intersection(cam_test, side * probe, Constants::RWI_OBJTYPES_CAMERA,
                                                           Constants::RWI_FLAGS_STOP_AT_SOLID);
                                if (!h.has_value() || h->m_distance >= probe)
                                {
                                    continue; // this side is clear within the probe
                                }
                                // Wall plane: point P, normal N (toward the camera). Lateral clearance along the
                                // arm is clear(t) = dot(pivot - P, N) + t * dot(ray_dir, N). Pulling IN clears the
                                // wall only when the arm runs INTO it (dot(ray_dir, N) < 0); a parallel / diverging
                                // wall is left alone. Solve for the largest t that keeps the camera `probe` off it.
                                const Vector3 &P = h->m_point;
                                const Vector3 &N = h->m_normal;
                                const float a = ray_dir.x * N.x + ray_dir.y * N.y + ray_dir.z * N.z;
                                if (a >= -0.05f)
                                {
                                    continue; // parallel / diverging side wall: pulling in cannot clear it
                                }
                                const float b = (pivot.x - P.x) * N.x + (pivot.y - P.y) * N.y + (pivot.z - P.z) * N.z;
                                const float t = (probe - b) / a;
                                if (t < capped)
                                {
                                    capped = t;
                                }
                            }
                            if (capped >= allowed_distance - 1e-3f)
                            {
                                break; // every side clear -> done
                            }
                            allowed_distance = std::max(lateral_floor, capped);
                            blocked = true;
                            cam.collision_hold_timer = k_collision_hold_seconds; // latch like a normal blocking hit
                        }
                    }
                }

                // Ease toward the allowed distance (fast pull-IN so a wall is never clipped, slower return-OUT),
                // via the shared helper the throttle bypass also uses.
                const float return_speed = cfg.collision_return_speed.load(std::memory_order_relaxed);
                ease_collision_toward(cam, allowed_distance, delta_time, return_speed);

                camera_position = pivot + ray_dir * cam.collision_distance;

                // Cache the freshly computed target so a held-still camera reuses it next frame (throttle above).
                s_collision_throttle_valid = true;
                s_throttle_pivot = pivot;
                s_throttle_cam = throttle_cam;
                s_cached_allowed = allowed_distance;
            }
        collision_done:;
        }

        // First-person fallback. With no room behind the player - a low lintel in a doorway (the roof clamp holds the
        // camera under it), a wall right behind - collision pulls the camera onto the pivot, inside the head, and the
        // view shows the head's inside until the player moves. Below HeadClearance of arm the camera eases onto the
        // real eye instead and the head is hidden by the game's own first-person rig (s_head_fallback, read by the
        // head re-assert and the head-visibility detour), so the view is plain first person until there is room
        // again. The arm is measured after collision, so a close zoom counts too. The margin keeps a doorway from
        // switching it on and off as the arm hovers around the threshold.
        {
            constexpr float k_head_fallback_margin = 0.15f; // meters of extra room before third person resumes
            constexpr float k_head_fallback_rate = 12.0f;   // ease rate, 1/sec (frame-rate independent below)
            const float clearance = cfg.head_clearance.load(std::memory_order_relaxed);
            // Measured from the head where it really is: the pivot plus the turn hold, which keeps the pivot off the
            // body while it steps through a turn.
            const float arm = (camera_position - (pivot + turn_hold)).magnitude();
            if (clearance <= 0.0f)
            {
                cam.head_fallback = false;
            }
            else if (!cam.head_fallback && arm < clearance)
            {
                cam.head_fallback = true;
                (void)DMK::log().try_log(DMK::LogLevel::Debug,
                                         "Camera: first-person fallback ON (arm {:.2f} m < HeadClearance {:.2f} m)",
                                         arm, clearance);
            }
            else if (cam.head_fallback && arm > clearance + k_head_fallback_margin)
            {
                cam.head_fallback = false;
                (void)DMK::log().try_log(DMK::LogLevel::Debug, "Camera: first-person fallback OFF (arm {:.2f} m)", arm);
            }
            const float target = cam.head_fallback ? 1.0f : 0.0f;
            const float k = 1.0f - std::exp(-k_head_fallback_rate * delta_time);
            cam.head_fallback_blend += (target - cam.head_fallback_blend) * k;
            if (std::fabs(target - cam.head_fallback_blend) < 1e-3f)
            {
                cam.head_fallback_blend = target;
            }
            // The head hides as soon as the fallback starts (the camera is already close to it) and shows again only
            // once the camera is back out past halfway.
            s_head_fallback.store(cam.head_fallback || cam.head_fallback_blend > 0.5f, std::memory_order_relaxed);
            if (cam.head_fallback_blend > 0.0f)
            {
                camera_position = camera_position + (fpv_position - camera_position) * cam.head_fallback_blend;
            }
        }

        // Write the offset position into the camera matrix translation column. The basis columns are
        // left as the engine built them (from the eye quat) unless convergence/orbit changed the look,
        // so the camera otherwise stays parallel to the player's view. The caller computes the cull
        // planes from this matrix next, so culling follows the rendered view.
        // Blend the final pose between first person (the engine's eye matrix) and the third-person pose
        // by view_blend so toggling the view eases instead of snapping. At view_blend 1 this is the full
        // third-person pose; at 0 it is the untouched first-person camera.
        const Vector3 final_position = fpv_position + (camera_position - fpv_position) * view_blend;
        matrix->m[0][3] = final_position.x;
        matrix->m[1][3] = final_position.y;
        matrix->m[2][3] = final_position.z;

        // Orientation: only when convergence/orbit changed the look (otherwise the engine-built eye basis
        // is already correct at every blend value, so the camera just sits behind the player looking where
        // they look). Ease the look from the eye forward to the converged look by view_blend, then rebuild
        // the column basis (right = forward x up, up = right x forward; col0 = right, col1 = forward,
        // col2 = up) so the orientation transitions smoothly too.
        // Screen-centre forward (the crosshair direction): the converged/orbited look when we rebuilt the
        // basis, else the engine eye forward. Published below for the camera-space interaction hook.
        // When the stable / smoothed basis is active, the rendered ORIENTATION must be rebuilt from it too:
        // otherwise the engine eye orientation (which carries the view-shake) would still drive the view
        // rotation even though the position is now stable, leaving the view tilting during an action. Forcing
        // the rebuild here routes the orientation through the same eye->stable blend below. When the basis was
        // NOT overridden, eye_forward == forward and eye_up == up, so this is a no-op and the path stays
        // byte-identical to the convergence/orbit-only behaviour.
        if (basis_overridden)
        {
            rebuild_basis = true;
        }
        Vector3 screen_forward = forward;
        if (rebuild_basis)
        {
            // Blend the orientation from the engine EYE basis (FPV side, so view_blend 0 leaves the untouched
            // first-person view) to the stable look (TPV side). At view_blend 0 this reconstructs the engine
            // eye basis exactly (eye_forward x eye_up == eye_right); at view_blend 1 it is the stable look.
            Vector3 blended_forward = eye_forward + (look_forward - eye_forward) * view_blend;
            blended_forward =
                (blended_forward.magnitude_squared() > 1e-6f) ? blended_forward.normalized() : look_forward;
            screen_forward = blended_forward;
            const Vector3 ref_up = eye_up + (up - eye_up) * view_blend;
            const Vector3 right_axis = blended_forward.cross(ref_up);
            if (right_axis.magnitude_squared() > 1e-6f)
            {
                const Vector3 new_right = right_axis.normalized();
                const Vector3 new_up = new_right.cross(blended_forward);
                matrix->m[0][0] = new_right.x;
                matrix->m[1][0] = new_right.y;
                matrix->m[2][0] = new_right.z;
                matrix->m[0][1] = blended_forward.x;
                matrix->m[1][1] = blended_forward.y;
                matrix->m[2][1] = blended_forward.z;
                matrix->m[0][2] = new_up.x;
                matrix->m[1][2] = new_up.y;
                matrix->m[2][2] = new_up.z;
            }
        }

        // Publish the rendered camera pose + crosshair direction for the camera-space interaction hook
        // (interaction_hook.cpp). The player use-cone is eye-anchored and never reads the render camera, so
        // in third person the screen-centre crosshair and the use-target diverge by the shoulder offset
        // (worst at close range - you cannot loot/use what the crosshair appears to be on). The hook
        // re-origins the cone onto this pose when InteractFromCamera is set. valid is true only here (while
        // the offset is engaged); the suppression path below clears it, so first person leaves the game alone.
        interaction_aim_pose().store(final_position.x, final_position.y, final_position.z, screen_forward.x,
                                     screen_forward.y, screen_forward.z);
    }

    /**
     * @brief Calls the head-visibility setter on the player entity.
     * @details Invokes the original (the trampoline, so this does not re-enter our detour).
     *          Faults are caught by the frustum detour's SEH wrapper this runs under. Runs on
     *          the view-update thread, the same thread the engine drives the setter on.
     * @param entity Player entity (C_Player).
     * @param hide_head Desired hide state (false = head shown).
     * @param flags The setter's third argument.
     */
    static void call_head_visibility(uintptr_t entity, bool hide_head, uint8_t flags)
    {
        if (const SetHeadVisibilityFunc original = s_set_head_visibility_original.load(std::memory_order_acquire))
        {
            original(entity, hide_head, static_cast<char>(flags));
        }
    }

    /**
     * @brief Latches @p player as if the game had just called the head-visibility setter on it.
     * @details The setter stores its hide value at OFFSET_ENTITY_HIDE_HEAD_FLAG and its third
     *          argument at OFFSET_ENTITY_HIDE_HEAD_ARG, and the game re-applies the head from
     *          exactly those two fields. A player the detour has not seen a call on (a new level,
     *          or a freshly loaded generation) is adopted from them before the re-assert first
     *          changes the head. Turning the offset off then restores what the game applied, not
     *          the default of a never-latched state, which would show the head in first person.
     * @param player The live C_Player.
     * @return False when either field cannot be read; nothing is latched then.
     */
    static bool adopt_head_state(uintptr_t player)
    {
        const auto hide_head =
            DMK::memory::read<uint8_t>(DMK::Address{player + Constants::OFFSET_ENTITY_HIDE_HEAD_FLAG});
        const auto flags = DMK::memory::read<uint8_t>(DMK::Address{player + Constants::OFFSET_ENTITY_HIDE_HEAD_ARG});
        if (!hide_head || !flags)
        {
            return false;
        }
        s_head_entity.store(player, std::memory_order_relaxed);
        s_head_flags.store(*flags, std::memory_order_relaxed);
        s_game_intended_hide_head.store(*hide_head != 0, std::memory_order_relaxed);
        return true;
    }

    /**
     * @brief Keeps the player head in sync with the offset state once per frame.
     * @details While the offset is active the head must stay shown (hidden only during the
     *          first-person fallback, when the camera sits at the eye), but the engine only
     *          sets head visibility on its own transitions, so re-call the setter whenever
     *          the live hide flag disagrees. When the offset has just turned
     *          off, restore the game's intended hide value exactly once so the first-person
     *          rig hides the head again. The hide flag is re-read rather than cached so this
     *          self-heals regardless of who last changed it, and a call is issued only on a
     *          mismatch so the engine is not driven every frame.
     *          The player is the live C_Player resolved this frame when there is one, else the
     *          one the setter was last called on. A live player that differs from the latched
     *          one is adopted first (adopt_head_state), because a freshly loaded generation or a
     *          new level has no call latched until the game next switches the view itself.
     * @param active Whether the offset is currently being applied to the game view.
     * @param c_player The live C_Player (vtable-validated), or 0.
     */
    static void reassert_head_visibility(bool active, uintptr_t c_player)
    {
        const uintptr_t latched = s_head_entity.load(std::memory_order_relaxed);
        const uintptr_t entity = c_player != 0 ? c_player : latched;
        if (entity != 0 && DMK::memory::is_plausible_ptr(DMK::Address{entity}) &&
            (entity == latched || adopt_head_state(entity)))
        {
            const uint8_t flags = s_head_flags.load(std::memory_order_relaxed);
            if (active)
            {
                const bool want_hidden = s_head_fallback.load(std::memory_order_relaxed);
                const auto hide_flag =
                    DMK::memory::read<uint8_t>(DMK::Address{entity + Constants::OFFSET_ENTITY_HIDE_HEAD_FLAG});
                if (hide_flag && (*hide_flag != 0) != want_hidden)
                {
                    call_head_visibility(entity, want_hidden, flags);
                }
            }
            else if (s_head_was_active.load(std::memory_order_relaxed))
            {
                call_head_visibility(entity, s_game_intended_hide_head.load(std::memory_order_relaxed), flags);
            }
        }
        s_head_was_active.store(active, std::memory_order_relaxed);
    }

    /**
     * @brief Applies the forced-view policy on STATE-CHANGE EDGES, not every frame.
     * @details A continuous per-frame override would fight the player: they could never toggle the view
     *          while a forced state was active, because the next frame would re-force it. Instead this
     *          forces the view ONCE when a forced state begins, lets the player toggle freely while it
     *          lasts, and restores the pre-force view when the state ends - unless the player changed
     *          the view themselves meanwhile, in which case their choice stands. Forced-FPV wins over
     *          forced-TPV on overlap. Runs on the render thread only (the detour), so the latch state is
     *          plain file-scope static; cam.applying is atomic because the hotkeys write it too.
     * @param cam Camera state whose applying flag (the live view) is forced and restored.
     * @param state Current debounced GameState mask.
     * @param forced_fpv_mask States that switch to first person on entry.
     * @param forced_tpv_mask States that switch to third person on entry.
     */
    static void apply_forced_view_policy(CameraState &cam, uint32_t state, uint32_t forced_fpv_mask,
                                         uint32_t forced_tpv_mask)
    {
        // The view the policy wants this frame: -1 none, 0 force FPV, 1 force TPV (forced-FPV wins).
        int forced_view = -1;
        if ((state & forced_fpv_mask) != 0)
        {
            forced_view = 0;
        }
        else if ((state & forced_tpv_mask) != 0)
        {
            forced_view = 1;
        }

        // s_prev_forced_view detects the edge; s_saved_applying is the view to restore on exit;
        // s_policy_owns is cleared once the player toggles the view while a forced state is active, so
        // the policy then stops re-forcing and skips the restore on exit (their manual choice stands).
        static int s_prev_forced_view = -1;
        static bool s_saved_applying = false;
        static bool s_policy_owns = false;

        if (forced_view != s_prev_forced_view)
        {
            if (forced_view == -1)
            {
                // Left every forced state: restore the pre-force view, but only if the player did not
                // switch the view themselves during the state (otherwise their choice stands).
                if (s_policy_owns)
                {
                    cam.applying.store(s_saved_applying, std::memory_order_relaxed);
                    s_policy_owns = false;
                }
            }
            else
            {
                // Entered a forced state (or switched directly from one forced view to another). Save
                // the pre-force view on the first entry from an unforced state so it can be restored on
                // exit, then apply the forced view exactly once.
                if (s_prev_forced_view == -1)
                {
                    s_saved_applying = cam.applying.load(std::memory_order_relaxed);
                }
                cam.applying.store(forced_view == 1, std::memory_order_relaxed);
                s_policy_owns = true;
            }
            s_prev_forced_view = forced_view;
        }
        else if (forced_view != -1 && s_policy_owns &&
                 cam.applying.load(std::memory_order_relaxed) != (forced_view == 1))
        {
            // Same forced state as last frame, but the player toggled the view away from the forced
            // value: release ownership so the policy stops forcing and does not restore on exit.
            s_policy_owns = false;
        }
    }

    /**
     * @brief Suspends free-look on entering an OrbitExcludeState and RESTORES it on exit.
     * @details Edge-triggered, like the forced-view policy: free-look is turned off once when a listed
     *          state begins and re-enabled when it ends, so a state that interrupts free-look (a
     *          dialogue, a minigame) does not permanently cancel it. It only re-enables if the policy
     *          was the one that turned it off (free-look was on at entry). Render-thread only.
     * @param cam Camera state whose orbit_active flag is suspended and restored.
     * @param state Current debounced GameState mask.
     * @param orbit_exclude_mask States in which free-look is disabled.
     */
    static void apply_orbit_exclude_policy(CameraState &cam, uint32_t state, uint32_t orbit_exclude_mask)
    {
        const bool excluded = (state & orbit_exclude_mask) != 0;
        static bool s_prev_excluded = false;
        static bool s_suspended_orbit = false; // the policy turned free-look off and will restore it

        if (excluded == s_prev_excluded)
        {
            // Still in the same state. If the policy suspended free-look on entry but the player has since
            // turned it back on by hand, release the suspension so the exit branch does not later re-assert
            // it against a manual choice (symmetric to apply_forced_view_policy's ownership release).
            if (excluded && s_suspended_orbit && cam.orbit_active.load(std::memory_order_relaxed))
            {
                s_suspended_orbit = false;
            }
            return;
        }
        if (excluded)
        {
            // Entering an excluded state (combat, dialogue, minigame) swaps the action map, which can swallow a
            // held-move release and strand the movement-input latch > 0. Drop it now so when free-look restores on
            // exit it cannot re-trip the body-turn with the keys released (the post-combat self-rotation). Logged
            // with the cleared magnitude so the trace shows whether the latch WAS actually stranded.
            const float stranded = player_onaction_reset();
            DMK::log().trace("Orbit: exclude-state entered; cleared move-latch (had magnitude "
                             "{:.2f}{})",
                             stranded, stranded > k_orbit_move_input_stop ? ", WAS STRANDED" : "");
            // If free-look was on, turn it off and remember to restore it.
            s_suspended_orbit = cam.orbit_active.load(std::memory_order_relaxed);
            if (s_suspended_orbit)
            {
                cam.orbit_active.store(false, std::memory_order_relaxed);
            }
        }
        else if (s_suspended_orbit)
        {
            // Leaving the excluded state: re-enable free-look and re-seed its angles to the configured
            // centre, matching a fresh toggle-on (the camera moved during the excluded state, so
            // resuming the old orbit angle would be meaningless).
            cam.orbit_yaw.store(0.0f, std::memory_order_relaxed);
            cam.orbit_pitch.store(0.0f, std::memory_order_relaxed);
            cam.orbit_active.store(true, std::memory_order_relaxed);
            s_suspended_orbit = false;
        }
        s_prev_excluded = excluded;
    }

    /**
     * @brief Returns the CView embedding @p camera when it is the game view's camera, else 0.
     * @details The camera is embedded in its CView at SVIEWPARAMS_VIEWMATRIX_OFFSET, so the CView is that far below
     *          the camera. It is confirmed by its vtable: shadow, reflection and portal cameras handed to the same
     *          builder are not embedded in a CView and fail this guard. The CView is identified through its cached
     *          class identity (rtti_types), so the steady-state gate is a single qword compare against the primary
     *          vtable resolved once at init; the RTTI type name rather than a hardcoded vtable address keeps this
     *          resilient across game patches, and the identity's image-generation stamp keeps it honest across a
     *          remap.
     */
    [[nodiscard]] static uintptr_t game_view_cview(uintptr_t camera)
    {
        if (!DMK::memory::is_plausible_ptr(DMK::Address{camera}))
        {
            return 0;
        }
        const uintptr_t cview = camera - Constants::SVIEWPARAMS_VIEWMATRIX_OFFSET;
        const auto vtable = DMK::memory::read<uintptr_t>(DMK::Address{cview});
        if (!vtable || !DMK::memory::is_plausible_ptr(DMK::Address{*vtable}) || !vtable_is(GameClass::View, *vtable))
        {
            return 0;
        }
        return cview;
    }

    /**
     * @brief SGameObjectEvent as the camera manager builds it when it switches the active camera.
     */
    struct alignas(16) GameObjectEvent
    {
        uintptr_t vtable;
        uint32_t event;
        uint32_t flags;
        uint64_t param[2];
    };
    static_assert(sizeof(GameObjectEvent) == 0x20, "SGameObjectEvent is 0x20 bytes");

    /**
     * @brief Sends the player the camera-changed event, so its locomotion action re-reads IsThirdPerson now.
     * @details The camera manager sends this event through C_Player::HandleEvent whenever it switches the active
     *          camera, and the movement action answers it, while idle, by taking or dropping its LockBodyTurn
     *          reference to match IsThirdPerson. Thread: the actor updates, the locomotion action included, run on
     *          job-system workers early in the frame and finish before the view update runs on the main thread.
     *          The frustum detour runs inside that view update, so this is sent from the same thread and frame phase
     *          as the game's own. Guarded: a layout change in the handler must never crash the game.
     * @param c_player The live C_Player (vtable-validated), or 0.
     * @return True when the event was delivered.
     */
    static bool send_camera_changed_event(uintptr_t c_player) noexcept
    {
        if (c_player == 0 || s_player_handle_event == 0 || s_game_object_event_vtable == 0)
        {
            return false;
        }
        const GameObjectEvent event{
            .vtable = s_game_object_event_vtable,
            .event = s_camera_changed_event_id,
            .flags = s_camera_changed_event_flags,
            .param = {0, 0},
        };
        __try
        {
            reinterpret_cast<HandleEventFunc>(s_player_handle_event)(c_player, &event);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
        return true;
    }

    /**
     * @brief Reads the player's LockBodyTurn reference count, or -1 when it cannot be read or its offset did not
     *        resolve. Used only for the log.
     */
    static int32_t read_lock_body_turn_count(uintptr_t c_player)
    {
        if (c_player == 0 || s_lock_body_turn_count_offset == 0)
        {
            return -1;
        }
        const auto count = DMK::memory::read<int32_t>(DMK::Address{c_player + s_lock_body_turn_count_offset});
        return count ? *count : -1;
    }

    /**
     * @brief Reads the player's world body yaw and look yaw, in radians (engine convention: forward = (-sin, cos)).
     * @return False when either could not be read. Used only for the log.
     */
    static bool read_body_and_look_yaw(uintptr_t c_player, float &body_yaw, float &look_yaw)
    {
        const auto entity =
            DMK::memory::read<uintptr_t>(DMK::Address{c_player + runtime_offsets().c_player_entity.load().value});
        const auto controller = DMK::memory::read<uintptr_t>(
            DMK::Address{c_player + runtime_offsets().c_player_look_controller.load().value});
        if (!entity || !controller || !DMK::memory::is_plausible_ptr(DMK::Address{*entity}) ||
            !DMK::memory::is_plausible_ptr(DMK::Address{*controller}))
        {
            return false;
        }
        const auto world = DMK::memory::read<GameStructures::Matrix34f>(
            DMK::Address{*entity + Constants::OFFSET_ENTITY_WORLD_MATRIX_MEMBER});
        const auto yaw = DMK::memory::read<float>(DMK::Address{*controller + Constants::LOOK_CONTROLLER_YAW_OFFSET});
        if (!world || !yaw || !std::isfinite(*yaw))
        {
            return false;
        }
        body_yaw = std::atan2(-world->m[0][1], world->m[1][1]);
        look_yaw = *yaw;
        return true;
    }

    /**
     * @brief Publishes @p actor as the native-turn actor (0 = off) and re-syncs the locomotion action on a change.
     * @details A switch resets the turn decision, then sends the camera-changed event so an idle action takes or drops
     *          its LockBodyTurn reference now rather than on its next locomotion change. Switching off only ever
     *          reaches the player it was switched on for: a player that went away (a load) took its action with it.
     *          Following the look again snaps the body to the look, as the game does when it leaves its own
     *          third-person camera. Game-view frustum frames only (the game thread).
     * @param c_player The live C_Player (vtable-validated), or 0.
     * @param actor The actor to publish: @p c_player to switch on, 0 to switch off.
     * @param reason Short description for the log line.
     */
    static void publish_native_turn_actor(uintptr_t c_player, uintptr_t actor, std::string_view reason)
    {
        const uintptr_t previous = s_native_turn_actor.load(std::memory_order_relaxed);
        if (actor == previous)
        {
            return;
        }
        s_turn_continuing.store(false, std::memory_order_relaxed);     // a fresh start for the turn decision
        s_turn_decision_missed.store(true, std::memory_order_relaxed); // and for the look's rest
        s_native_turn_actor.store(actor, std::memory_order_seq_cst);
        const uintptr_t target = actor != 0 ? actor : (previous == c_player ? previous : 0);
        const int32_t count_before = read_lock_body_turn_count(target);
        const bool sent = send_camera_changed_event(target);
        const int32_t count_after = read_lock_body_turn_count(target);
        (void)DMK::log().try_log(DMK::LogLevel::Debug,
                                 "Native turn: {} ({}); camera-changed event {}, LockBodyTurn count {} -> {} (0 = body "
                                 "follows the look)",
                                 actor != 0 ? "ON" : "OFF", reason, sent ? "sent" : "not sent", count_before,
                                 count_after);
    }

    /**
     * @brief Publishes the native turn-animation state for the IsThirdPerson detour and re-syncs the locomotion
     *        action's LockBodyTurn reference on every change.
     * @details The detour reports third person to the locomotion action while all of these hold:
     *          - the third-person view is engaged, including its ease-out, so the body follows the look again only
     *            once the view is back at the eye;
     *          - the setting is on and no NativeTurnExcludeState state is active;
     *          - the view is not on the first-person eye (@p eye_anchored: the head fallback, or an Eye Height 0
     *            preset). On the eye the body follows the look as in first person, because the eye sits on the head
     *            bone and swings with a turn, and a body free of the look with no turns stays behind while the player
     *            looks around.
     *          Turns are held off (the body stays free of the look but starts no turn) while @p turns_allowed is
     *          false, which is free-look. Its look input is captured, so a look change is the mod's own heading write
     *          on a move start and must not start a turn fragment under the orbit body override.
     *          On a change the action is told at once through the camera-changed event (publish_native_turn_actor).
     *          Game-view frustum frames only.
     * @param c_player The live C_Player (vtable-validated), or 0.
     * @param engaged Whether the third-person offset is rendering this frame.
     * @param state The debounced GameState mask.
     * @param eye_anchored Whether the view rides the first-person eye (see above).
     * @param turns_allowed Whether a turn fragment may start (see above).
     * @param delta_time Frame time in seconds, for the trace cadence.
     */
    static void update_native_turn(uintptr_t c_player, bool engaged, uint32_t state, bool eye_anchored,
                                   bool turns_allowed, float delta_time)
    {
        const LiveSettings &cfg = settings();
        const bool enabled = cfg.native_turn_animation.load(std::memory_order_relaxed);
        const bool excluded = (state & cfg.native_turn_exclude_mask.load(std::memory_order_relaxed)) != 0;

        // Without a resolved player there is no one to send the event to, so switching off would leave the action's
        // reference taken until its next idle start. Keep the published state through a brief miss; a longer one is a
        // load or a menu, whose player (and action) is going away anyway.
        constexpr float k_player_miss_grace = 0.5f; // seconds
        static float s_player_missing = 0.0f;
        if (c_player == 0)
        {
            s_player_missing += delta_time;
            if (s_player_missing < k_player_miss_grace)
            {
                return;
            }
        }
        else
        {
            s_player_missing = 0.0f;
        }
        const bool want = s_native_turn_armed.load(std::memory_order_acquire) && c_player != 0 && engaged && enabled &&
                          !excluded && !eye_anchored;
        s_native_turn_trigger.store(want && turns_allowed, std::memory_order_relaxed);

        const uintptr_t actor = want ? c_player : 0;
        if (actor != s_native_turn_actor.load(std::memory_order_relaxed))
        {
            const std::string reason = std::format("view engaged {}, setting {}, excluded state {}, view on the eye {}",
                                                   engaged, enabled, excluded, eye_anchored);
            publish_native_turn_actor(c_player, actor, reason);
        }

        // The player's animated character, for the movement detour that keeps turn steps in place (0 while off).
        uintptr_t player_animchar = 0;
        if (actor != 0)
        {
            const RuntimeOffsets &offsets = runtime_offsets();
            const std::array<std::ptrdiff_t, 3> animchar_chain{offsets.c_player_animated_human.load().value,
                                                               offsets.animated_human_animchar.load().value, 0};
            const auto anim_char = DMK::memory::walk(DMK::Address{c_player}, animchar_chain);
            if (anim_char && DMK::memory::is_plausible_ptr(*anim_char))
            {
                const auto vt = DMK::memory::read<uintptr_t>(*anim_char);
                if (vt && vtable_is(GameClass::AnimatedCharacter, *vt))
                {
                    player_animchar = anim_char->raw();
                }
            }
        }
        s_player_animchar.store(player_animchar, std::memory_order_relaxed);

        // The turn decision's settings, read by the decision hook in the next frame's actor update.
        const float start_angle_deg = std::clamp(cfg.native_turn_angle.load(std::memory_order_relaxed), 10.0f, 90.0f);
        s_turn_start_angle.store(DMK::math::degrees_to_radians(start_angle_deg), std::memory_order_relaxed);
        s_turn_settle_delay.store(std::max(0.0f, cfg.native_turn_settle_delay.load(std::memory_order_relaxed)),
                                  std::memory_order_relaxed);

        if (actor == 0 || !DMK::log().is_enabled(DMK::LogLevel::Trace))
        {
            return;
        }

        // Trace the gap between the look and the body a few times a second while it changes, so a log shows each
        // turn's start, progress and finish against the LockBodyTurn count and the decision state.
        static float s_trace_timer = 0.0f;
        static float s_last_gap_deg = 0.0f;
        s_trace_timer += delta_time;
        if (s_trace_timer >= 0.1f)
        {
            s_trace_timer = 0.0f;
            float body_yaw = 0.0f;
            float look_yaw = 0.0f;
            if (read_body_and_look_yaw(c_player, body_yaw, look_yaw))
            {
                const float gap = std::remainder(look_yaw - body_yaw, 2.0f * DirectX::XM_PI);
                const float gap_deg = DMK::math::radians_to_degrees(gap);
                if (std::fabs(gap_deg - s_last_gap_deg) > 1.0f)
                {
                    (void)DMK::log().try_log(DMK::LogLevel::Trace,
                                             "Native turn: look leads body by {:.1f} deg (LockBodyTurn count {}, turn "
                                             "trigger {}, turning {}, look still for {} ms)",
                                             gap_deg, read_lock_body_turn_count(c_player),
                                             s_native_turn_trigger.load(std::memory_order_relaxed) ? "on" : "off",
                                             s_turn_continuing.load(std::memory_order_relaxed),
                                             GetTickCount64() - s_turn_rest_since.load(std::memory_order_relaxed));
                }
                s_last_gap_deg = gap_deg;
            }
        }
    }

    /**
     * @brief Switches the native turn animation off on the game thread, for the teardown hand-off.
     * @details Stops reporting third person and sends the camera-changed event, so an idle locomotion action drops its
     *          LockBodyTurn reference and the body follows the look again before the hooks are retired.
     * @param c_player The live C_Player (vtable-validated), or 0.
     */
    static void release_native_turn(uintptr_t c_player)
    {
        s_native_turn_trigger.store(false, std::memory_order_relaxed);
        publish_native_turn_actor(c_player, 0, "shutting down");
        s_player_animchar.store(0, std::memory_order_relaxed);
    }

    /**
     * @brief Gate + matrix-offset body for the frustum-builder detour. Separated from the SEH wrapper
     *        so that frame can hold C++ objects that need unwinding.
     * @details Cheapest exits first: the runtime toggle, then the CView vtable identity (a single
     *          guarded read), so the inactive feature and any non-game camera (shadow, reflection,
     *          portal) pay almost nothing.
     * @param camera The camera handed to the frustum builder (matrix at offset 0).
     */
    static void detour_frustum_build_impl(uintptr_t camera)
    {
        // Named timing scope for the whole per-frame camera body. Compiles to nothing unless the build sets
        // DMK_ENABLE_PROFILING, and the collision/occlusion queries carry their own nested scopes, so a
        // profiling build attributes a frame spike to a specific query instead of "the camera hook".
        DMK_PROFILE_SCOPE("camera.frustum_build");

        // Teardown: the control thread asked for the per-frame overrides back. Do it HERE, on a game-view frame of
        // the thread the engine itself drives them on, so the move field, the head-visibility setter and the
        // locomotion action are never touched concurrently with the engine (shadow and reflection cameras share this
        // builder from other call sites, so their builds only wait); then leave the view to the game until the hooks
        // are retired.
        if (s_release_requested.load(std::memory_order_acquire))
        {
            if (!s_release_done.load(std::memory_order_relaxed) && game_view_cview(camera) != 0)
            {
                // Stop mirroring the offset first, so the head-visibility and input detours pass the game's own
                // values through from now on.
                s_offset_active.store(false, std::memory_order_relaxed);
                s_head_fallback.store(false, std::memory_order_relaxed);
                s_ai_eye_valid.store(false, std::memory_order_release);
                apply_keyboard_move_override(false, 0.0f, 0.0f);
                const uintptr_t c_player = resolve_c_player();
                // The body follows the look again before the IsThirdPerson hook goes away.
                release_native_turn(c_player);
                // Restores the game's intended head state once, if it was forced.
                reassert_head_visibility(false, c_player);
                interaction_aim_pose().invalidate();
                s_release_done.store(true, std::memory_order_release);
            }
            return;
        }

        CameraState &cam = camera_state();
        LiveSettings &cfg = settings();

        const bool state_policy = cfg.enable_state_behavior.load(std::memory_order_relaxed);
        const uint32_t forced_fpv = state_policy ? cfg.forced_fpv_mask.load(std::memory_order_relaxed) : 0u;
        const uint32_t forced_tpv = state_policy ? cfg.forced_tpv_mask.load(std::memory_order_relaxed) : 0u;

        // Fast path: nothing can drive the offset, so there is nothing to do. When any forced state is
        // configured the policy must run every game-view frame to catch the state-change EDGES that
        // trigger a one-time forced switch, so only skip when the player is in manual first person with
        // no forced states configured and the head has already been restored (the head-restore branch
        // keeps running for one frame after a toggle-off, while s_head_was_active is still set).
        // The native turn animation must also be off (it lets the body follow the look again on the frame the view
        // disengages).
        if (!cam.applying.load(std::memory_order_relaxed) && (forced_fpv | forced_tpv) == 0 &&
            !s_head_was_active.load(std::memory_order_relaxed) && cam.view_blend <= 1e-3f &&
            s_native_turn_actor.load(std::memory_order_relaxed) == 0)
        {
            // Even while idle (first person, no forced state), probe for the player until the world is
            // first seen so game_world_ready becomes true in-world REGARDLESS of the third-person view
            // being on - the overlay waits on it. resolve_c_player sets the flag on success and returns
            // 0 at the menu, so this costs a few guarded reads per frame only until load-in, then never.
            if (!game_world_ready().load(std::memory_order_relaxed))
            {
                resolve_c_player();
                // The probe publishes the chain bases its walk reaches, so let the self-heal scheduler act on
                // them while the world loads in (the game-view path below ticks it once the offset engages).
                offset_heal_tick();
            }
            // Offset disengaged: the orbit cannot be capturing, and the cursor flag is only refreshed on
            // the game-view path below, so clear it here to keep it from latching true across the gap.
            s_cursor_shown.store(false, std::memory_order_relaxed);
            return;
        }

        // Only the game view's camera is offset (see game_view_cview).
        const uintptr_t cview = game_view_cview(camera);
        if (cview == 0)
        {
            return;
        }

        // Advance the self-heal scheduler once per game-view frame, before anything reads a healed offset. This
        // is the mod's render-thread heartbeat: every un-latched group whose gate passes and whose retry interval
        // is due runs its scan here, and a group that has resolved is not scanned again. Ticking behind the CView
        // gate (not per frustum call) keeps the interval in real frames, since shadow and reflection cameras run
        // the same builder several times a frame.
        offset_heal_tick();

        // Game-view camera: take the single per-frame delta and resolve the player once here, then
        // reuse both in the matrix offset below so neither is computed twice per frame. The game state
        // is derived from the discrete engine signals and published for the input-dispatch thread.
        const float delta_time = frame_delta();
        const uintptr_t c_player = resolve_c_player();
        // Presets are always active, so the debounced game state is always needed here (to select the
        // active preset and, when state behaviour is on, to drive the forced-view / orbit-exclude policies).
        const uint32_t raw_state = poll_game_state(c_player);
        const uint32_t state =
            debounce_game_state(raw_state, delta_time, cfg.state_switch_hold_seconds.load(std::memory_order_relaxed));
        if (state_policy)
        {
            // Both policies are edge-triggered (they act on state-change edges, not every frame) so the
            // player keeps manual control while a state lasts. The forced-view policy writes cam.applying
            // on entry and restores it on exit; the orbit-exclude policy suspends free-look on entry and
            // restores it on exit.
            apply_forced_view_policy(cam, state, forced_fpv, forced_tpv);
            apply_orbit_exclude_policy(cam, state, cfg.orbit_exclude_mask.load(std::memory_order_relaxed));
        }
        game_state_mask().store(state, std::memory_order_relaxed);

        // Publish whether the game is showing the OS cursor (a UI is up) so the free-look input gate can
        // freeze the orbit while menus / loot / trade / dialogue are open. The hardware-mouse reference
        // counter (g_env -> p_hardware_mouse -> + count) reads > 0 whenever any UI requests the cursor.
        // Every link is screened (one guarded DMK::memory::walk to the counter, then a guarded read), and any failed
        // link - or the feature being disabled - publishes false, so a layout miss or a load degrades to
        // normal orbit rather than a stuck-frozen one. Read here on the render thread; the input thread only reads the
        // published flag (same producer/consumer split as game_state_mask, so no new cross-thread race).
        // Non-game-view frustum frames (shadow/reflection) skip this publish, but cannot strand the orbit
        // frozen: s_offset_active is co-published on this same game-view path and the input gate tests it
        // first, so a stale true here is moot whenever the offset is not actively rendering the view.
        bool cursor_shown = false;
        if (cfg.freeze_orbit_on_cursor.load(std::memory_order_relaxed) && s_genv_runtime != 0)
        {
            const std::array<std::ptrdiff_t, 2> cursor_chain{Constants::GENV_HARDWARE_MOUSE_OFFSET,
                                                             Constants::HARDWARE_MOUSE_CURSOR_COUNT_OFFSET};
            const auto count_addr = DMK::memory::walk(DMK::Address{s_genv_runtime}, cursor_chain);
            if (count_addr)
            {
                const auto count = DMK::memory::read<int32_t>(*count_addr);
                cursor_shown = count.has_value() && *count > 0;
            }
        }
        s_cursor_shown.store(cursor_shown, std::memory_order_relaxed);

        // Drive the player head from the offset state every frame (the engine only sets it on its own
        // transitions, so toggling the offset would otherwise leave the head stuck), then offset the
        // matrix while active. The offset follows cam.applying directly - both the manual toggle and
        // the edge-triggered policy write it - and should_apply_view() applies the SuppressTPVState hard
        // gate.
        // Ease the first-person <-> third-person blend toward the desired view so toggling (and UI
        // suppression) slides instead of snapping. ViewTransitionDuration 0 makes the switch instant.
        const bool want_tpv = cam.applying.load(std::memory_order_relaxed) && should_apply_view();
        const float view_dur = cfg.view_transition_duration.load(std::memory_order_relaxed);
        const float view_target = want_tpv ? 1.0f : 0.0f;
        if (view_dur > 1e-4f)
        {
            const float view_step = delta_time / view_dur;
            cam.view_blend = (cam.view_blend < view_target) ? std::min(view_target, cam.view_blend + view_step)
                                                            : std::max(view_target, cam.view_blend - view_step);
        }
        else
        {
            cam.view_blend = view_target;
        }

        // The offset is rendered while heading TO or holding third person, so the ease-OUT renders too.
        const bool offset_engaged = want_tpv || cam.view_blend > 1e-3f;
        s_offset_active.store(offset_engaged, std::memory_order_relaxed);
        reassert_head_visibility(offset_engaged, c_player);
        // The body's native turn-in-place animation follows the offset too (it follows the look again once the view is
        // back at the eye), and is off while the view rides the first-person eye (the head fallback, or an Eye Height 0
        // preset anchored to it). No turn starts under free-look.
        const bool eye_anchored =
            s_head_fallback.load(std::memory_order_relaxed) || cfg.eye_height.load(std::memory_order_relaxed) <= 0.0f;
        update_native_turn(c_player, offset_engaged, state, eye_anchored,
                           !cam.orbit_active.load(std::memory_order_relaxed), delta_time);

        // Edge tracker for the disengage cleanup below: true while the offset is rendering, so the cleanup runs
        // ONCE on the third-person -> first-person transition, not every first-person frame.
        static bool s_orbit_was_engaged = false;
        if (!offset_engaged)
        {
            if (s_orbit_was_engaged)
            {
                // Just left third person (toggled to FPV, or a state suppressed the offset). Drop the orbit
                // run-state so re-engaging is fresh: clear the move re-arm latch and force-clear any
                // movement-input latch the game may have stranded on an action-map swap. Edge-gated so a key
                // held in first person does not spam the reset/log every frame.
                cam.orbit_move_armed = false;
                const float stranded = player_onaction_reset();
                if (stranded > k_orbit_move_input_stop)
                {
                    DMK::log().trace("Orbit: TPV disengaged; cleared a stranded move-latch (magnitude {:.2f})",
                                     stranded);
                }
                s_orbit_was_engaged = false;
            }
            cam.collision_valid = false;
            cam.collision_hold_timer = 0.0f;
            cam.head_fallback = false;
            cam.head_fallback_blend = 0.0f;
            s_head_fallback.store(false, std::memory_order_relaxed);
            // First person (or suppressed): the camera is the eye, so the interaction hook must NOT redirect.
            interaction_aim_pose().invalidate();
            // Nor does the AI's camera observer need the eye substituted.
            s_ai_eye_valid.store(false, std::memory_order_release);
            cam.orbit_level_blend = 0.0f;
            cam.orbit_render_valid =
                false; // next engaged frame snaps the orbit low-pass instead of easing across the gap
            cam.orbit_steer_valid = false; // and the continuous-align steer low-pass
            cam.eye_sync_valid = false;    // and the dynamic eye-height low-pass
            cam.fov_ease_valid = false;    // and the per-preset FOV override ease
            cam.basis_quat_valid = false;  // and the aim-basis low-pass
            cam.turn_track_valid = false;  // and the turn-in-place pivot hold
            cam.orbit_moving = false;
            cam.orbit_target_valid = false;
            cam.orbit_settle_hold = false; // drop any pending settle hold so re-engaging TPV is fresh
            // Back to first person: the next engaged frame should snap the preset, not ease across the gap.
            Presets::reset_transition();
            return;
        }
        s_orbit_was_engaged = true;

        // Resolve the active preset (by debounced state, or the overlay's editing pin) and ease the
        // live framing toward it BEFORE the matrix offset reads those settings this frame.
        Presets::resolve_and_apply(state, delta_time);

        // Publish the untouched first-person eye for the camera-observer detour before the matrix is offset: the AI
        // judges which NPCs to update from the observer, and in first person that observer stands at the eye.
        if (const auto eye = DMK::memory::read<Vector3>(DMK::Address{cview + Constants::SVIEWPARAMS_POSITION_OFFSET});
            eye)
        {
            s_ai_eye_x.store(eye->x, std::memory_order_relaxed);
            s_ai_eye_y.store(eye->y, std::memory_order_relaxed);
            s_ai_eye_z.store(eye->z, std::memory_order_relaxed);
            s_ai_eye_valid.store(true, std::memory_order_release);
        }

        // Smoothstep the linear view blend for an ease-in/out feel, then offset with it.
        const float vb = cam.view_blend;
        const float view_s = vb * vb * (3.0f - 2.0f * vb);
        offset_game_view_camera(camera, cview, c_player, delta_time, view_s);
    }

    /**
     * @brief Runs the per-frame camera offset under SEH, so an outdated offset or layout never crashes the game.
     * @details Apart from the detour, because the detour's DetourScope needs C++ object unwinding, which a __try
     *          frame cannot hold.
     */
    static void frustum_build_offset_guarded(uintptr_t camera) noexcept
    {
        __try
        {
            detour_frustum_build_impl(camera);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Swallow: an outdated offset or layout must never crash the game.
        }
    }

    /**
     * @brief Per-frame frustum-builder detour.
     * @details The matrix offset runs BEFORE the original, which then computes the cull planes from
     *          the offset matrix, so geometry culling matches the rendered third-person view. A
     *          layout drift degrades the offset to a no-op. The original always runs and its return
     *          value is forwarded so the frustum is still built whether or not the offset applied.
     */
    static uintptr_t __fastcall detour_frustum_build(uintptr_t camera) noexcept
    {
        const DetourScope in_flight;
        frustum_build_offset_guarded(camera);
        const FrustumBuildFunc original = s_frustum_build_original.load(std::memory_order_acquire);
        return original ? original(camera) : 0;
    }

    /**
     * @brief Runs the head-visibility latch and the original setter under SEH.
     * @details Apart from the detour, because the detour's DetourScope needs C++ object unwinding, which a __try
     *          frame cannot hold.
     */
    static void set_head_visibility_guarded(SetHeadVisibilityFunc original, uintptr_t entity, bool hide_head,
                                            char flags) noexcept
    {
        __try
        {
            // Latch the player entity, the flags, and the game's intended hide value so
            // the per-frame re-assert can keep the head shown while the offset is active
            // and restore the game's value when it turns off. This is the player because
            // the setter only toggles the FirstPersonView rig.
            s_head_entity.store(entity, std::memory_order_relaxed);
            s_head_flags.store(static_cast<uint8_t>(flags), std::memory_order_relaxed);
            s_game_intended_hide_head.store(hide_head, std::memory_order_relaxed);

            // Mirror the head to the offset's effective active state (published by the frustum
            // detour) rather than the raw toggle, so a forced-FPV/TPV state shows or hides the head
            // to match the view the player actually sees. The first-person fallback (camera at the
            // eye, no room behind) hides it like first person does.
            const bool active = s_offset_active.load(std::memory_order_relaxed);
            const bool final_hide_head = active ? s_head_fallback.load(std::memory_order_relaxed) : hide_head;
            original(entity, final_hide_head, flags);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Swallow: a layout change in the head setter must never crash the game.
        }
    }

    /**
     * @brief Head-visibility detour: keep the player head while the offset is rendering.
     * @details The first-person rig hides the head so it does not clip the eye camera.
     *          While the third-person view is active, force hide_head to false
     *          so the player is not headless from behind. Otherwise pass the game's
     *          intended value through unchanged.
     */
    static void __fastcall detour_set_head_visibility(uintptr_t entity, bool hide_head, char flags) noexcept
    {
        const DetourScope in_flight;
        if (const SetHeadVisibilityFunc original = s_set_head_visibility_original.load(std::memory_order_acquire))
        {
            set_head_visibility_guarded(original, entity, hide_head, flags);
        }
    }

    /**
     * @brief Free-look capture/block decision for one input event (toggle orbit camera).
     * @details While the offset is active and orbit is TOGGLED on, mouse-look deltas are accumulated
     *          into the orbit angles and ONLY those look events are blocked, so the player's look stays
     *          put while free-looking. Every other input (movement keys, interaction, clicks) passes
     *          through, so the toggle orbit is a usable camera mode the character can move and act in.
     *          Lives apart from the SEH wrapper so that frame stays free of C++ object unwinding; the
     *          wrapper guards the engine-owned reads.
     * @param input_event Engine input event (GameStructures::InputEvent layout).
     * @return true to block (swallow) the event, false to dispatch it normally.
     */
    [[nodiscard]] static bool orbit_capture_and_decide(uintptr_t input_event)
    {
        CameraState &cam = camera_state();
        // Gate on the offset's effective active state (so free-look also works when a forced-TPV state
        // turned the offset on without the manual toggle), the orbit toggle, the cursor-shown flag (so a
        // UI being up holds the orbit instead of letting cursor motion turn it), and the shared UI gate
        // so the cursor and look work normally while a suppressed UI is up. Returning false here leaves
        // orbit_yaw/orbit_pitch untouched, so the camera resumes from the same angle when the UI closes.
        // orbit_active is the single source of truth for whether free-look captures input. The
        // OrbitExcludeState policy turns it off when ENTERING a listed state (edge-triggered, see
        // apply_orbit_exclude_policy), so capture stops there without forbidding a manual re-enable: a
        // player who toggles free-look back on in an excluded state (e.g. for a photo on a mount) still
        // gets mouse-look here. The cursor-shown gate freezes the orbit while any UI cursor is up.
        if (!s_offset_active.load(std::memory_order_relaxed) || !cam.orbit_active.load(std::memory_order_relaxed) ||
            s_cursor_shown.load(std::memory_order_relaxed) || !should_apply_view())
        {
            return false;
        }
        if (input_event == 0 || !DMK::memory::is_plausible_ptr(DMK::Address{input_event}))
        {
            return false;
        }

        const int32_t type = *reinterpret_cast<const int32_t *>(input_event + Constants::INPUT_EVENT_TYPE_OFFSET);
        const int32_t id = *reinterpret_cast<const int32_t *>(input_event + Constants::INPUT_EVENT_ID_OFFSET);
        // The look channel is the eIS_Changed (analog-axis-moved) state. Mouse AND gamepad both post here; the
        // keyId picks the axis and the device. Everything else (movement axes, buttons, clicks) falls through.
        if (type == Constants::MOUSE_INPUT_TYPE_ID)
        {
            const float value = *reinterpret_cast<const float *>(input_event + Constants::INPUT_EVENT_VALUE_OFFSET);

            // Mouse look: relative DELTA accumulated straight into the orbit angle (one event = one nudge).
            if (id == Constants::INPUT_LOOK_YAW_EVENT_ID || id == Constants::INPUT_LOOK_PITCH_EVENT_ID)
            {
                if (id == Constants::INPUT_LOOK_YAW_EVENT_ID)
                {
                    // Negated so mouse-left orbits the camera left and mouse-right orbits right; a negative X
                    // sensitivity inverts that.
                    const float sensitivity_x = settings().orbit_sensitivity_x.load(std::memory_order_relaxed);
                    cam.orbit_yaw.store(cam.orbit_yaw.load(std::memory_order_relaxed) - value * sensitivity_x,
                                        std::memory_order_relaxed);
                }
                else
                {
                    // Mouse-up raises the camera, mouse-down lowers it; a negative Y sensitivity inverts that.
                    const float sensitivity_y = settings().orbit_sensitivity_y.load(std::memory_order_relaxed);
                    const float pitch = cam.orbit_pitch.load(std::memory_order_relaxed) + value * sensitivity_y;
                    cam.orbit_pitch.store(std::clamp(pitch, settings().orbit_pitch_min.load(std::memory_order_relaxed),
                                                     settings().orbit_pitch_max.load(std::memory_order_relaxed)),
                                          std::memory_order_relaxed);
                }
                return true; // block ONLY the look so the player look stays put while free-looking
            }

            // Gamepad RIGHT STICK: latch the held DEFLECTION (-1..1) for the orbit rate integration, then ZERO
            // the event value IN PLACE and let it PASS (do NOT block). A held analog stick drives an engine
            // look-RATE that the engine only zeroes on a release event. BLOCKING swallows that release: if orbit
            // engages while the stick is already deflected (e.g. you hold the right stick then toggle orbit, or an
            // exclude state suspends/restores orbit mid-deflection), the engine keeps its last rate and SPINS the
            // player look forever - surviving a switch to first person and curable only by a hard input flush
            // (menu / alt-tab). It is the same swallowed-release defect as the move latch, but stranding the
            // ENGINE's own gamepad look. Zeroing the value instead means the engine continuously sees no
            // deflection (so it never turns and never strands) while we keep the real value for the orbit camera;
            // the release reaches the engine too. The mouse path above can still hard-block: a mouse delta is a
            // one-shot nudge with no held rate, so there is nothing to strand. Left stick (movement) keeps its own
            // ids and passes untouched.
            if (id == Constants::INPUT_PAD_LOOK_YAW_EVENT_ID)
            {
                cam.orbit_pad_yaw.store(value, std::memory_order_relaxed);
                *reinterpret_cast<float *>(input_event + Constants::INPUT_EVENT_VALUE_OFFSET) = 0.0f;
                return false;
            }
            if (id == Constants::INPUT_PAD_LOOK_PITCH_EVENT_ID)
            {
                cam.orbit_pad_pitch.store(value, std::memory_order_relaxed);
                *reinterpret_cast<float *>(input_event + Constants::INPUT_EVENT_VALUE_OFFSET) = 0.0f;
                return false;
            }
        }

        return false; // pass movement, interaction and everything else through
    }

    /**
     * @brief Runs orbit_capture_and_decide under SEH. A fault falls back to normal dispatch.
     * @details Apart from the detour, because the detour's DetourScope needs C++ object unwinding, which a __try
     *          frame cannot hold.
     * @return true to block (swallow) the event, false to dispatch it normally.
     */
    [[nodiscard]] static bool orbit_capture_guarded(uintptr_t input_event) noexcept
    {
        __try
        {
            return orbit_capture_and_decide(input_event);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    /**
     * @brief Input-dispatcher detour. Swallows events while free-looking, else passes through.
     */
    static void __fastcall detour_input_dispatch(uintptr_t controller, uintptr_t input_event, char flag) noexcept
    {
        const DetourScope in_flight;
        if (orbit_capture_guarded(input_event))
        {
            return;
        }
        if (const InputDispatchFunc original = s_input_dispatch_original.load(std::memory_order_acquire))
        {
            original(controller, input_event, flag);
        }
    }

    /**
     * @brief Resolves the SSystemGlobalEnvironment (g_env) base, patch-resiliently.
     * @details Reads the g_env base through the Engine gate. The Genv anchor is a 2-of-3 quorum of
     *          RIP-relative lea/mov [rip+g_env] reference sites, so the address survives game
     *          patches that shift the RVA. The result is screened as a plausible user-space pointer
     *          before it is accepted. There is no fixed-address fallback. The Steam and GOG builds keep
     *          g_env at different addresses, so a fixed one names the wrong slot on every build but one.
     * @return The g_env base address, or 0 when the gate failed. Every consumer then stays off.
     */
    static uintptr_t resolve_genv()
    {
        DMK::Logger &logger = DMK::log();

        // The Genv quorum resolved up front in resolve_all_anchors(), when at least two independent
        // lea/mov [rip+g_env] reference sites agreed. The result is screened as a plausible pointer.
        const uintptr_t resolved = gated_anchor_address(Feature::Engine, AnchorId::Genv);
        if (resolved != 0 && DMK::memory::is_plausible_ptr(DMK::Address{resolved}))
        {
            logger.info("Camera: g_env resolved at {}", DMK::format::format_address(resolved));
            return resolved;
        }

        logger.warning("Camera: g_env did not resolve; collision, aim convergence, render occlusion and the "
                       "hardware-mouse reads are unavailable");
        return 0;
    }

    /**
     * @brief Camera-observer update detour: keeps the AI's camera observer at the first-person eye in third person.
     * @details The engine's camera observer copies the system view camera, which carries the third-person offset.
     *          The AI selects which NPCs to update in full, and which to hide and pause, from that observer, so an
     *          NPC a few metres beyond its reach from the pulled-back camera (a sleeper in a house, someone inside a
     *          shop) vanishes in third person while first person, whose camera is the eye, shows it. The original
     *          runs first. While the offset renders, its position is replaced with the eye the frustum detour last
     *          published, so every consumer of the observer sees what it sees in first person. The direction and
     *          field of view stay as the original set them: the offset camera looks the same way as the eye.
     */
    static bool __fastcall detour_camera_observer_update(uintptr_t observer, float *position, bool *position_valid,
                                                         float *direction, bool *direction_valid, float *fov) noexcept
    {
        const DetourScope in_flight;
        const CameraObserverUpdateFunc original = s_camera_observer_update_original.load(std::memory_order_acquire);
        const bool updated =
            original != nullptr && original(observer, position, position_valid, direction, direction_valid, fov);
        // The original has just written through this pointer, so writing it again is as safe as its own store.
        if (updated && position != nullptr && s_offset_active.load(std::memory_order_relaxed) &&
            s_ai_eye_valid.load(std::memory_order_acquire))
        {
            position[0] = s_ai_eye_x.load(std::memory_order_relaxed);
            position[1] = s_ai_eye_y.load(std::memory_order_relaxed);
            position[2] = s_ai_eye_z.load(std::memory_order_relaxed);
        }
        return updated;
    }

    /**
     * @brief Reads a vtable slot and returns its target when it lies in the game image, else 0.
     */
    static uintptr_t read_image_vtable_slot(uintptr_t vtable, size_t slot, uintptr_t module_base, size_t module_size)
    {
        const DMK::Region image{DMK::Address{module_base}, module_size};
        const auto slot_value = DMK::memory::read<uintptr_t>(DMK::Address{vtable + slot * sizeof(uintptr_t)});
        return slot_value.has_value() && image.contains(DMK::Address{*slot_value}) ? *slot_value : 0;
    }

    /**
     * @brief Reads a vtable slot and returns its target when it lies in the game image and @p signature matches
     *        within its first @p window bytes, else 0, so a slot that no longer holds the expected function is
     *        refused rather than hooked or called.
     */
    static uintptr_t read_checked_vtable_slot(uintptr_t vtable, size_t slot, const DMK::scan::Pattern &signature,
                                              size_t window, uintptr_t module_base, size_t module_size)
    {
        const DMK::Region image{DMK::Address{module_base}, module_size};
        const uintptr_t target = read_image_vtable_slot(vtable, slot, module_base, module_size);
        return code_window_matches(target, signature, window, image) ? target : 0;
    }

    /**
     * @brief Hooks the camera observer's update, found through its RTTI vtable (no signature scan).
     * @details Best-effort: without it the camera still works, and NPCs just beyond the pulled-back camera's reach stay
     *          hidden in third person, as they would for the unmodded game with its view camera there. The slot's
     *          target must lie in the game image and still read the view camera (Aob::k_cameraObserverUpdateBody
     *          among its first instructions), so a patch that moves the slot leaves the hook uninstalled rather than
     *          hooking another function.
     */
    static void install_camera_observer_hook(uintptr_t module_base, size_t module_size, HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();
        const std::optional<std::uintptr_t> vtable = class_vtable(GameClass::CameraObserver);
        if (!vtable.has_value())
        {
            logger.warning("Camera: C_CameraObserver did not resolve; in third person the AI keeps judging NPCs from "
                           "the pulled-back camera");
            return;
        }
        const uintptr_t target = read_checked_vtable_slot(
            *vtable, Constants::CAMERA_OBSERVER_VTABLE_UPDATE_SLOT, Aob::k_cameraObserverUpdateBody,
            Aob::k_cameraObserverUpdateBodyWindow, module_base, module_size);
        if (target == 0)
        {
            logger.warning("Camera: C_CameraObserver slot {} is not an in-image update that reads the view camera; "
                           "camera-observer hook skipped",
                           Constants::CAMERA_OBSERVER_VTABLE_UPDATE_SLOT);
            return;
        }

        auto result = DMK::hook::inline_at(
            DMK::hook::InlineRequest{.name = "CameraObserverUpdate", .target = DMK::Address{target}},
            &detour_camera_observer_update);
        if (!result.has_value())
        {
            logger.warning("Camera: camera-observer hook failed ({}); in third person the AI keeps judging NPCs from "
                           "the pulled-back camera",
                           result.error().message());
            return;
        }
        // Publish the trampoline before enable() arms the patch, so the detour never sees a null original.
        s_camera_observer_update_original.store(result->original<CameraObserverUpdateFunc>(),
                                                std::memory_order_release);
        if (auto armed = hooks.push(std::move(*result)).enable(); !armed)
        {
            logger.warning("Camera: camera-observer hook could not be armed ({}); in third person the AI keeps judging "
                           "NPCs from the pulled-back camera",
                           armed.error().message());
            return;
        }
        logger.info("Camera: the AI camera observer follows the first-person eye in third person (C_CameraObserver "
                    "slot {} at {})",
                    Constants::CAMERA_OBSERVER_VTABLE_UPDATE_SLOT, DMK::format::format_address(target));
    }

    /**
     * @brief IsThirdPerson detour: answers "third person" to the free-roam locomotion action for the native turn.
     * @details Hot (every actor, several calls a frame each), so it only compares: the published player first, then
     *          the caller's return address against the two resolved call sites. The inline hook enters this detour
     *          with a jump, so _ReturnAddress() is the game caller's return address. Every other call, every other
     *          actor's included, goes to the original unchanged. Reads nothing through a pointer, so it needs no SEH
     *          frame.
     */
    static bool __fastcall detour_is_third_person(uintptr_t actor) noexcept
    {
        const DetourScope in_flight;
        if (actor != 0 && actor == s_native_turn_actor.load(std::memory_order_relaxed))
        {
            const uintptr_t ret = reinterpret_cast<uintptr_t>(_ReturnAddress());
            if (ret == s_lock_sync_return)
            {
                return true;
            }
            if (ret == s_turn_trigger_return && s_native_turn_trigger.load(std::memory_order_relaxed))
            {
                return true;
            }
        }
        const IsThirdPersonFunc original = s_is_third_person_original.load(std::memory_order_acquire);
        return original != nullptr && original(actor);
    }

    /**
     * @brief True when deciding to turn this frame would set the game's spin latch: the latch is clear, a turn
     *        fragment is still installed (state 1 or 2) and the gap's @p sign differs from the previous evaluation's
     *        non-zero sign. The latch then spins the body the OLD way, the long way round. @p action is the
     *        C_PlayerMovementAction the hook runs in; the field offsets come from resolve_turn_decision_layout. An
     *        unreadable field counts as a latch, so the turn waits.
     */
    static bool would_set_spin_latch(uintptr_t action, float sign) noexcept
    {
        const auto latched = DMK::memory::read<uint8_t>(DMK::Address{action + s_spin_latch_offset});
        const auto state = DMK::memory::read<int32_t>(DMK::Address{action + s_installed_state_offset});
        const auto last_sign = DMK::memory::read<float>(DMK::Address{action + s_last_sign_offset});
        if (!latched.has_value() || !state.has_value() || !last_sign.has_value())
        {
            return true;
        }
        return *latched == 0 && (*state == 1 || *state == 2) && *last_sign != 0.0f && *last_sign != sign;
    }

    /**
     * @brief Turn-decision mid hook: decides turn versus idle for the player through the flags `seta cl` reads.
     * @details Runs at the `seta cl` right after the game compared |angle| (xmm6) with its 35 degrees. The game
     *          reaches it only after IsThirdPerson answered true, so for the player only while the native turn is on
     *          with turns allowed. Leaves any other actor to the game. Sets the flags so that cl comes out as the
     *          mod's decision: CF and ZF clear gives cl = 1 (turn), ZF set gives cl = 0 (idle). xmm6 and xmm7 are left
     *          alone, so the animation's turn angle and playback speed, which the game derives next, are the game's
     *          own. DetourModKit owns the rundown of a mid-hook callback, so it needs no Pass. See s_turn_start_angle.
     */
    static void detour_turn_decision(DMK::hook::MidContext &ctx) noexcept
    {
        const uintptr_t actor = DMK::hook::gpr(ctx, DMK::hook::Gpr::Rbx);
        if (actor == 0 || actor != s_native_turn_actor.load(std::memory_order_relaxed))
        {
            return;
        }
        if (DMK::hook::gpr(ctx, DMK::hook::Gpr::R12) == 0)
        {
            // UpdatePending: the action is queued behind another one that moves him, and runs ComputeMoveState without
            // the turn-angle output pointer it keeps in r12. Left to the game, and not an idle decision.
            return;
        }
        const float gap = DMK::hook::xmm(ctx, 13).lane<float>(0); // signed look-minus-body angle, radians
        if (!std::isfinite(gap))
        {
            return;
        }
        const float gap_abs = std::fabs(gap);
        const float sign = gap < 0.0f ? -1.0f : 1.0f;
        const uint64_t now = GetTickCount64();
        const uint64_t last_decision = s_turn_decision_tick.exchange(now, std::memory_order_relaxed);
        const bool broke = s_turn_steps_hooked.load(std::memory_order_relaxed)
                               ? s_turn_decision_missed.exchange(false, std::memory_order_relaxed)
                               : now - last_decision > k_turn_decision_break_ms;
        if (broke)
        {
            // Back in the idle decision after a break: what came before no longer describes this turn or this rest.
            s_turn_continuing.store(false, std::memory_order_relaxed);
            s_turn_rest_gap.store(gap, std::memory_order_relaxed);
            s_turn_rest_since.store(now, std::memory_order_relaxed);
        }
        s_turn_decision_seen.store(true, std::memory_order_relaxed);

        // The look's rest, judged on the gap itself (see k_turn_rest_drift).
        if (std::fabs(gap - s_turn_rest_gap.load(std::memory_order_relaxed)) > k_turn_rest_drift)
        {
            s_turn_rest_gap.store(gap, std::memory_order_relaxed);
            s_turn_rest_since.store(now, std::memory_order_relaxed);
        }
        const float settle_delay = s_turn_settle_delay.load(std::memory_order_relaxed);
        const uint64_t rest_ms = now - s_turn_rest_since.load(std::memory_order_relaxed);
        const bool rested = settle_delay > 0.0f && static_cast<float>(rest_ms) >= settle_delay * 1000.0f;

        // A started turn continues until he faces the look. Otherwise a turn starts past the start angle, or past the
        // settle angle after the look rested.
        const bool wants_turn =
            s_turn_continuing.load(std::memory_order_relaxed)
                ? gap_abs > k_turn_finish_angle && sign == s_turn_last_sign.load(std::memory_order_relaxed)
                : gap_abs > s_turn_start_angle.load(std::memory_order_relaxed) ||
                      (gap_abs > k_turn_settle_angle && rested);
        const bool turn = wants_turn && !would_set_spin_latch(DMK::hook::gpr(ctx, DMK::hook::Gpr::Rdi), sign);
        s_turn_continuing.store(turn, std::memory_order_relaxed);
        s_turn_last_sign.store(sign, std::memory_order_relaxed);
        if (turn)
        {
            s_turn_decided_tick.store(now, std::memory_order_relaxed);
            s_turn_tail_frames.store(k_turn_step_tail_frames, std::memory_order_relaxed);
        }
        else if (const int tail = s_turn_tail_frames.load(std::memory_order_relaxed); tail > 0)
        {
            s_turn_tail_frames.store(tail - 1, std::memory_order_relaxed);
        }

        constexpr uintptr_t k_carry_flag = 0x1;
        constexpr uintptr_t k_zero_flag = 0x40;
        uintptr_t &cpu_flags = DMK::hook::flags(ctx);
        cpu_flags = turn ? (cpu_flags & ~(k_carry_flag | k_zero_flag)) : (cpu_flags | k_zero_flag);
    }

    /**
     * @brief Installs the turn-decision mid hook on the site resolve_turn_decision_layout proves around the trigger.
     * @details Best-effort: without it the native turn still works, with the game's own 35 degrees and the body
     *          resting about 35 degrees short of the look. The layout fixes the registers the hook reads (rbx, xmm13,
     *          rdi, r12), the instruction it sits on, and the action's spin-latch field offsets, which are written
     *          before the hook arms.
     * @return True when the hook is armed.
     */
    static bool install_turn_decision_hook(uintptr_t trigger_return, HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();
        const std::optional<TurnDecisionLayout> layout = resolve_turn_decision_layout(trigger_return);
        if (!layout.has_value())
        {
            logger.warning("Camera: turn decision hook skipped; turns rest about 35 degrees short of the look");
            return false;
        }
        const uintptr_t site = layout->site;
        s_spin_latch_offset = layout->spin_latch_offset;
        s_installed_state_offset = layout->installed_state_offset;
        s_last_sign_offset = layout->last_sign_offset;
        auto result = DMK::hook::mid_at(DMK::hook::MidRequest{.name = "TurnDecision", .target = DMK::Address{site}},
                                        detour_turn_decision);
        if (!result.has_value())
        {
            logger.warning("Camera: turn decision hook failed ({}); turns rest about 35 degrees short of the look",
                           result.error().message());
            return false;
        }
        if (auto armed = hooks.push(std::move(*result)).enable(); !armed)
        {
            logger.warning("Camera: turn decision hook could not be armed ({}); turns rest about 35 degrees short "
                           "of the look",
                           armed.error().message());
            return false;
        }
        logger.info("Camera: turn decision hooked at {} (turns finish facing the look)",
                    DMK::format::format_address(site));
        return true;
    }

    /**
     * @brief Movement detour: keeps a native turn step on the spot, so the body pivots without moving.
     * @details Drops the horizontal translation of the player's movement on a frame his movement action ran its
     *          idle/turn decision, from the first turn frame through the step tail after the last one (see
     *          s_turn_decision_seen). A frame without a decision ends the tail and marks a break for the decision hook.
     *          The rotation and the vertical part are left to the game, and so is an impulse.
     *          Every other character, and the player on any frame the action did not decide (walking, interactions,
     *          scripted animations), goes through untouched. Hot (every animated character each frame), so it only
     *          compares before calling the original.
     */
    static char __fastcall detour_phys_ent_movement(uintptr_t animchar, float *movement) noexcept
    {
        const DetourScope in_flight;
        if (animchar != 0 && animchar == s_player_animchar.load(std::memory_order_relaxed))
        {
            if (!s_turn_decision_seen.exchange(false, std::memory_order_relaxed))
            {
                // Something else drove this frame: a break for the decision, and the end of any step tail.
                s_turn_decision_missed.store(true, std::memory_order_relaxed);
                s_turn_tail_frames.store(0, std::memory_order_relaxed);
                s_turn_decided_tick.store(0, std::memory_order_relaxed);
            }
            else if (movement != nullptr &&
                     (s_turn_tail_frames.load(std::memory_order_relaxed) > 0 ||
                      GetTickCount64() - s_turn_decided_tick.load(std::memory_order_relaxed) < k_turn_step_tail_ms))
            {
                const auto type = DMK::memory::read<int32_t>(DMK::Address{animchar + s_movement_type_offset});
                if (type.has_value() && *type != Constants::ANIMATED_CHARACTER_MOVEMENT_IMPULSE)
                {
                    movement[4] = 0.0f; // translation x
                    movement[5] = 0.0f; // translation y
                }
            }
        }
        const UpdatePhysEntMovementFunc original = s_phys_ent_movement_original.load(std::memory_order_acquire);
        return original != nullptr ? original(animchar, movement) : 0;
    }

    /**
     * @brief Hooks CAnimatedCharacter::UpdatePhysicalEntityMovement to keep turn steps in place. Best-effort: without
     *        it a turn step moves the body 5-20 cm, which the still camera leaves slightly off centre.
     */
    static void install_turn_in_place_hook(HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();
        const uintptr_t target = gated_anchor_address(Feature::TurnSteps, AnchorId::PhysEntMovement);
        if (target == 0)
        {
            logger.warning("Camera: UpdatePhysicalEntityMovement did not resolve; turn steps move the body a little");
            return;
        }
        // The movement request type the detour reads to leave impulses alone, written before the hook arms.
        const std::optional<std::ptrdiff_t> type_offset = resolve_movement_type_offset(target);
        if (!type_offset.has_value())
        {
            logger.warning("Camera: UpdatePhysicalEntityMovement at {} is not the expected one; turn steps move the "
                           "body a little",
                           DMK::format::format_address(target));
            return;
        }
        s_movement_type_offset = *type_offset;
        auto result = DMK::hook::inline_at(
            DMK::hook::InlineRequest{.name = "UpdatePhysicalEntityMovement", .target = DMK::Address{target}},
            &detour_phys_ent_movement);
        if (!result.has_value())
        {
            logger.warning("Camera: UpdatePhysicalEntityMovement hook failed ({}); turn steps move the body a little",
                           result.error().message());
            return;
        }
        // Published before enable() arms the patch, and never cleared: an armed or pinned hook still routes through it.
        s_phys_ent_movement_original.store(result->original<UpdatePhysEntMovementFunc>(), std::memory_order_release);
        if (auto armed = hooks.push(std::move(*result)).enable(); !armed)
        {
            logger.warning("Camera: UpdatePhysicalEntityMovement hook could not be armed ({}); turn steps move "
                           "the body a little",
                           armed.error().message());
            return;
        }
        s_turn_steps_hooked.store(true, std::memory_order_relaxed);
        logger.info("Camera: turn steps kept in place (UpdatePhysicalEntityMovement at {})",
                    DMK::format::format_address(target));
    }

    /**
     * @brief Crouched animations mid hook on CAnimationSet::GetAnimIDByCRC (see
     *        Constants::CROUCHED_IDLE_PLAYER_ANIMATION).
     * @details While the native turn is on, a lookup of the player's crouched idle or crouched turn blend space gets
     *          its NPC twin, so the idle and the turns share one stance. The hook runs at the entry of the vtable
     *          slot's thunk, with the name hash in rdx. Every character's lookups pass through it, so it only compares.
     *          Any other hash goes to the game unchanged, and so does any lookup while the native turn is off (first
     *          person, or the feature switched off). A clip looks its animation up when it starts, so a crouched clip
     *          started in third person keeps that animation.
     */
    static void detour_crouched_animation(DMK::hook::MidContext &ctx) noexcept
    {
        if (s_native_turn_actor.load(std::memory_order_relaxed) == 0)
        {
            return;
        }
        uintptr_t &hash = DMK::hook::gpr(ctx, DMK::hook::Gpr::Rdx);
        for (const AnimationSwap &swap : s_crouched_swaps)
        {
            if (hash == swap.player)
            {
                hash = swap.npc;
                return;
            }
        }
    }

    /**
     * @brief Hooks CAnimationSet::GetAnimIDByCRC for the crouched animation swap (see detour_crouched_animation).
     *        Best-effort: without it a crouched right turn can throw the game's broken pose late in its clip.
     * @details CActionScope::InstallAnimation calls the slot with a clip's name hash, and AnchorId::AnimIdByCrcSlot
     *          reads the slot from that call. The slot comes from CAnimationSet's RTTI vtable. Its target must lie in
     *          the game image and still be the thunk to the name map lookup (Aob::k_animIdByCrcThunk). The hashes come
     *          from the name hash that CAnimationSet::GetAnimIDByName calls (AnchorId::AnimNameHashCall). That function
     *          must lie in the game image and still open as Aob::k_animNameHashBody before the mod calls it. All four
     *          hashes must be non-zero and distinct, and the idle and the turns swap together or not at all, because
     *          one without the other slides the body between the two stances.
     */
    static void install_crouched_animation_hook(uintptr_t module_base, size_t module_size, HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();
        const DMK::Region image{DMK::Address{module_base}, module_size};
        const std::optional<std::int64_t> slot_offset =
            gated_anchor_value(Feature::CrouchedAnimations, AnchorId::AnimIdByCrcSlot);
        const std::optional<std::uintptr_t> vtable = class_vtable(GameClass::AnimationSet);
        const uintptr_t lookup =
            slot_offset.has_value() && vtable.has_value()
                ? read_checked_vtable_slot(*vtable, static_cast<size_t>(*slot_offset) / sizeof(uintptr_t),
                                           Aob::k_animIdByCrcThunk, Aob::k_animIdByCrcThunk.max_match_length(),
                                           module_base, module_size)
                : 0;
        // The anchor proved that the call's target is a function entry in the image before this decode.
        uintptr_t hash_function = 0;
        if (const uintptr_t hash_call = gated_anchor_address(Feature::CrouchedAnimations, AnchorId::AnimNameHashCall);
            hash_call != 0)
        {
            if (const auto callee = DMK::scan::resolve_rip_relative(DMK::Address{hash_call}, 1, 5); callee)
            {
                hash_function = callee->raw();
            }
        }
        if (lookup == 0 || !code_window_matches(hash_function, Aob::k_animNameHashBody,
                                                Aob::k_animNameHashBody.max_match_length(), image))
        {
            logger.warning("Camera: crouched animation lookup not found; crouched right turns can show the game's "
                           "broken pose");
            return;
        }
        using NameHashFunc = std::uint64_t(__fastcall *)(const char *name, std::uint32_t length);
        const auto name_hash = reinterpret_cast<NameHashFunc>(hash_function);
        const auto hash_of = [name_hash](std::string_view name) -> std::uint64_t
        { return name_hash(name.data(), static_cast<std::uint32_t>(name.size())); };
        const std::array<AnimationSwap, 2> swaps{{
            {hash_of(Constants::CROUCHED_IDLE_PLAYER_ANIMATION), hash_of(Constants::CROUCHED_IDLE_NPC_ANIMATION)},
            {hash_of(Constants::CROUCHED_TURN_PLAYER_BLEND_SPACE), hash_of(Constants::CROUCHED_TURN_NPC_BLEND_SPACE)},
        }};
        const std::array<std::uint64_t, 4> hashes{swaps[0].player, swaps[0].npc, swaps[1].player, swaps[1].npc};
        const bool usable =
            std::ranges::none_of(hashes, [](std::uint64_t h) { return h == 0; }) &&
            std::ranges::all_of(hashes, [&hashes](std::uint64_t h) { return std::ranges::count(hashes, h) == 1; });
        if (!usable)
        {
            logger.warning("Camera: crouched animation hashes are not usable; crouched right turns can show the "
                           "game's broken pose");
            return;
        }
        s_crouched_swaps = swaps;
        auto result =
            DMK::hook::mid_at(DMK::hook::MidRequest{.name = "CrouchedAnimation", .target = DMK::Address{lookup}},
                              detour_crouched_animation);
        if (!result.has_value())
        {
            logger.warning("Camera: crouched animation hook failed ({}); crouched right turns can show the game's "
                           "broken pose",
                           result.error().message());
            return;
        }
        if (auto armed = hooks.push(std::move(*result)).enable(); !armed)
        {
            logger.warning("Camera: crouched animation hook could not be armed ({}); crouched right turns can show the "
                           "game's broken pose",
                           armed.error().message());
            return;
        }
        logger.debug("Camera: crouched idle hash {:#x} plays as {:#x}, crouched turn hash {:#x} plays as {:#x}",
                     swaps[0].player, swaps[0].npc, swaps[1].player, swaps[1].npc);
        logger.info("Camera: crouched animations hooked at {} (the crouched idle and turns play the NPC set)",
                    DMK::format::format_address(lookup));
    }

    /**
     * @brief Hooks IsThirdPerson for the native turn-in-place animation, found through the C_Player vtable.
     * @details Best-effort: without it the camera still works and the body follows the look, as in first person.
     *          The install requires all of these:
     *          - both locomotion call sites resolve (answering at only one of them either never turns or freezes the
     *            body);
     *          - the IsThirdPerson slot both call sites use resolves, and its target lies in the game image and still
     *            asks the active camera;
     *          - the camera-changed event (id, target/flags word, HandleEvent slot) resolves, and that slot's target
     *            dispatches the id. Without it a switch-off cannot reach an idle action, whose body then stays free of
     *            the look in first person until the player's next step.
     *          The trampoline pointer is never cleared: an armed hook, or one a failed teardown left installed, still
     *          routes calls through it. s_native_turn_armed is what switches the feature on, and only once the hook is
     *          armed.
     */
    static void install_native_turn_hook(uintptr_t module_base, size_t module_size, HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();
        const uintptr_t trigger_return = gated_anchor_address(Feature::NativeTurn, AnchorId::TurnTriggerReturn);
        const uintptr_t lock_sync_return = gated_anchor_address(Feature::NativeTurn, AnchorId::LockSyncReturn);
        if (trigger_return == 0 || lock_sync_return == 0)
        {
            logger.warning("Camera: native turn animation unavailable (locomotion call sites did not resolve: turn "
                           "trigger {}, LockBodyTurn sync {})",
                           DMK::format::format_address(trigger_return), DMK::format::format_address(lock_sync_return));
            return;
        }
        const std::optional<std::uintptr_t> player_vtable = class_vtable(GameClass::Player);
        if (!player_vtable.has_value())
        {
            logger.warning("Camera: native turn animation unavailable (C_Player did not resolve)");
            return;
        }
        // The vtable slots and the event are read from the game's code (see AnchorId::IsThirdPersonSlot onwards).
        const std::optional<std::int64_t> is_third_person_offset =
            gated_anchor_value(Feature::NativeTurn, AnchorId::IsThirdPersonSlot);
        const std::optional<std::int64_t> handle_event_offset =
            gated_anchor_value(Feature::NativeTurn, AnchorId::HandleEventSlot);
        const std::optional<std::int64_t> event_id = gated_anchor_value(Feature::NativeTurn, AnchorId::CameraEventId);
        const std::optional<std::int64_t> event_flags =
            gated_anchor_value(Feature::NativeTurn, AnchorId::CameraEventFlags);
        if (!is_third_person_offset || !handle_event_offset || !event_id || !event_flags)
        {
            logger.warning("Camera: native turn animation unavailable (C_Player's IsThirdPerson or HandleEvent slot, "
                           "or the camera-changed event, did not resolve from the game code)");
            return;
        }
        const size_t is_third_person_slot = static_cast<size_t>(*is_third_person_offset) / sizeof(uintptr_t);
        const size_t handle_event_slot = static_cast<size_t>(*handle_event_offset) / sizeof(uintptr_t);

        const uintptr_t target =
            read_checked_vtable_slot(*player_vtable, is_third_person_slot, Aob::k_isThirdPersonBody,
                                     Aob::k_isThirdPersonBodyWindow, module_base, module_size);
        if (target == 0)
        {
            logger.warning("Camera: native turn animation unavailable (C_Player slot {} is not IsThirdPerson)",
                           is_third_person_slot);
            return;
        }

        // HandleEvent dispatches the event id somewhere in its body. That dispatch, found with the resolved id, ties
        // the slot the sender calls to the function the id was read from.
        const uintptr_t handle_event =
            read_image_vtable_slot(*player_vtable, handle_event_slot, module_base, module_size);
        const bool dispatches =
            handle_event != 0 && dispatches_camera_event(handle_event, static_cast<uint8_t>(*event_id));
        s_player_handle_event = dispatches ? handle_event : 0;
        s_game_object_event_vtable = class_vtable(GameClass::GameObjectEvent).value_or(0);
        if (s_player_handle_event == 0 || s_game_object_event_vtable == 0)
        {
            logger.warning("Camera: native turn animation unavailable (camera-changed event did not resolve: "
                           "HandleEvent slot {} at {}, SGameObjectEvent {})",
                           handle_event_slot, DMK::format::format_address(s_player_handle_event),
                           DMK::format::format_address(s_game_object_event_vtable));
            return;
        }
        s_camera_changed_event_id = static_cast<uint32_t>(*event_id);
        s_camera_changed_event_flags = static_cast<uint32_t>(*event_flags);
        s_lock_body_turn_count_offset = static_cast<ptrdiff_t>(anchor_value(AnchorId::LockBodyTurnCount).value_or(0));

        // Written before the hook arms, so the detour never compares against a half-set pair.
        s_turn_trigger_return = trigger_return;
        s_lock_sync_return = lock_sync_return;

        auto result = DMK::hook::inline_at(
            DMK::hook::InlineRequest{.name = "IsThirdPerson", .target = DMK::Address{target}}, &detour_is_third_person);
        if (!result.has_value())
        {
            logger.warning("Camera: IsThirdPerson hook failed ({}); native turn animation unavailable",
                           result.error().message());
            return;
        }
        // Publish the trampoline before enable() arms the patch, so the detour never sees a null original.
        s_is_third_person_original.store(result->original<IsThirdPersonFunc>(), std::memory_order_release);
        if (auto armed = hooks.push(std::move(*result)).enable(); !armed)
        {
            // The detour may still be reachable (a backend error after the patch committed leaves the hook active), so
            // the trampoline stays; the feature simply stays off.
            logger.warning("Camera: IsThirdPerson hook could not be armed ({}); native turn animation unavailable",
                           armed.error().message());
            return;
        }
        s_native_turn_armed.store(true, std::memory_order_release);
        logger.info("Camera: native turn animation ready (IsThirdPerson slot {} at {}; turn trigger {}, LockBodyTurn "
                    "sync {}; camera-changed event {} through HandleEvent slot {})",
                    is_third_person_slot, DMK::format::format_address(target),
                    DMK::format::format_address(trigger_return), DMK::format::format_address(lock_sync_return),
                    s_camera_changed_event_id, handle_event_slot);

        // Lets turns finish facing the look instead of resting 35 degrees short, and keeps their steps on the spot.
        // The step hook keys on the decision hook's per-frame flag, so it goes in only with it. Best-effort.
        if (install_turn_decision_hook(trigger_return, hooks))
        {
            install_turn_in_place_hook(hooks);
        }
        install_crouched_animation_hook(module_base, module_size, hooks);
    }

    DMK::Result<void> initialize_camera(uintptr_t module_base, size_t module_size, HookSet &hooks)
    {
        DMK::Logger &logger = DMK::log();

        // Start in first-person (offset off) so the game looks normal on load; the view
        // hotkeys toggle/force the third-person offset on. The hooks below fast-path out
        // while the offset is off, so installing them unconditionally costs almost nothing.
        CameraState &cam = camera_state();
        cam.applying.store(false);
        cam.zoom_offset.store(0.0f);

        // Resolve g_env once (patch-resilient runtime AOB). The CView class identity is resolved by
        // init_game_types(), so nothing else is resolved here.
        s_genv_runtime = resolve_genv();

        // Resolve the engine ray helper for collision + aim convergence. Best-effort: on a miss
        // those features no-op (the camera still renders), so the result is intentionally discarded.
        (void)initialize_physics_raycast(module_base, module_size, s_genv_runtime);

        // Resolve the 3DEngine render-octree query so the camera can also collide with render-only roofs
        // (tent / awning canopy cloth) that carry no ray-collidable physics. Best-effort: a miss no-ops the
        // roof render clamp, so the result is intentionally discarded.
        (void)initialize_render_occlusion(module_base, module_size, s_genv_runtime);

        // The default hook::Options prologue policy is Fail: refuse an entry that leads with a breakpoint byte
        // (a cascade mis-resolution or a foreign int3 stub). A sibling mod's E9 jump-hook decodes as a
        // relocatable branch rather than a refusal, so layering still works. Every hook goes into the mod's hook
        // set, which shutdown() retires only after no game thread is left inside a detour.

        // Hook the camera frustum builder - the matrix-offset point; without it the feature does nothing, so
        // its Error propagates verbatim. The module-scoped cascade resolves to the function entry inside the game
        // image or returns 0, so no separate bounds check is needed here.
        const uintptr_t frustum_addr = gated_anchor_address(Feature::Camera, AnchorId::Frustum);
        if (frustum_addr == 0)
        {
            logger.error("Camera: frustum builder cascade unresolved");
            return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "camera_hook/frustum"});
        }
        DMK_TRY(frustum_hook, DMK::hook::inline_at(DMK::hook::InlineRequest{.name = "CameraFrustumBuild",
                                                                            .target = DMK::Address{frustum_addr}},
                                                   &detour_frustum_build));
        // Publish the trampoline and store the handle BEFORE enable() arms the patch. The detour then cannot observe a
        // null original on its first frame, and the set owns a hook whose arm fails with the patch live. The backend
        // allocates the trampoline at install, so it is readable off the still-disabled handle.
        s_frustum_build_original.store(frustum_hook.original<FrustumBuildFunc>(), std::memory_order_release);
        DMK_TRY_VOID(hooks.push(std::move(frustum_hook)).enable());

        // The head-visibility hook is best-effort: if it fails the camera still works,
        // the player just appears headless from behind, so a miss is a warning.
        const uintptr_t head_addr = gated_anchor_address(Feature::HeadVisibility, AnchorId::HeadVisibility);
        if (head_addr == 0)
        {
            logger.warning("Camera: Head visibility cascade unresolved; player may appear headless from behind");
        }
        else if (auto head_hook = DMK::hook::inline_at(
                     DMK::hook::InlineRequest{.name = "SetHeadVisibility", .target = DMK::Address{head_addr}},
                     &detour_set_head_visibility);
                 !head_hook)
        {
            logger.warning("Camera: Head visibility hook failed ({}); player may appear headless from behind",
                           head_hook.error().message());
        }
        else
        {
            s_set_head_visibility_original.store(head_hook->original<SetHeadVisibilityFunc>(),
                                                 std::memory_order_release);
            if (auto armed = hooks.push(std::move(*head_hook)).enable(); !armed)
            {
                logger.warning("Camera: Head visibility hook did not arm ({}); player may appear headless from "
                               "behind",
                               armed.error().message());
            }
        }

        // The input-dispatcher hook powers free-look orbit. Best-effort: a miss only disables orbit, the
        // offset camera still works. The detour is inert until the orbit key is held, so it is harmless when
        // free-look is unused. InputDispatch is a runtime AOB cascade (k_inputDispatchCandidates).
        const uintptr_t input_addr = gated_anchor_address(Feature::Orbit, AnchorId::InputDispatch);
        if (input_addr == 0)
        {
            logger.warning("Camera: Input dispatcher cascade unresolved; free-look orbit unavailable");
        }
        else if (auto input_hook = DMK::hook::inline_at(
                     DMK::hook::InlineRequest{.name = "CameraInputDispatch", .target = DMK::Address{input_addr}},
                     &detour_input_dispatch);
                 !input_hook)
        {
            logger.warning("Camera: Input dispatcher hook failed ({}); free-look orbit unavailable",
                           input_hook.error().message());
        }
        else
        {
            s_input_dispatch_original.store(input_hook->original<InputDispatchFunc>(), std::memory_order_release);
            if (auto armed = hooks.push(std::move(*input_hook)).enable(); !armed)
            {
                logger.warning("Camera: Input dispatcher hook did not arm ({}); free-look orbit unavailable",
                               armed.error().message());
            }
        }

        // Keep the AI judging which NPCs to update (and which to hide and pause) from the first-person eye while the
        // third-person offset renders. Best-effort, like the two hooks above.
        install_camera_observer_hook(module_base, module_size, hooks);

        // Let the body play the game's own turn-in-place animations while the third-person view is engaged.
        // Best-effort, like the hooks above.
        install_native_turn_hook(module_base, module_size, hooks);

        logger.info("Camera: Third-person camera hooks installed");
        return {};
    }

    void refresh_zoom_binding_tokens() noexcept
    {
        try
        {
            const DMK::input::Input &input = DMK::input::Input::instance();
            s_zoom_tokens.store(std::make_shared<const ZoomBindingTokens>(ZoomBindingTokens{
                                    .zoom_in = input.acquire_token(k_zoom_in_binding),
                                    .zoom_out = input.acquire_token(k_zoom_out_binding),
                                }),
                                std::memory_order_release);
        }
        catch (...)
        {
            // An allocation failure leaves no tokens published, so the render thread falls back to the name-based
            // query rather than reading a stale pair.
            s_zoom_tokens.store(nullptr, std::memory_order_release);
        }
    }

    void release_zoom_binding_tokens() noexcept
    {
        s_zoom_tokens.store(nullptr, std::memory_order_release);
    }

    bool release_camera_on_game_thread(std::chrono::milliseconds budget) noexcept
    {
        s_release_requested.store(true, std::memory_order_release);
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!s_release_done.load(std::memory_order_acquire))
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            Sleep(1);
        }
        return true;
    }

    void release_camera_overrides() noexcept
    {
        if (s_release_done.load(std::memory_order_acquire))
        {
            return;
        }
        // Fallback for a render thread that ran no frame within the hand-off budget (a load screen, a minimized
        // game). The keyboard turn-and-run override writes C_PlayerInput's move field every frame while it is
        // active and relies on the frustum detour's falling edge to hand the field back to the held keys; with
        // the detours retired there is no later frame, so run that falling edge here once (a no-op when the
        // override was not active). The head-visibility restore needs the engine's setter on its own thread, so
        // it is left to the engine's next transition. The body-turn and look-pitch writes are consume-once /
        // re-derived by the engine each frame, so they leave nothing behind. The native turn animation cannot be
        // switched off from here either (the locomotion action must not be driven from this thread): its hooks are
        // gone, so the action reads first person again and lets the body follow the look on its next idle start.
        apply_keyboard_move_override(false, 0.0f, 0.0f);
        if (s_native_turn_actor.exchange(0, std::memory_order_seq_cst) != 0)
        {
            DMK::log().warning("Shutdown: no game frame switched the native turn animation off; the body follows the "
                               "look again on the player's next step");
        }
        s_release_done.store(true, std::memory_order_release);
    }

} // namespace TPVCamera
