/**
 * @file hooks/player_onaction_hook.cpp
 * @brief Hooks the KCD1 global action dispatcher and latches device-agnostic movement intent for the orbit.
 *
 * KCD2 hooked sub_1808EBEE4, found by a profiler string STRIPPED from retail KCD1 1.9.7. On KCD1 the same
 * dispatcher was located via the surviving "OnAction" Lua string -> sub_1801FF740, whose signature is
 * IDENTICAL to KCD2's: (this, const char** name, uint activation, float value). It runs the action-map
 * press/release/hold state machine and is the C++ source of Lua Player:OnAction, so every player action
 * (movement included) flows through it. The hook latches |value| per movement action and always forwards to
 * the original unchanged. Resolved at runtime by the ActionDispatch AOB cascade (the KCD2 AOB anchors a
 * profiler string stripped from KCD1).
 */

#include "hooks/player_onaction_hook.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <array>
#include <atomic>
#include <cmath>
#include <exception>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace TPVCamera
{

    // Global action dispatcher sub_1801FF740: fires once per action-map
    // action (the C++ source of Lua Player:OnAction) and returns a pointer we forward unchanged. action_name
    // points to a ref-counted C-string (the action name, e.g. "xi_movey"); value is the post-action-map axis
    // magnitude. activation is 1=press, 2=release, 4=hold.
    using ActionDispatchFunc = uintptr_t(__fastcall *)(uintptr_t self, const char **action_name,
                                                       unsigned int activation, float value);

    static ActionDispatchFunc s_action_dispatch_original = nullptr;
    static std::atomic<bool> s_available{false};

    // Movement action names whose value magnitude signals locomotion intent, across input devices and ALL
    // directions. The orbit move-detection keys on the LARGEST of these: it engages for forward, strafe and
    // reverse alike (only "is the player moving" matters; the engine applies the direction body-relative).
    // KEYBOARD uses the digital actions (value ~1 held, 0 released); GAMEPAD uses the signed analog left-stick
    // axes (value -1..1, magnitude taken). The probe below logs each distinct action name once (trace) so the
    // movement vocabulary can be confirmed from the trace log.
    static constexpr std::array<std::string_view, 8> k_move_actions = {
        "moveforward", "moveback",   "moveleft", "moveright", // keyboard digital (one per direction)
        "xi_movey",    "xi_movex",                            // gamepad left-stick (signed analog)
        "movement_y",  "movement_x",                          // named analog aliases (some device/rebind paths)
    };
    static constexpr size_t k_move_count = k_move_actions.size();

    // One latched |value| per movement action, written on the input thread and read on the render thread.
    // Value-initialized to 0; relaxed atomics suffice (a one-frame-stale signal is harmless).
    static std::atomic<float> s_move_values[k_move_count]{};

    // The same actions latched with their RAW SIGN preserved (parallel to s_move_values, same indices). The
    // move-detection uses the magnitudes above; the orbit "follow the stick" sprint uses these to reconstruct
    // the signed move vector (+forward / +right). Kept separate so the magnitude path is byte-for-byte unchanged.
    static std::atomic<float> s_move_signed[k_move_count]{};

    // The sprint action name and the activation code for a release event (1=press, 2=release, 4=hold). Sprint is
    // latched held on press/hold with a live value and cleared on release, so the body-turn can tell when KCD1's
    // forward-only sprint is driving locomotion.
    static constexpr std::string_view k_sprint_action = "sprint";
    static constexpr unsigned int k_activation_release = 2u;
    static std::atomic<bool> s_sprint_active{false};

    // Set by the camera detour (render thread) while the full-turn orbit redirect needs the gamepad move axes
    // collapsed to pure-forward (a backward-hemisphere stick). Read on the input thread; the collapse is gated
    // additionally on s_sprint_active so a stranded flag can never disable normal gamepad strafing/back-pedal
    // once sprint is released. See player_onaction_set_force_forward().
    static std::atomic<bool> s_force_forward_axes{false};

    // Activation code for an analog "value changed" event (eIS_Changed). Analog axes dispatch ONLY on change, so
    // a stick held at full deflection stops sending events -- the re-assert below uses this to re-inject the
    // collapsed value between real events.
    static constexpr unsigned int k_activation_changed = 8u;

    // Re-assert support for the gamepad full-turn collapse. The collapse rewrites the forwarded value PER EVENT,
    // but a held full-back stick stops sending xi_movey Changed events, so the engine keeps the stale backward
    // value and the char runs backward for up to ~1.6s despite force_fwd (the root cause). To keep the
    // collapse fresh, cache the engine CryString name of each gamepad analog axis (as it fires) and which axis the
    // current event was, then re-dispatch the OTHER axis on every move event -- the frequently-jittering lateral
    // axis drives the forward refresh. All touched only on the input thread (the detour) -> plain statics suffice.
    static const char *s_fwd_axis_name = nullptr; // engine CryString for xi_movey / movement_y
    static const char *s_lat_axis_name = nullptr; // engine CryString for xi_movex / movement_x
    static int s_last_move_axis = -1;             // this event: -1 none, 0 forward axis, 1 lateral axis
    static bool s_collapse_prev = false;          // collapse-active state on the previous event (falling-edge)

    // The player's wh::entitymodule::C_PlayerInput (the action-dispatcher's `self`), cached for the KEYBOARD
    // turn-and-run field write (camera_hook): its body-relative move input is at +0x58 (x/strafe) / +0x5C
    // (y/forward); writing (0,+1) overrides the held digital keys AND does not flip the HUD glyphs (it is a field
    // write, not an xi_* action). Written on the input thread, read on the render thread; consumer validates the
    // vtable before writing.
    static std::atomic<uintptr_t> s_player_input{0};

    bool player_onaction_available()
    {
        return s_available.load(std::memory_order_relaxed);
    }

    float player_onaction_move_magnitude()
    {
        // Largest movement-intent magnitude across all directions and devices: ~1.0 while moving, 0 when
        // released. The orbit move latch keys on this, so it engages for forward, strafe and reverse alike.
        float magnitude = 0.0f;
        for (size_t i = 0; i < k_move_count; ++i)
        {
            const float value = s_move_values[i].load(std::memory_order_relaxed);
            if (value > magnitude)
            {
                magnitude = value;
            }
        }
        return magnitude;
    }

    float player_onaction_reset()
    {
        // exchange() atomically reads-and-clears each slot, so a concurrent input-thread store of a fresh press
        // is never lost (it re-latches after this returns). The largest cleared value is returned so the caller
        // can tell whether the latch was genuinely stranded (the post-combat self-rotation guard).
        float had = 0.0f;
        for (size_t i = 0; i < k_move_count; ++i)
        {
            const float prev = s_move_values[i].exchange(0.0f, std::memory_order_relaxed);
            s_move_signed[i].store(0.0f, std::memory_order_relaxed); // keep the signed mirror in sync
            if (prev > had)
            {
                had = prev;
            }
        }
        // Drop the full-turn force-forward request on the same orbit-off/exclude/suppression edges that clear the
        // move latches, so the gamepad axes are never left collapsed after the orbit redirect disengages.
        s_force_forward_axes.store(false, std::memory_order_relaxed);
        return had;
    }

    bool player_onaction_gamepad_move_vector(float &forward, float &lateral)
    {
        // GAMEPAD analog axes ONLY (k_move_actions indices 4=xi_movey, 5=xi_movex, 6=movement_y, 7=movement_x).
        // The keyboard digital keys (moveforward/back/left/right) are intentionally NOT read here: the
        // follow-stick sprint redirect is a gamepad-only workaround (gamepad sprint forces forward-only, so the
        // body is faced at the stick direction). Keyboard sprint preserves the input direction and is handled by
        // the base body-turn; including keyboard here would double-apply the input on top of the body rotation
        // (world_move = body + input) and run the character backwards. Sign: +xi_movey forward,
        // +xi_movex right. The movement_* aliases cover device/rebind paths that report analog under those names.
        const float xi_movey = s_move_signed[4].load(std::memory_order_relaxed);
        const float xi_movex = s_move_signed[5].load(std::memory_order_relaxed);
        const float movement_y = s_move_signed[6].load(std::memory_order_relaxed);
        const float movement_x = s_move_signed[7].load(std::memory_order_relaxed);
        forward = (std::fabs(xi_movey) >= std::fabs(movement_y)) ? xi_movey : movement_y;
        lateral = (std::fabs(xi_movex) >= std::fabs(movement_x)) ? xi_movex : movement_x;
        return (forward * forward + lateral * lateral) > 1e-4f;
    }

    bool player_onaction_sprint_active()
    {
        return s_sprint_active.load(std::memory_order_relaxed);
    }

    void player_onaction_set_force_forward(bool on)
    {
        s_force_forward_axes.store(on, std::memory_order_relaxed);
    }

    uintptr_t player_onaction_player_input()
    {
        return s_player_input.load(std::memory_order_relaxed);
    }

    bool player_onaction_keyboard_move_vector(float &forward, float &lateral)
    {
        // KEYBOARD digital move keys only (k_move_actions indices 0=moveforward, 1=moveback, 2=moveleft,
        // 3=moveright). Digital values are ~1 while held, so the net vector is forward = moveforward - moveback,
        // lateral = moveright - moveleft (+lateral is right, matching the engine's +0x58 x sign). The gamepad
        // analog axes (indices 4..7) are deliberately excluded -- they use the gamepad collapse path.
        const float fwd = s_move_signed[0].load(std::memory_order_relaxed) - s_move_signed[1].load(std::memory_order_relaxed);
        const float lat = s_move_signed[3].load(std::memory_order_relaxed) - s_move_signed[2].load(std::memory_order_relaxed);
        forward = fwd;
        lateral = lat;
        return (fwd * fwd + lat * lat) > 1e-4f;
    }

    /**
     * @brief Trace-only vocabulary probe: logs each distinct action name once (with its activation + value) so
     *        the on-foot movement vocabulary can be confirmed from the trace log. Inert unless trace is on; the dedup list is
     *        touched only here, on the input thread, under its own mutex.
     */
    static void maybe_log_action_name(const char *name, unsigned int activation, float value)
    {
        DMK::Logger &logger = DMK::Logger::get_instance();
        if (!logger.is_enabled(DMK::LogLevel::Trace))
        {
            return;
        }
        static std::mutex seen_mutex;
        static std::vector<std::string> seen;
        const std::lock_guard<std::mutex> lock(seen_mutex);
        for (const std::string &entry : seen)
        {
            if (entry == name)
            {
                return;
            }
        }
        seen.emplace_back(name);
        logger.trace("PlayerOnAction: action '{}' activation={} value={:.2f}", name, activation, value);
    }

    /**
     * @brief Latches the movement axes from one action event. Separated from the SEH wrapper so this frame
     *        holds no unwinding objects; the engine-owned string reads are screened before use.
     */
    static float capture_movement_input(const char **action_name, unsigned int activation, float value)
    {
        s_last_move_axis = -1; // default: not a gamepad move axis this event (drives the re-assert decision below)
        if (action_name == nullptr || !DMK::Memory::plausible_userspace_ptr(reinterpret_cast<uintptr_t>(action_name)))
        {
            return value;
        }
        const char *name = *action_name;
        if (name == nullptr || !DMK::Memory::plausible_userspace_ptr(reinterpret_cast<uintptr_t>(name)))
        {
            return value;
        }

        maybe_log_action_name(name, activation, value);

        // Latch this action's magnitude (|value|) into its own slot; player_onaction_move_magnitude takes the
        // largest across slots. Each action owns a slot, so an independent release (value 0) does not clobber
        // another still-held source (keyboard + stick). Digital keys report ~1 held / 0 released; an analog axis
        // reports a signed deflection, so its magnitude is taken regardless of direction.
        const std::string_view name_view(name);

        // Sprint latch: held on press/hold with a live value, cleared on release. The orbit "follow the stick"
        // sprint reads this so it only re-faces the body at the move direction while sprint is actually driving
        // the (forward-only) locomotion. Sprint is not a movement axis, so it does not feed the loop below.
        if (name_view == k_sprint_action)
        {
            const bool held = (activation != k_activation_release) && (std::fabs(value) > 0.5f);
            s_sprint_active.store(held, std::memory_order_relaxed);
            return value;
        }

        // Full-turn orbit redirect (backward hemisphere): collapse the GAMEPAD move axes to pure-forward so the
        // forced-forward sprint runs along the body's faced (stick) direction instead of the raw backward input,
        // which would sprint AWAY from the camera. Only when the camera detour asks for it AND sprint is actually
        // held -- the sprint gate is the failsafe against a stranded flag disabling normal strafing/back-pedal.
        // The signed latch below stays the REAL stick (the camera detour reads it to set the body-turn angle), so
        // only the value forwarded to the engine is rewritten -- no feedback into the angle.
        const bool collapse = s_force_forward_axes.load(std::memory_order_relaxed) &&
                              s_sprint_active.load(std::memory_order_relaxed);
        float forward_value = value;

        for (size_t i = 0; i < k_move_count; ++i)
        {
            if (k_move_actions[i] == name_view)
            {
                s_move_values[i].store(std::fabs(value), std::memory_order_relaxed); // magnitude (move-detect)
                s_move_signed[i].store(value, std::memory_order_relaxed);             // signed (follow-stick vector)
                // Cache the engine CryString + axis kind for the GAMEPAD analog axes only (4=xi_movey /
                // 6=movement_y forward, 5=xi_movex / 7=movement_x lateral) so the detour can re-assert the OTHER
                // axis between change-only events. Keyboard digital keys (0..3) are never collapsed or cached.
                // Forward axis -> full forward, lateral -> zero (a pure forward run in the faced direction).
                if (i == 4 || i == 6)
                {
                    s_fwd_axis_name = name;
                    s_last_move_axis = 0;
                    if (collapse)
                    {
                        forward_value = 1.0f;
                    }
                }
                else if (i == 5 || i == 7)
                {
                    s_lat_axis_name = name;
                    s_last_move_axis = 1;
                    if (collapse)
                    {
                        forward_value = 0.0f;
                    }
                }
                break;
            }
        }
        return forward_value;
    }

    /**
     * @brief Action-dispatcher detour: latch movement intent, then always forward to the original so the game's
     *        action handling (and Lua Player:OnAction) is untouched. A fault while reading the event is
     *        swallowed and the original still runs.
     */
    static uintptr_t __fastcall detour_action_dispatch(uintptr_t self, const char **action_name,
                                                       unsigned int activation, float value)
    {
        // forward_value is the value passed on to the engine: identical to the latched input except while the
        // full-turn orbit redirect is collapsing the gamepad move axes to pure-forward (see capture_movement_input).
        // A fault while reading the event leaves it at the original value, so the original still runs unchanged.
        float forward_value = value;
        bool collapse_active = false;
        int move_axis = -1;
        __try
        {
            forward_value = capture_movement_input(action_name, activation, value);
            collapse_active = s_force_forward_axes.load(std::memory_order_relaxed) &&
                              s_sprint_active.load(std::memory_order_relaxed);
            move_axis = s_last_move_axis;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            forward_value = value;
            collapse_active = false;
            move_axis = -1;
        }

        const uintptr_t ret =
            s_action_dispatch_original ? s_action_dispatch_original(self, action_name, activation, forward_value) : 0;

        // Keep the collapse FRESH across the change-only analog axes. A stick held at full deflection stops sending
        // its Changed events, so without this the engine retains the stale value -- a full-back stick keeps running
        // backward despite force_fwd (the cause of the few-second wrong-direction window). On each
        // move event re-dispatch the OTHER axis (the frequently-jittering lateral axis thus refreshes forward); on
        // the collapse falling edge push the REAL stick once so a steady stick does not strand the forced-forward
        // value (e.g. sprint released while still holding back must back-pedal). Re-dispatch goes straight to the
        // original (no detour re-entry); engine-owned name reads -> guarded.
        if (s_action_dispatch_original)
        {
            __try
            {
                if (collapse_active && move_axis == 1 && s_fwd_axis_name != nullptr)
                {
                    const char *fwd = s_fwd_axis_name; // lateral event -> refresh forward axis to full forward
                    s_action_dispatch_original(self, &fwd, k_activation_changed, 1.0f);
                }
                else if (collapse_active && move_axis == 0 && s_lat_axis_name != nullptr)
                {
                    const char *lat = s_lat_axis_name; // forward event -> refresh lateral axis to zero
                    s_action_dispatch_original(self, &lat, k_activation_changed, 0.0f);
                }
                else if (!collapse_active && s_collapse_prev)
                {
                    float real_fwd = 0.0f;
                    float real_lat = 0.0f;
                    (void)player_onaction_gamepad_move_vector(real_fwd, real_lat); // latched REAL stick (pre-collapse)
                    if (s_fwd_axis_name != nullptr)
                    {
                        const char *fwd = s_fwd_axis_name;
                        s_action_dispatch_original(self, &fwd, k_activation_changed, real_fwd);
                    }
                    if (s_lat_axis_name != nullptr)
                    {
                        const char *lat = s_lat_axis_name;
                        s_action_dispatch_original(self, &lat, k_activation_changed, real_lat);
                    }
                }
                s_collapse_prev = collapse_active;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }

        // Cache the dispatcher's `self` = the player's wh::entitymodule::C_PlayerInput. The keyboard turn-and-run
        // writes its body-relative move-input field (see camera_hook); the consumer validates the vtable before
        // writing. self is always the player C_PlayerInput (the dispatcher is its method), so this is unconditional.
        s_player_input.store(self, std::memory_order_relaxed);
        return ret;
    }

    bool initialize_player_onaction_hook()
    {
        DMK::Logger &logger = DMK::Logger::get_instance();
        try
        {
            const uintptr_t module_base = module_info().base;
            if (module_base == 0)
            {
                logger.warning("PlayerOnAction: module base unknown; orbit move-detection disabled");
                return false;
            }
            // ActionDispatch is a runtime AOB cascade (k_actionDispatchCandidates); a total cascade miss fails
            // closed (orbit move-detection disabled).
            const uintptr_t dispatch_addr = anchor_address(AnchorId::ActionDispatch);
            if (dispatch_addr == 0)
            {
                logger.warning("PlayerOnAction: action dispatcher cascade unresolved; orbit move-detection off");
                return false;
            }

            DMK::HookManager &hook_manager = DMK::HookManager::get_instance();
            // Fail closed if the resolved entry leads with a call/breakpoint byte (a sibling mod's E9 jump hook
            // does not trip this, so layering still works).
            const DMK::HookConfig hook_config{.prologue_policy = DMK::InlineProloguePolicy::Fail};
            auto result = hook_manager.create_inline_hook(
                "PlayerOnActionDispatch", dispatch_addr, reinterpret_cast<void *>(detour_action_dispatch),
                reinterpret_cast<void **>(&s_action_dispatch_original), hook_config);

            if (!result.has_value())
            {
                logger.warning("PlayerOnAction: action dispatcher hook failed ({}); orbit move-detection disabled",
                               DMK::Hook::error_to_string(result.error()));
                return false;
            }

            s_available.store(true, std::memory_order_relaxed);
            logger.info("PlayerOnAction: hooked action dispatcher at {} (orbit move-detection enabled)",
                        DMK::Format::format_address(dispatch_addr));
            return true;
        }
        catch (const std::exception &e)
        {
            logger.error("PlayerOnAction: initialization failed: {}", e.what());
            return false;
        }
    }

} // namespace TPVCamera
