/**
 * @file tpv_camera.cpp
 * @brief Mod lifecycle: configuration, hooks, and input bindings.
 *
 * init() runs off the Windows loader lock and receives the live Session: on the DetourModKit bootstrap worker in
 * the release ASI, on the resident loader's control thread in the dev build. shutdown() is driven by the host's
 * detach path (dllmain.cpp in production, the logic DLL's Shutdown() export in the dev build) and must likewise
 * run off the loader lock. Hooks are caller-owned, and only the retirement of the hook set restores the patched
 * prologues.
 */

#include "tpv_camera.hpp"
#include "aob_resolver.hpp"
#include "config.hpp"
#include "constants.hpp"
#include "global_state.hpp"
#include "game_interface.hpp"
#include "offset_heal.hpp"
#include "rtti_types.hpp"
#include "version.hpp"
#include "hooks/camera_hook.hpp"
#include "hooks/ui_overlay_hooks.hpp"
#include "hooks/ui_menu_hooks.hpp"
#include "hooks/interaction_hook.hpp"
#include "hooks/player_onaction_hook.hpp"
#include "presets/preset_store.hpp"
#include "overlay/overlay.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace TPVCamera
{

    // The Session's binding scope, borrowed by init(). Every guard from DMK::config::press_combo / hold_combo
    // goes in here rather than a mod-owned vector: ~Session clears the scope FIRST (reverse insertion order) so
    // no callback can run during subsystem teardown, and a still-held hold-combo guard delivers one balancing
    // on_state_change(false) on clear, so a torn-down orbit hold cannot strand free-look on. On the
    // process-termination path Session::abandon() retains the guards and their captures instead of destroying
    // callables under the loader lock.
    static DMK::input::Scope *s_binding_scope = nullptr;

    // Every hook the mod installs. HookSet disables and destroys newest first, the only safe order for layered
    // patches on one target: the newer layer trampoline chains through the older jump, so the base must
    // be restored last. shutdown() retires it while the code pages are still mapped.
    static HookSet s_hooks;

    // Bound on the wait for the render thread to run the frame that hands the per-frame overrides back. Generous
    // enough for a low frame rate; a render thread that runs no frame at all (a load screen) falls back to a
    // control-thread release after the hooks retire.
    constexpr std::chrono::milliseconds k_release_budget{500};

    // Teardown progress, so a retried shutdown() resumes where the previous call stopped instead of repeating a
    // destructive step. s_worker_retained latches: a worker that kept its module reference stays a failure.
    static bool s_workers_stopped = false;
    static bool s_worker_retained = false;
    static bool s_teardown_complete = false;

    /**
     * @brief Returns true when a menu or overlay is up; the hotkeys ignore presses then.
     */
    [[nodiscard]] static bool is_ui_blocking_input()
    {
        // The preset overlay also blocks the camera hotkeys while it wants the keyboard/mouse, so a
        // press consumed by ImGui (e.g. typing a preset name) never doubles as a camera toggle.
        return is_game_menu_open() || overlay_state().active.load(std::memory_order_relaxed) || Overlay::wants_input();
    }

    /**
     * @brief Engages free-look orbit, seeding the orbit angles to the configured centre.
     * @details Seeds yaw/pitch to 0,0 (directly behind the player - the camera's resting offset) so a
     *          fresh engage always starts from the centred pose, then flips orbit_active on. Shared by
     *          the orbit toggle, the momentary hold binding, and the start-of-session auto-enable so
     *          "engage" means exactly the same thing at every entry point.
     */
    static void orbit_engage()
    {
        CameraState &cam = camera_state();
        cam.orbit_yaw.store(0.0f);
        cam.orbit_pitch.store(0.0f);
        cam.orbit_active.store(true);
    }

    /**
     * @brief Disengages free-look orbit and drops any stranded movement-input latch.
     * @details Turning orbit off clears no run-state on its own, so a latch left > 0 (a held-move
     *          release swallowed on a combat action-map swap) would re-trip the body-turn the next time
     *          orbit engages; player_onaction_reset() drops it here. Shared by the orbit toggle and the
     *          hold-release path.
     */
    static void orbit_disengage()
    {
        camera_state().orbit_active.store(false);
        const float stranded = player_onaction_reset();
        DMK::log().trace("Orbit: disengaged; cleared move-latch (had magnitude {:.2f})", stranded);
    }

    /**
     * @brief Resolves the game module base and size into TPVCamera::module_info().
     * @details DMK::Region::module_named is the library's module-range lookup; it reports the image's current extent
     *          and yields an empty region (size 0) when the module is not mapped, so it doubles as the presence
     *          test. Polls for up to ~3 seconds because an ASI can attach fractionally before WHGame.dll
     *          finishes mapping. Every scan and identity sweep in the mod is confined to the region this stores.
     */
    static DMK::Result<void> validate_game_module()
    {
        DMK::Logger &logger = DMK::log();

        DMK::Region image{};
        for (int i = 0; i < 30 && image.size == 0; ++i)
        {
            image = DMK::Region::module_named(Constants::MODULE_NAME);
            if (image.size == 0)
            {
                Sleep(100);
            }
        }

        if (image.size == 0)
        {
            logger.error("Failed to find module: {}", Constants::MODULE_NAME);
            return std::unexpected(DMK::Error{DMK::ErrorCode::ProcessMismatch, "TPVCamera::init/module"});
        }

        ModuleInfo &mod = module_info();
        mod.base = image.base.raw();
        mod.size = image.size;

        // The ASLR-insensitive PE build identity of the image every anchor and offset in this mod was authored
        // against. Logging it makes a patch-day report self-diagnosing: two logs whose identity tokens differ
        // are two different game builds (the Steam and GOG builds differ too), so an anchor miss below is drift
        // rather than a broken install.
        const DMK::scan::ImageIdentity identity = DMK::scan::image_identity(image);
        logger.info("Module validated: {} (Size: {} bytes, build {:#x})", DMK::format::format_address(mod.base),
                    mod.size, identity.token());
        return {};
    }

    /**
     * @brief Reports a best-effort subsystem that refused to initialize, keeping the mod running.
     * @details Each initialize_* returns the library's typed Error, so the degraded-feature line carries the
     *          ErrorCode and raising site rather than a stringified summary. Mandatory failures do not come
     *          through here; they propagate out of initialize_hooks() as the Error itself.
     * @param outcome The subsystem's result.
     * @param degraded What the mod loses when this subsystem is absent.
     */
    static void warn_if_degraded(const DMK::Result<void> &outcome, std::string_view degraded)
    {
        if (!outcome.has_value())
        {
            DMK::log().warning("{} ({})", degraded, outcome.error().message());
        }
    }

    /**
     * @brief Installs every game hook in dependency order.
     * @details The third-person camera hook is mandatory (it is the mod), so its Error propagates verbatim and
     *          init() fails with the library's own code. The view-flag interface and the menu/overlay
     *          suppression hooks degrade to a warning on failure: a missing view flag is treated as
     *          not-built-in-TPV, and missing menu/overlay detection only means the offset is not
     *          auto-suppressed under UI.
     */
    static DMK::Result<void> initialize_hooks()
    {
        DMK::Logger &logger = DMK::log();
        const ModuleInfo &mod = module_info();

        // Resolve every game-image anchor in one parallel pass, confined to the WHGame.dll image range,
        // before any module init reads its target. resolve_all_anchors() logs a per-anchor status, the feature
        // gates, and a quality summary. Each init below reads its addresses through its feature's gate, and a
        // mandatory feature whose gate failed fails the init that needs it.
        resolve_all_anchors(mod.base, mod.size);
        if (settings().export_signatures.load(std::memory_order_relaxed))
        {
            export_signatures();
        }

        // Build the cached class-vtable identities over the WHGame.dll image, before any detour is armed.
        // Every per-frame "is this vtable type X" test resolves through these, so the RTTI sweep happens
        // here once per type instead of on the render thread. Scoped to the game image on purpose: the DMK
        // default DMK::Region::host() is the game EXE, and every tracked type lives in WHGame.dll.
        init_game_types(DMK::Region{DMK::Address{mod.base}, mod.size});

        // Start the self-heal scheduler and register its groups before any detour is armed, so the very first
        // frame that resolves a base can already scan. Every group is gated on a live base the render path
        // publishes, so nothing is scanned until the corresponding object exists.
        start_offset_heal();

        // Global-context slot, read by the game-state camera walk.
        warn_if_degraded(initialize_game_interface(),
                         "Game interface initialization failed - game-state camera detection disabled");

        warn_if_degraded(initialize_ui_menu_hooks(s_hooks),
                         "UI Menu hooks initialization failed - menu suppression disabled");

        warn_if_degraded(initialize_ui_overlay_hooks(s_hooks),
                         "UI Overlay hooks initialization failed - overlay suppression disabled");

        warn_if_degraded(initialize_interaction_hook(s_hooks),
                         "Interaction hook initialization failed - camera-space interaction disabled");

        // Device-agnostic movement intent for the orbit move-detection. Best-effort: a miss falls back to
        // body-position speed, so the camera still works without it.
        warn_if_degraded(initialize_player_onaction_hook(s_hooks),
                         "Player OnAction hook initialization failed - orbit move-detection uses body speed");

        // The third-person camera itself. A hard failure here means the mod cannot function, so its Error is
        // returned unchanged rather than flattened into a mod-invented code.
        if (auto camera = initialize_camera(mod.base, mod.size, s_hooks); !camera.has_value())
        {
            logger.error("Critical: third-person camera hook installation failed ({}) - mod cannot function",
                         camera.error().message());
            return camera;
        }

        return {};
    }

    /**
     * @brief Registers the press bindings, fusing each INI key with its input binding via
     *        DMK::config::press_combo (through the section binder).
     * @details Each returned RAII guard goes into the Session scope so the callback stays live until
     *          teardown. All callbacks act on the camera state; rendering is
     *          additionally gated by should_apply_view(), so a state flip under a
     *          menu is harmless, but the toggles still ignore presses while a UI is up so
     *          the hotkey cannot fire from under an inventory/dialog.
     */
    static void register_press_bindings()
    {
        // Section binders, so each INI section name appears once here as well as in register_config_items().
        const DMK::config::SectionBinder settings_section = DMK::config::section("Settings");
        const DMK::config::SectionBinder orbit = DMK::config::section("Orbit");

        // Every press binding also gets its per-binding passthrough suppression key (<Key>.Consume), which
        // press_combo registers right after the binding it targets and before load(). Default false = the trigger
        // still reaches the game (current behaviour); set true to mask the combo's GAMEPAD trigger button so a
        // controller combo does not ALSO fire the game action bound to that button. Inert for keyboard binds
        // (DMK masks gamepad triggers only).
        auto add_press = [](const DMK::config::SectionBinder &section, std::string_view ini_key,
                            std::string_view log_name, std::string_view binding, std::function<void()> on_press,
                            std::string_view default_combo, bool consume_default = false)
        {
            s_binding_scope->add(
                section.press_combo(ini_key, log_name, binding, std::move(on_press), default_combo, consume_default));
        };

        // Enter/exit third-person at runtime. Default: F3, or hold LB + press RB on a controller.
        add_press(
            settings_section, "ToggleViewKey", "Toggle View Key", "toggle_view",
            []
            {
                if (is_ui_blocking_input())
                    return;
                CameraState &cam = camera_state();
                const bool new_state = !cam.applying.load();
                cam.applying.store(new_state);
                DMK::log().info("Third-person camera {}", new_state ? "ENABLED" : "DISABLED");
            },
            "F3,Gamepad_LB+Gamepad_RB");

        // Force first-person (turn the offset off). Always allowed: turning the camera off is safe.
        add_press(
            settings_section, "ForceFPVKey", "Force FPV Key", "force_fpv",
            []
            {
                camera_state().applying.store(false);
                DMK::log().info("Third-person camera DISABLED (force FPV)");
            },
            "");

        // Force third-person (turn the offset on).
        add_press(
            settings_section, "ForceTPVKey", "Force TPV Key", "force_tpv",
            []
            {
                if (is_ui_blocking_input())
                    return;
                camera_state().applying.store(true);
                DMK::log().info("Third-person camera ENABLED (force TPV)");
            },
            "");

        // Free-look orbit: press to TOGGLE on/off. While on, the mouse orbits the camera around the
        // character (the look stays put), you can still move and act, and starting to move turns the
        // character to face the camera direction. The momentary OrbitHoldKey below is the alternative
        // freelook style (hold to engage, release to return). OrbitExcludeState only auto-disables
        // free-look when you ENTER those states (e.g. mounting); it does not forbid manually turning it
        // back on there (Combat and Mount are excluded because free-look currently fights the game's own
        // camera control in those states).
        // Default: F4, or hold LB + click the left stick (LS) on a controller.
        add_press(
            orbit, "OrbitToggleKey", "Orbit Toggle Key", "orbit_toggle",
            []
            {
                if (is_ui_blocking_input())
                    return;
                const bool new_state = !camera_state().orbit_active.load();
                if (new_state)
                    orbit_engage();
                else
                    orbit_disengage();
                DMK::log().info("Orbit camera {}", new_state ? "ENABLED" : "DISABLED");
            },
            "F4,Gamepad_LB+Gamepad_LS",
            // Consume ON by default: the default controller bind clicks the left stick (LS), which is KCD1's
            // crouch toggle, so without this the orbit combo would also crouch. (The other press binds default
            // to no-consume; there is no known collision on them.)
            /*consume_default=*/true);

        // Open/close the preset-manager overlay. Always allowed (it is the mod's own UI), so it can be
        // opened over a game menu; the camera keeps rendering live so preset edits are visible.
        add_press(
            settings_section, "ToggleOverlayKey", "Toggle Overlay Key", "toggle_overlay", [] { Overlay::toggle(); },
            "Home");
    }

    /**
     * @brief Registers the hold bindings, fusing each INI key with its input hold binding via
     *        DMK::config::hold_combo (through the section binder).
     * @details Mirrors register_press_bindings: each returned guard goes into the Session scope so the
     *          callback stays live until teardown clears it. hold_combo carries the default combo, rebinds the
     *          live hold on every INI reload (Input::rebind), and - on the zoom triggers - registers the
     *          "<key>.Consume" passthrough-suppression flag. The zoom callbacks are empty: the frustum-builder
     *          detour queries their hold state each frame (through BindingTokens) to drive the follow distance.
     *          The orbit-hold callback instead engages/releases free-look on its key edges (momentary freelook),
     *          so nothing polls it per frame.
     */
    static void register_hold_bindings()
    {
        const DMK::config::SectionBinder camera = DMK::config::section("Camera");
        const DMK::config::SectionBinder orbit = DMK::config::section("Orbit");

        auto add_hold = [](const DMK::config::SectionBinder &section, std::string_view ini_key,
                           std::string_view log_name, std::string_view binding,
                           std::function<void(bool)> on_state_change, std::string_view default_combo,
                           std::optional<bool> consume)
        {
            s_binding_scope->add(
                section.hold_combo(ini_key, log_name, binding, std::move(on_state_change), default_combo, consume));
        };

        // Zoom hold keys. Defaults: LShift+PageUp / LShift+PageDown on keyboard, or hold LB + D-pad
        // up/down on a controller. Consume is on by default and toggled per binding from the INI
        // (ZoomInKey.Consume / ZoomOutKey.Consume): while enabled, DMK masks just the bound D-pad button out of
        // the XInput state the game reads, so the LB + D-pad up/down zoom combo does not also fire the game's
        // inventory/map shortcut as the gesture ends. Only the trigger button is masked (never the LB modifier,
        // and keyboard zoom is never affected), and the mask is latched to the physical D-pad release plus a
        // short grace window, so releasing LB a frame early cannot leak a bare D-pad press.
        add_hold(
            camera, "ZoomInKey", "Zoom In Key", k_zoom_in_binding, [](bool) {},
            "LShift+PageUp,Gamepad_LB+Gamepad_DpadUp", true);
        add_hold(
            camera, "ZoomOutKey", "Zoom Out Key", k_zoom_out_binding, [](bool) {},
            "LShift+PageDown,Gamepad_LB+Gamepad_DpadDown", true);

        // Momentary free-look (freelook, as in ArmA / DayZ / PUBG): hold OrbitHoldKey to engage the orbit
        // and release to return to the precise camera-aim view, separate from the press-to-toggle
        // OrbitToggleKey. Empty default so it is opt-in and never collides with a game key. The combo fires
        // the callback with true on the press edge and false on release; the returned guard also synthesizes
        // one balancing false if the hold is still held when teardown clears the guard, so a torn-down hold
        // cannot strand orbit on. s_engaged_by_hold records whether THIS hold turned orbit on, so the
        // release only undoes what the hold engaged: if orbit was already toggled on via OrbitToggleKey, the
        // press is a no-op and the release leaves it on. The engage is gated on the UI like the toggle; the
        // release is always honoured (even under UI) so a momentary orbit can never get stuck on. The guard
        // serializes its synthesized release against any in-flight poll-thread delivery, so the static needs
        // no lock.
        add_hold(
            orbit, "OrbitHoldKey", "Orbit Hold Key", k_orbit_hold_binding,
            [](bool pressed)
            {
                static bool s_engaged_by_hold = false;
                if (pressed)
                {
                    if (is_ui_blocking_input() || camera_state().orbit_active.load())
                        return;
                    orbit_engage();
                    s_engaged_by_hold = true;
                    DMK::log().info("Orbit camera ENABLED (hold)");
                }
                else if (s_engaged_by_hold)
                {
                    orbit_disengage();
                    s_engaged_by_hold = false;
                    DMK::log().info("Orbit camera DISABLED (hold released)");
                }
            },
            "", std::nullopt);
    }

    /**
     * @brief Starts the INI hot-reload watcher.
     * @details The bound setters re-apply the live settings on each reload. A reload that runs them also rebinds
     *          every key combo (Input::rebind) and re-applies each Consume flag, the only runtime reshapes of the
     *          input bindings. A reshape leaves the published zoom BindingTokens stale, so the callback republishes
     *          them on the watcher thread, a control-plane thread, before it reports the outcome.
     */
    static void enable_hot_reload(const DMK::config::Ini &ini)
    {
        DMK::Logger &logger = DMK::log();

        const DMK::config::AutoReloadStatus status =
            ini.enable_auto_reload(std::chrono::milliseconds{250},
                                   [](bool setters_ran)
                                   {
                                       refresh_zoom_binding_tokens();
                                       DMK::Logger &reload_logger = DMK::log();
                                       if (setters_ran)
                                           reload_logger.info("INI auto-reload: live settings applied");
                                       else
                                           reload_logger.info("INI auto-reload: no setter ran (file unchanged or "
                                                              "unreadable)");
                                   });

        if (status == DMK::config::AutoReloadStatus::Started)
            logger.info("INI hot-reload watcher started (250 ms debounce)");
        else
            logger.warning("INI hot-reload watcher not started (status {})", static_cast<int>(status));
    }

    DMK::Result<void> init(DMK::Session &session, const WheelHostTable *wheel_host)
    {
        DMK::Logger &logger = session.log();
        logger.info("----------------------------------------");
        Version::log_version_info();

        // Borrow the Session's binding scope. The Session outlives every registration below (the host destroys
        // it only after shutdown()), so the pointer stays valid for as long as any binding can be registered.
        s_binding_scope = &session.scope();

        // Register every config item, then the press and hold bindings, then load and log once through the
        // Session's INI handle. The bindings are all registered before load() so the INI key combos (and the
        // consume flags) apply to them during load.
        const DMK::config::Ini ini = session.ini();
        register_config_items();
        register_press_bindings();
        register_hold_bindings();
        ini.load(Constants::get_config_filename());
        ini.log_all();

        // Camera presets are user-owned and created automatically: the file is seeded from the embedded
        // factory defaults on first run, any missing built-in is re-added, and a corrupt file falls back to
        // those defaults, so loading never fails and never blocks the mod. The built-in state presets
        // (DEFAULT/COMBAT/AIMING/MOUNT/STEALTH) and any user presets feed the render-thread resolver via the
        // published binding table.
        const std::string presets_path =
            DMK::filesystem::get_runtime_directory_utf8() + "\\" + Constants::get_presets_filename();
        Presets::PresetStore::instance().load(presets_path);

        // Memory cache is a hot-path accelerator; a failure is non-fatal because the
        // readability checks fall back to direct VirtualQuery calls.
        if (DMK::memory::init_cache())
            logger.info("Memory cache system initialized");
        else
            logger.warning("Memory cache init failed; readability checks fall back to syscalls");

        // Each fallible step below returns the library's own typed Error rather than a mod-invented one, so
        // init()'s caller sees the real ErrorCode (and its category) instead of a stringified summary.
        DMK_TRY_VOID(validate_game_module());
        DMK_TRY_VOID(initialize_hooks());

        // The input engine drives every hotkey, so a failed start disables the mod's controls even though the
        // camera itself still renders. It is the final fallible step, so a failure never leaves a poller running
        // behind a failed init. A resident host means the wheel keepalive is booked against the LOADER, not this
        // module, so this image can still unmap on a reload. Without one, the local MessageHook backend is
        // correct: the release build is a single DLL that is never unloaded, and its keepalive is harmless there.
        DMK::input::Input::Settings input_settings{};
        if (wheel_host != nullptr)
        {
            input_settings.wheel_backend = DMK::input::Input::WheelBackend::ExternalHost;
            input_settings.wheel_host = wheel_host;
            input_settings.wheel_host_required = true;
        }
        if (auto started = session.input().start(input_settings); !started.has_value())
        {
            logger.error("Input engine failed to start ({}); hotkeys unavailable", started.error().message());
            return std::unexpected(started.error());
        }
        logger.info("Input engine started ({} wheel backend)",
                    wheel_host != nullptr ? "resident-host" : "local MessageHook");

        // The input engine now holds the bindings, so resolve the per-frame zoom tokens for the first time.
        refresh_zoom_binding_tokens();

        enable_hot_reload(ini);

        // Apply the start-of-session auto-enable flags (read once here). The view gate (should_apply_view)
        // still suppresses the offset under menus/loading, so an auto-enabled view simply eases in once
        // gameplay is reached. Orbit engages with the camera (it is gated on the offset being active),
        // starting from the centred 0,0 angle.
        {
            const LiveSettings &startup = settings();
            CameraState &cam = camera_state();
            if (startup.auto_enable_tpv.load(std::memory_order_relaxed))
            {
                cam.applying.store(true, std::memory_order_relaxed);
                logger.info("AutoEnableTPV: third-person camera enabled on start");
            }
            if (startup.auto_enable_orbit.load(std::memory_order_relaxed))
            {
                orbit_engage();
                logger.info("AutoEnableOrbit: free-look orbit enabled on start");
            }
        }

        // Start the preset-manager overlay (self-hosted ImGui on a DetourModKit StoppableWorker). A failure is
        // non-fatal: the camera and its hotkeys still work, only the in-game preset editor is unavailable.
        if (Overlay::start())
            logger.info("Preset overlay started (toggle with ToggleOverlayKey)");
        else
            logger.warning("Preset overlay failed to start; presets still apply from JSON/INI");

        logger.info("Initialization completed successfully");
        return {};
    }

    RetireStatus shutdown()
    {
        namespace diag = DMK::diagnostics;
        DMK::Logger &logger = DMK::log();

        if (s_teardown_complete)
        {
            return RetireStatus::Retired;
        }
        if (s_worker_retained)
        {
            return RetireStatus::Failed;
        }

        if (!s_workers_stopped)
        {
            logger.info("Shutdown: starting teardown");

            // Health snapshot taken while the hooks are still installed, because the teardown below removes them.
            // The anchor report is handed to collect() so the library rolls up the hook population and the anchor
            // quality rather than the mod counting them itself (the self-heal drift report is still being written
            // by the render thread here, so it is rolled up after the detours are proven quiescent).
            // total_intentional_leaks counts caller-requested leaks alongside the library's own defensive pins, so
            // read it as a delta across one operation rather than as an absolute.
            const diag::Snapshot snapshot = diag::collect({}, anchor_report());
            logger.info("Diagnostics: {} hooks ({} active, {} disabled), {} intentional leaks, {} module pins",
                        snapshot.hooks_total, snapshot.hooks_active, snapshot.hooks_disabled,
                        snapshot.total_intentional_leaks, snapshot.total_module_pins);
            logger.info("Diagnostics: anchors {}/{} resolved ({} failed, {} at risk)", snapshot.anchor_quality.resolved,
                        snapshot.anchor_quality.total, snapshot.anchor_quality.failed,
                        snapshot.anchor_quality.manual_at_risk);

            // Stop and join every worker first, so nothing on a mod-owned or watcher thread can run into the state
            // the teardown below retires. The INI watcher goes first (no reload setter runs during teardown), then
            // the overlay render worker (no UI mutation races the preset flush).
            DMK::config::disable_auto_reload();
            Overlay::stop();
            s_workers_stopped = true;

            // A StoppableWorker whose join failed (or that was detached under the loader lock) keeps its counted
            // module reference, and its body may still run. The watcher and the overlay are the only Worker-pinned
            // threads, so any remaining Worker pin is a worker that did not retire; latch it, because there is no
            // independent proof that its body exited later.
            if (diag::module_pin_count(diag::ModulePinReason::Worker) != 0)
            {
                s_worker_retained = true;
                logger.error("Shutdown: a worker did not join and keeps its module reference; the module must stay "
                             "mapped");
                return RetireStatus::Failed;
            }

            // Persist any unsaved preset edits.
            Presets::PresetStore::instance().flush();
        }

        // Hand the per-frame game overrides back to the engine BEFORE the route that owns them is retired: the
        // render thread restores the keyboard move field and the game's intended head visibility on its own thread,
        // then leaves the view to the game. Without a frame in time (a load screen, a minimized game) the move field
        // is handed back from this thread after the hooks retire instead.
        if (!release_camera_on_game_thread(k_release_budget))
        {
            logger.warning("Shutdown: the render thread ran no frame within {} ms; overrides are released after the "
                           "hooks retire",
                           k_release_budget.count());
        }

        // Hooks are caller-owned and the library removes none of them, so this is the only path that restores the
        // patched prologues. The set disables every hook, waits until no game thread is inside a detour, and only then
        // destroys the handles. Busy and Failed keep the hooks, and HookSet logs the reason.
        if (const RetireStatus hooks = s_hooks.retire(); hooks != RetireStatus::Retired)
        {
            return hooks;
        }

        // The detours are proven gone, so the state only they touched can be read and retired from this thread.
        // The self-heal drift report is final now, so roll it up before its scheduler goes.
        std::array<DMK::rtti::DriftEntry, 12> drift_report{};
        const std::size_t drift_count = offset_heal_drift_report(drift_report);
        const diag::Snapshot drift =
            diag::collect(std::span<const DMK::rtti::DriftEntry>(drift_report.data(), drift_count), {});
        logger.info("Diagnostics: self-heal {}/{} landmarks healed ({} failed)", drift.drift_healed, drift.drift_total,
                    drift.drift_failed);

        // Release whatever the render thread could not hand back itself (a no-op when it did), drop the published
        // zoom tokens, and destroy the render-thread-owned self-heal scheduler.
        release_camera_overrides();
        release_zoom_binding_tokens();
        stop_offset_heal();

        s_teardown_complete = true;
        logger.info("Shutdown: teardown complete");
        return RetireStatus::Retired;
    }

} // namespace TPVCamera
