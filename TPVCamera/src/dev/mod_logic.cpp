/**
 * @file dev/mod_logic.cpp
 * @brief The hot-reloaded half of the dev build: one generation of mod logic behind a C ABI.
 *
 * @details The resident loader owns the process; this DLL owns one generation. The loader calls Init() after
 *          LoadLibrary on a uniquely named staged copy and Shutdown() before it releases or retains that copy.
 *          There is no DllMain bootstrap on this path, so Init() owns the Session directly and Shutdown() drops
 *          it. Only compiled when KCD1_TPVCAMERA_DEV_BUILD is defined.
 *
 *          Shutdown() follows DetourModKit's logic-DLL shutdown order (docs/guides/hot-reload):
 *            1. stop and join every mod worker (the INI watcher, the overlay render worker), then check that
 *               none kept its module reference;
 *            2-5. retire the game-thread detours through the DetourGate: disable every hook, prove the game
 *               callers quiescent, revert the per-frame game-memory overrides, then destroy the hooks
 *               newest-first and latch any backend DetourModKit had to retain (TPVCamera::shutdown());
 *            6. prepare_logic_dll_unload_all() and require SafeToUnload;
 *            7. destroy the Session;
 *            8. read the module-pin and leak counters and compute the retirement verdict.
 *
 *          Its result is tri-state: zero refuses retirement (the image must stay mapped and Init() is never run
 *          on it again), KCD1_TPVCAMERA_RELOAD_OK permits the loader to release its reference, and
 *          KCD1_TPVCAMERA_RELOAD_RETAINED means the generation retired but left resources (a retained XInput
 *          interception, a permanent reaper reference) that need the loader to keep its reference.
 */

#ifdef KCD1_TPVCAMERA_DEV_BUILD

#include "constants.hpp"
#include "protocol.h"
#include "tpv_camera.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <format>
#include <optional>
#include <string>

namespace
{
    namespace diag = DMK::diagnostics;

    /// The live Session for this generation. Empty before Init() and after a completed Shutdown().
    std::optional<DMK::Session> s_session;

    /// This generation's id from the loader's Init request. Names the profile export of a profiling build.
    std::uint64_t s_generation_id = 0;

    /// The loader-visible build identity, formatted once by Init() (see Revision()).
    char s_revision[96] = "unknown";

    // Latched refusals. A worker that kept its module reference or a hook backend DetourModKit retained can still
    // run code in this image, and there is no later proof that it stopped, so every later Shutdown() refuses too
    // and Init() never runs on this image again.
    bool s_worker_retained = false;
    bool s_hook_retained = false;

    /**
     * @brief Writes this generation's profiler samples to KCD1_TPVCamera_profile_genNNNN.json beside the log.
     * @details A profiling build (-DDMK_ENABLE_PROFILING=ON) records every DMK_PROFILE_SCOPE into a ring owned by
     *          the DetourModKit instance linked into THIS image, so the samples are generation-local and gone once
     *          the image unmaps: the hot-reload guide's rule is to export them before Shutdown() retires it.
     *          Exporting once per generation leaves one Chrome Tracing file per generation (chrome://tracing,
     *          ui.perfetto.dev). Runs on the loader's control thread, off the loader lock, which the export
     *          requires because it allocates and writes a file. A failure is contained so a diagnostics export
     *          can never keep Shutdown() from retiring the generation.
     */
    void export_profile() noexcept
    {
#ifdef DMK_ENABLE_PROFILING
        try
        {
            const std::string path =
                std::format("{}\\{}_profile_gen{:04}.json", DMK::filesystem::get_runtime_directory_utf8(),
                            Constants::MOD_NAME, s_generation_id);
            const bool written = DMK::Profiler::get_instance().export_to_file(path);
            (void)DMK::log().try_log(written ? DMK::LogLevel::Info : DMK::LogLevel::Warning,
                                     "[DEV] Profile export to {} {}", path, written ? "written" : "failed");
        }
        catch (...)
        {
            (void)DMK::log().log_noexcept(DMK::LogLevel::Warning, "[DEV] Profile export threw; skipped");
        }
#endif
    }

    /**
     * @brief Computes the retirement verdict once the Session is gone.
     * @details Pin and leak counters stay readable after ~Session. A nonzero count does not prove the leaked
     *          resource pins this image, so any count retains the loader's reference rather than releasing it.
     */
    [[nodiscard]] std::uint32_t retirement_verdict() noexcept
    {
        if (s_worker_retained || s_hook_retained)
        {
            return 0;
        }
        const std::size_t pins = diag::total_module_pins();
        const std::size_t leaks = diag::total_intentional_leaks();
        const bool retained = pins != 0 || leaks != 0;
        if (retained)
        {
            char line[160];
            (void)std::snprintf(line, sizeof(line),
                                "[KCD1_TPVCamera][DEV] generation retained: %zu module pin(s) (XInput keepalive %zu), "
                                "%zu intentional leak(s)\n",
                                pins, diag::module_pin_count(diag::ModulePinReason::XInputKeepalive), leaks);
            OutputDebugStringA(line);
        }
        return retained ? KCD1_TPVCAMERA_RELOAD_RETAINED : KCD1_TPVCAMERA_RELOAD_OK;
    }

    /**
     * @brief Runs the shutdown order against the live Session.
     * @return The tri-state Shutdown() result.
     * @details Shared by Shutdown() and the Init() failure path, so a partially published generation is retired
     *          through exactly the same proofs, typed drain included, as a live one.
     */
    [[nodiscard]] std::uint32_t retire_generation() noexcept
    {
        if (!s_session.has_value())
        {
            return retirement_verdict();
        }

        // Steps 1-5: workers, detours, overrides, hooks. A refusal leaves the Session and its bindings live and the
        // image mapped; a retry resumes where this call stopped.
        const TPVCamera::ShutdownVerdict verdict = TPVCamera::shutdown();
        switch (verdict)
        {
        case TPVCamera::ShutdownVerdict::Retired:
            break;
        case TPVCamera::ShutdownVerdict::WorkerRetained:
            s_worker_retained = true;
            return 0;
        case TPVCamera::ShutdownVerdict::HookRetained:
            s_hook_retained = true;
            return 0;
        case TPVCamera::ShutdownVerdict::CallersActive:
            (void)DMK::log().try_log(DMK::LogLevel::Warning,
                                     "[DEV] Shutdown refused: a game thread was still in a detour; retry later");
            return 0;
        }

        // Step 6: the library's own drain. It retires every input binding and config setter DMK still owns and
        // delivers a held hold-combo's balancing edge while this image is still mapped, so no callback body can be
        // entered afterwards.
        const DMK::LogicDllUnloadStatus drain = DMK::prepare_logic_dll_unload_all();
        if (drain != DMK::LogicDllUnloadStatus::SafeToUnload)
        {
            (void)DMK::log().try_log(DMK::LogLevel::Error,
                                     "[DEV] Drain refused unload (status {}); module stays mapped",
                                     static_cast<int>(drain));
            return 0;
        }

        // Step 7: the ordered DetourModKit teardown. The XInput interception can decide to retain here (a rival
        // writer such as the Steam overlay owns the XInputGetState prologue), which is why the verdict follows it.
        s_session.reset();

        // Step 8.
        return retirement_verdict();
    }
} // namespace

extern "C"
{
    /**
     * @brief Reports which bytes the loader actually mapped.
     * @details The identity is this image's own PE build fingerprint (link timestamp, image size, and section
     *          layout, via DetourModKit's scan::image_identity), which changes on every relink, plus the compile
     *          stamp of this translation unit. Formatted once by Init(); "unknown" before that.
     */
    __declspec(dllexport) const char *DMK_WHEELHOST_CALL Revision() noexcept
    {
        return s_revision;
    }

    /**
     * @brief Starts one generation with the loader's resident wheel host.
     * @param request The versioned request. Its host table remains valid for the process lifetime.
     * @return KCD1_TPVCAMERA_RELOAD_OK when the generation is live, or zero after the failure path retired it.
     * @note The loader calls this from its control thread, off the loader lock.
     */
    __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL Init(const Kcd1TpvReloadInitRequest *request) noexcept
    {
        // Validate the whole request before touching a field: a stale generation left in the deploy directory
        // must fail loudly rather than read through a shifted layout. A retired or refused image is never
        // initialized again: its globals and function-local statics still hold the previous generation's state.
        if (request == nullptr || request->struct_size < sizeof(Kcd1TpvReloadInitRequest) ||
            request->abi_version != KCD1_TPVCAMERA_RELOAD_ABI_VERSION || request->generation_id == 0 ||
            request->wheel_host == nullptr || request->expected_host_identity == 0 ||
            request->wheel_host->host_identity != request->expected_host_identity || s_session.has_value() ||
            s_generation_id != 0 || s_worker_retained || s_hook_retained)
        {
            OutputDebugStringA("[KCD1_TPVCamera][DEV] Init rejected an invalid, foreign, or repeated request\n");
            return 0;
        }
        s_generation_id = request->generation_id;

        // The loader calls this through a C function pointer, so an exception must never unwind across the
        // boundary. Guard the whole body; any failure retires the partial generation through the same proofs as
        // Shutdown().
        try
        {
            DMK::AsyncLoggerConfig async_cfg;
            async_cfg.overflow_policy = DMK::OverflowPolicy::SyncFallback;

            // LogOpenMode::Append is what keeps a reload diagnosable. Under the default Truncate, this
            // generation's first sink open erases the PREVIOUS generation's teardown records - including the
            // XInput retention warning naming which writer owns the prologue, which is the only line that
            // explains a retained image. The loader truncates the log once per game run instead.
            auto started = DMK::Session::start(DMK::ModInfo{
                .name = Constants::MOD_NAME,
                .log_file = Constants::LOG_FILE_NAME,
                .game_process_name = "",
                .instance_mutex_prefix = Constants::INSTANCE_MUTEX_PREFIX,
                .log = async_cfg,
                .log_open_mode = DMK::LogOpenMode::Append,
                // Keep the [file:line] stamp only on Trace, matching the release build.
                .log_source_stamp_mode = DMK::LogSourceStampMode::at_or_below(DMK::LogLevel::Trace),
            });
            if (!started.has_value())
            {
                OutputDebugStringA("[KCD1_TPVCamera][DEV] Session::start failed\n");
                return 0;
            }
            s_session.emplace(std::move(*started));

            const DMK::scan::ImageIdentity identity = DMK::scan::image_identity(DMK::Region::own());
            (void)std::snprintf(s_revision, sizeof(s_revision), "build %016llx (%s %s)",
                                static_cast<unsigned long long>(identity.token()), __DATE__, __TIME__);
            DMK::log().info("[DEV] Init generation {} - {}", request->generation_id, s_revision);

            // The resident host table travels all the way to Input::start, so the wheel keepalive is booked
            // against the loader instead of this image.
            if (auto ready = TPVCamera::init(*s_session, request->wheel_host); !ready.has_value())
            {
                DMK::log().error("[DEV] TPVCamera initialization FAILED ({})", ready.error().message());
                (void)retire_generation();
                return 0;
            }
            return KCD1_TPVCAMERA_RELOAD_OK;
        }
        catch (...)
        {
            OutputDebugStringA("[KCD1_TPVCamera][DEV] Init threw an exception; retiring the partial generation\n");
            (void)retire_generation();
            return 0;
        }
    }

    /**
     * @brief Retires this generation before the loader releases or retains its image.
     * @return Zero refuses retirement (keep the image mapped). KCD1_TPVCAMERA_RELOAD_OK permits release.
     *         KCD1_TPVCAMERA_RELOAD_RETAINED requires the loader to keep its module reference.
     * @note The loader calls this from its control thread, off the loader lock. Retrying a recoverable refusal is
     *       safe: a completed step is not repeated.
     */
    __declspec(dllexport) std::uint32_t DMK_WHEELHOST_CALL Shutdown() noexcept
    {
        if (s_session.has_value())
        {
            static bool s_profile_exported = false;
            if (!s_profile_exported)
            {
                s_profile_exported = true;
                // Before teardown, while the Session's logger still reports where the file went.
                export_profile();
            }
            (void)DMK::log().try_log(DMK::LogLevel::Info, "[DEV] Shutdown generation {}", s_generation_id);
        }
        return retire_generation();
    }
} // extern "C"

/** @brief Prevents Session teardown under the loader lock at process termination. */
BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID reserved) noexcept
{
    if (reason == DLL_PROCESS_DETACH && reserved != nullptr && s_session.has_value())
    {
        s_session->abandon();
    }
    return TRUE;
}

#endif // KCD1_TPVCAMERA_DEV_BUILD
