/**
 * @file dllmain.cpp
 * @brief DLL entry point wiring the mod lifecycle to the DetourModKit Session.
 *
 * bootstrap_attach() performs the process and single-instance gates without allocating, then runs
 * on_ready(session) on its own worker thread off the loader lock; ~Session (also on that worker)
 * clears the binding scope and tears the DMK subsystems down in order.
 *
 * DetourModKit does not own the mod's own state. Hooks are caller-owned handles, so
 * TPVCamera::shutdown() is the only path that restores the patched prologues, and this file calls it.
 */

#include "tpv_camera.hpp"
#include "constants.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <atomic>

// In the two-DLL dev build the logic is loaded by the resident loader ASI, which owns the
// entry points (see src/dev/mod_logic.cpp). The production ASI uses DllMain.
#ifndef TPVCAMERA_DEV_BUILD

namespace
{
    // Set once on_ready starts, so the detach path tears down only an image whose init actually ran. A refused
    // attach (a duplicate load holding the instance mutex) also reaches DLL_PROCESS_DETACH with lpReserved NULL,
    // and running shutdown() there would make that never-initialized image's first logger use, allocation
    // included, under the loader lock.
    std::atomic<bool> s_init_ran{false};

    DMK::Result<void> on_ready(DMK::Session &session)
    {
        s_init_ran.store(true, std::memory_order_release);
        return TPVCamera::init(session);
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE h_module, DWORD ul_reason_for_call, LPVOID lp_reserved)
{
    // bootstrap_attach captures the calling module itself, because DetourModKit links statically into this
    // DLL and its code address resolves to this HMODULE.
    (void)h_module;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DMK::AsyncLoggerConfig async_cfg;
        // Fall back to synchronous logging if the async queue overflows so no
        // diagnostic line is lost during a burst (startup or teardown).
        async_cfg.overflow_policy = DMK::OverflowPolicy::SyncFallback;

        // No process-name gate: the WHGame.dll module check in init() is the gate.
        const DMK::ModInfo info{
            .name = Constants::MOD_NAME,
            .log_file = Constants::LOG_FILE_NAME,
            .game_process_name = "",
            .instance_mutex_prefix = Constants::INSTANCE_MUTEX_PREFIX,
            .log = async_cfg,
            // The [file:line] stamp is kept only on Trace, where it is read while debugging, and every higher
            // level renders clean. log_open_mode stays at the default Truncate: this build is a single DLL with
            // one Session per run, while the dev loader needs Append to keep each generation's teardown records.
            .log_source_stamp_mode = DMK::LogSourceStampMode::at_or_below(DMK::LogLevel::Trace),
        };

        // A gate refusal (a duplicate load already holding the mutex) is a reason for this DLL to go away, not
        // for the host to fail, so report it as a failed attach and let the loader unmap us.
        return DMK::bootstrap_attach(info, &on_ready).has_value() ? TRUE : FALSE;
    }

    case DLL_PROCESS_DETACH:
        // lp_reserved == NULL is an explicit FreeLibrary. Run the mod teardown so the patched prologues are
        // restored; under the loader lock every join and hook mutation fails closed, so this changes nothing it
        // cannot prove safe (the bootstrap worker's own module reference also keeps a bare FreeLibrary from
        // reaching here while the Session lives). lp_reserved != NULL is process exit: the OS has already killed
        // every other thread, so touching patched pages there would be a UAF and the abandon path inside
        // bootstrap_detach is the correct no-op.
        if (lp_reserved == nullptr && s_init_ran.load(std::memory_order_acquire))
        {
            // The verdict is discarded here on purpose. DllMain cannot refuse a FreeLibrary already in
            // progress, and this ASI is loaded once for the process, so there is no later load that a
            // retained hook could hand a stale image to. shutdown() logs the failure itself.
            (void)TPVCamera::shutdown();
        }
        DMK::bootstrap_detach(lp_reserved);
        break;

    default:
        break;
    }

    return TRUE;
}

#endif // TPVCAMERA_DEV_BUILD
