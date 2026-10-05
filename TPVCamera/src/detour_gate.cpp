/**
 * @file detour_gate.cpp
 * @brief Newest-first disable and the in-flight + thread-sweep quiescence proof over the mod's hook stack.
 */

#include "detour_gate.hpp"

#include <DetourModKit.hpp>

#include <windows.h>
#include <tlhelp32.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace TPVCamera::DetourGate
{
    namespace
    {
        // Upper bound on recorded hooks. The first arm() reserves this much HookStack capacity, so no later push
        // reallocates: HookStack::push is a vector push_back, and a push within reserved capacity leaves every
        // earlier element in place, which is what keeps the recorded Hook pointers valid until retire() clears the
        // stack. The mod's fixed hook set stays far below it.
        constexpr std::size_t k_capacity = 32;

        // Every hook arm() pushed, in push order, for the newest-first disable pass HookStack does not expose.
        // Built and cleared on the setup thread only.
        std::array<DMK::hook::Hook *, k_capacity> s_records{};
        std::size_t s_record_count = 0;

        // The range the sweep inspects: this whole image. Every detour body, the leaves its prologue can call, and
        // any incremental-link thunk in front of it live here. DetourModKit's own threads (the input poller, the
        // log writer) also run code in this image, so one caught mid-step is a transient blocker the retry loop
        // absorbs; it can never hide a thread that is entering a detour.
        DMK::Region s_image{};

        // Bytes from each trampoline's start that count as "on the way into a detour". DetourModKit does not expose
        // a trampoline's size; the E9 layout is the relocated prologue (well under 64 bytes for a 5-byte patch)
        // followed by a 5-byte jump back, the 6-byte FF 25 jump to the detour, and its 8-byte target, so 128 bytes
        // covers it with margin. A wider window can only add false blockers, never miss a thread.
        constexpr std::size_t k_trampoline_window = 128;

        // The trampoline of every recorded inline hook. A thread on a trampoline's FF 25 jump has left the
        // restored target but not yet reached the detour, so the sweep must see it.
        std::array<DMK::Region, k_capacity> s_trampolines{};
        std::size_t s_trampoline_count = 0;

        // Latches the first backend retention across retries: a retained route keeps its detour reachable.
        bool s_restore_failed = false;

        /// The thread found inside the detour code, for the refusal log line.
        struct Blocker
        {
            DWORD thread_id = 0;
            std::uintptr_t ip = 0;
            /// ResumeThread failed twice for this thread, which then stays suspended. Reported, never retried.
            bool resume_failed = false;
        };

        /// Reads the in-flight count as a locked RMW, the full-barrier (seq_cst) load side of the [B-43] litmus.
        [[nodiscard]] long inflight_now() noexcept
        {
            return _InterlockedCompareExchange(&detail::g_inflight, 0, 0);
        }

        /// True when @p ip is on the way into, or inside, a detour: in this image or in a recorded trampoline.
        [[nodiscard]] bool in_detour_path(std::uintptr_t ip) noexcept
        {
            if (s_image.contains(DMK::Address{ip}))
            {
                return true;
            }
            for (std::size_t i = 0; i < s_trampoline_count; ++i)
            {
                if (s_trampolines[i].contains(DMK::Address{ip}))
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Suspends every other thread of the process in turn and checks it is not on its way into a detour.
         * @return True when no thread's instruction pointer lies in this image or a recorded trampoline, and no
         *         thread's top-of-stack return address lies in this image. A thread that cannot be inspected counts
         *         as inside (fail closed).
         * @details Nothing between SuspendThread and ResumeThread allocates, locks, or logs: GetThreadContext is a
         *          syscall and the stack-top read is DetourModKit's guarded read, so a suspended thread holding the
         *          heap or loader lock cannot deadlock the sweep. The top-of-stack check catches a thread inside a
         *          leaf the detour prologue calls before its Pass (an unoptimized Pass constructor, or __chkstk on a
         *          large frame). A thread id reused by another process between the snapshot and OpenThread is
         *          skipped, so the sweep never suspends a foreign thread.
         */
        [[nodiscard]] bool sweep(Blocker &blocker) noexcept
        {
            const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                blocker = {};
                return false;
            }
            const DWORD pid = GetCurrentProcessId();
            const DWORD self = GetCurrentThreadId();
            bool clean = true;
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            for (BOOL more = Thread32First(snapshot, &entry); more && clean; more = Thread32Next(snapshot, &entry))
            {
                if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == self)
                {
                    continue;
                }
                const HANDLE thread =
                    OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                               entry.th32ThreadID);
                if (thread == nullptr)
                {
                    // ERROR_INVALID_PARAMETER: the thread exited after the snapshot, so it cannot be in a detour.
                    if (GetLastError() != ERROR_INVALID_PARAMETER)
                    {
                        blocker = {entry.th32ThreadID, 0};
                        clean = false;
                    }
                    continue;
                }
                if (GetProcessIdOfThread(thread) != pid)
                {
                    // The id was recycled for a thread of another process after the snapshot; ours exited.
                    CloseHandle(thread);
                    continue;
                }
                if (SuspendThread(thread) == static_cast<DWORD>(-1))
                {
                    blocker = {entry.th32ThreadID, 0};
                    clean = false;
                    CloseHandle(thread);
                    continue;
                }
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                bool inside = true;
                std::uintptr_t ip = 0;
                if (GetThreadContext(thread, &context) != 0)
                {
                    ip = static_cast<std::uintptr_t>(context.Rip);
                    inside = in_detour_path(ip);
                    if (!inside)
                    {
                        const auto return_address = DMK::memory::read<std::uintptr_t>(DMK::Address{context.Rsp});
                        inside = return_address.has_value() && s_image.contains(DMK::Address{*return_address});
                    }
                }
                const bool resumed =
                    ResumeThread(thread) != static_cast<DWORD>(-1) || ResumeThread(thread) != static_cast<DWORD>(-1);
                CloseHandle(thread);
                if (!resumed)
                {
                    blocker = {entry.th32ThreadID, ip, true};
                    clean = false;
                }
                else if (inside)
                {
                    blocker = {entry.th32ThreadID, ip};
                    clean = false;
                }
            }
            CloseHandle(snapshot);
            return clean;
        }

        /**
         * @brief Waits, within @p deadline, until no thread is inside or entering a detour body.
         * @return True once a clean sweep is bracketed by two zero in-flight reads.
         */
        [[nodiscard]] bool prove_quiescent(std::chrono::steady_clock::time_point deadline) noexcept
        {
            DMK::Logger &logger = DMK::log();
            std::uint32_t passes = 0;
            Blocker blocker{};
            for (;;)
            {
                // The drain read is a full-barrier RMW: it pairs with Pass's locked increment, so a detour that
                // already incremented is observed here ([B-43]).
                if (inflight_now() == 0)
                {
                    ++passes;
                    // A thread that took the patched jump before the disable can sit on a trampoline's jump or in a
                    // detour prologue with the counter still at zero. The sweep catches it; the re-read below catches
                    // one that counted itself in while the sweep ran.
                    const bool clean = sweep(blocker);
                    if (blocker.resume_failed)
                    {
                        logger.error("DetourGate: thread {} could not be resumed after the quiescence check",
                                     blocker.thread_id);
                        return false;
                    }
                    if (clean && inflight_now() == 0)
                    {
                        logger.debug("DetourGate: callers quiescent after {} sweep(s)", passes);
                        return true;
                    }
                }
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    logger.warning("DetourGate: callers not quiescent ({} in flight, thread {} at {}, {} sweep(s)); "
                                   "the hooks stay installed and the image must stay mapped",
                                   inflight_now(), blocker.thread_id, DMK::format::format_address(blocker.ip), passes);
                    return false;
                }
                Sleep(1);
            }
        }
    } // namespace

    DMK::Result<DMK::hook::Hook *> detail::adopt(DMK::hook::HookStack &hooks, DMK::hook::Hook hook)
    {
        if (s_record_count == 0)
        {
            hooks.reserve(k_capacity);
            s_image = DMK::Region::own();
        }
        if (s_record_count >= k_capacity || hooks.size() >= k_capacity)
        {
            // Never reached by this mod's fixed hook set. A push past the reserved capacity would move every
            // recorded hook, so the hook is refused (and destroyed unarmed) instead.
            return std::unexpected(DMK::Error{DMK::ErrorCode::OutOfMemory, "DetourGate::adopt"});
        }
        DMK::hook::Hook &held = hooks.push(std::move(hook));
        s_records[s_record_count++] = &held;
        if (const auto trampoline = held.original<void (*)()>(); trampoline != nullptr)
        {
            s_trampolines[s_trampoline_count++] = DMK::Region{DMK::Address{trampoline}, k_trampoline_window};
        }
        return &held;
    }

    DMK::Result<void> arm(DMK::hook::HookStack &hooks, DMK::hook::Hook hook)
    {
        DMK_TRY(held, detail::adopt(hooks, std::move(hook)));
        return held->enable();
    }

    Retirement retire(DMK::hook::HookStack &hooks, std::chrono::milliseconds budget) noexcept
    {
        if (s_restore_failed)
        {
            return Retirement::RestoreFailed;
        }
        if (s_record_count == 0)
        {
            return Retirement::Clean;
        }
        DMK::Logger &logger = DMK::log();
        if (s_image.size == 0)
        {
            // Without this image's range the sweep could not see a thread inside a detour body, so the proof cannot
            // hold: keep the hooks and the image (fail closed).
            logger.error("DetourGate: this image's range is unknown; the hooks stay installed and the image must stay "
                         "mapped");
            return Retirement::CallersActive;
        }

        // Disarm newest-first, the only order a layered target accepts. A disabled hook restores the target bytes
        // but keeps its trampoline, so a detour already running can still chain to its original.
        bool all_disabled = true;
        for (std::size_t i = s_record_count; i-- > 0;)
        {
            DMK::hook::Hook &hook = *s_records[i];
            if (!hook.is_enabled())
            {
                continue;
            }
            if (const auto disabled = hook.disable(); !disabled)
            {
                all_disabled = false;
                logger.error("DetourGate: {} did not disable ({}); its target can still enter the detour, so the "
                             "image stays mapped (a hook layered on the same target by another mod blocks this until "
                             "the game restarts)",
                             hook.name(), disabled.error().message());
            }
        }
        if (!all_disabled)
        {
            return Retirement::CallersActive;
        }

        if (!prove_quiescent(std::chrono::steady_clock::now() + budget))
        {
            return Retirement::CallersActive;
        }

        // Callers are proven gone, so the trampolines can go. A backend DetourModKit cannot prove idle (or whose
        // target bytes it cannot witness) is retained and booked as a HookManager leak; the delta reports it.
        namespace diag = DMK::diagnostics;
        const std::size_t leaks_before = diag::intentional_leak_count(diag::LeakSubsystem::HookManager);
        s_record_count = 0;
        s_trampoline_count = 0;
        hooks.clear();
        if (diag::intentional_leak_count(diag::LeakSubsystem::HookManager) != leaks_before)
        {
            s_restore_failed = true;
            logger.error("DetourGate: a hook backend was retained at teardown; its detour stays reachable");
            return Retirement::RestoreFailed;
        }
        return Retirement::Clean;
    }

    std::string_view to_string(Retirement retirement) noexcept
    {
        switch (retirement)
        {
        case Retirement::Clean:
            return "Clean";
        case Retirement::CallersActive:
            return "CallersActive";
        case Retirement::RestoreFailed:
            return "RestoreFailed";
        }
        return "Unknown";
    }
} // namespace TPVCamera::DetourGate
