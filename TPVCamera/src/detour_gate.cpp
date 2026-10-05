/**
 * @file detour_gate.cpp
 * @brief Hook ownership, newest-first disable, and the in-flight + thread-sweep quiescence proof.
 */

#include "detour_gate.hpp"

#include <DetourModKit.hpp>

#include <windows.h>
#include <tlhelp32.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace TPVCamera::DetourGate
{
    namespace
    {
        /// Upper bound on owned hooks. Reserved up front so the handles HookStack hands back never move.
        constexpr std::size_t k_capacity = 32;

        /// The name MSVC gives the TPV_DETOUR section in the image (IMAGE_SIZEOF_SHORT_NAME bytes, NUL padded).
        constexpr std::array<char, IMAGE_SIZEOF_SHORT_NAME> k_section_name = {'.', 't', 'p', 'v', 'd', 'e', 't', '\0'};

        // Every game-thread hook, owned newest-first for teardown, plus the same handles in install order for
        // the newest-first disable pass HookStack does not expose. Built and torn down on the setup thread only.
        DMK::hook::HookStack s_stack;
        std::vector<DMK::hook::Hook *> s_order;

        // The range the sweep inspects: the TPV_DETOUR section, or this whole image when the section cannot be
        // located (a conservative superset: it can only add false blockers, never miss a detour).
        DMK::Region s_detour_code{};

        // Bytes from each trampoline's start that count as "on the way into a detour". DetourModKit does not expose
        // a trampoline's size; the E9 layout is the relocated prologue (well under 64 bytes for a 5-byte patch)
        // followed by a 5-byte jump back, the 6-byte FF 25 jump to the detour, and its 8-byte target, so 128 bytes
        // covers it with margin. A wider window can only add false blockers, never miss a thread.
        constexpr std::size_t k_trampoline_window = 128;

        // The trampoline of every owned hook, recorded at adopt() time. A thread on a trampoline's FF 25 jump has
        // left the restored target but not yet reached the detour section, so the sweep must see it.
        std::array<DMK::Region, k_capacity> s_trampolines{};
        std::size_t s_trampoline_count = 0;

        // Latches the first backend retention across retries: a retained route keeps its detour reachable.
        bool s_restore_failed = false;

        /// Finds the TPV_DETOUR section in this image's own (always mapped) PE headers.
        [[nodiscard]] DMK::Region find_detour_section(const DMK::Region &image) noexcept
        {
            if (!image.base || image.size < sizeof(IMAGE_DOS_HEADER))
            {
                return {};
            }
            const auto *bytes = image.base.ptr<const std::byte>();
            const auto *dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(bytes);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
                static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > image.size)
            {
                return {};
            }
            const auto *nt = reinterpret_cast<const IMAGE_NT_HEADERS64 *>(bytes + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
            {
                return {};
            }
            const IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
            for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section)
            {
                if (std::memcmp(section->Name, k_section_name.data(), k_section_name.size()) == 0 &&
                    section->VirtualAddress + section->Misc.VirtualSize <= image.size)
                {
                    return image.sub(section->VirtualAddress, section->Misc.VirtualSize);
                }
            }
            return {};
        }

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

        /// True when @p ip is on the way into, or inside, a detour: in the detour section or in a recorded trampoline.
        [[nodiscard]] bool in_detour_path(std::uintptr_t ip) noexcept
        {
            if (s_detour_code.contains(DMK::Address{ip}))
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
         * @return True when no thread's instruction pointer lies in the detour section or a recorded trampoline, and
         *         no thread's top-of-stack return address lies in the detour section. A thread that cannot be
         *         inspected counts as inside (fail closed).
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
                        inside = return_address.has_value() && s_detour_code.contains(DMK::Address{*return_address});
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

    void bind_detour_section() noexcept
    {
        if (s_detour_code.size != 0)
        {
            return;
        }
        const DMK::Region image = DMK::Region::own();
        s_detour_code = find_detour_section(image);
        if (s_detour_code.size == 0)
        {
            s_detour_code = image;
            DMK::log().warning("DetourGate: {} section not found; the quiescence sweep inspects the whole image",
                               std::string_view(k_section_name.data()));
        }
    }

    DMK::hook::Hook &adopt(DMK::hook::Hook hook)
    {
        if (s_order.empty())
        {
            s_stack.reserve(k_capacity);
            s_order.reserve(k_capacity);
        }
        if (s_order.size() >= k_capacity)
        {
            // Never reached by this mod's fixed hook set; a growth here would move every handle s_order points at.
            throw std::length_error("DetourGate: hook capacity exceeded");
        }
        DMK::hook::Hook &held = s_stack.push(std::move(hook));
        s_order.push_back(&held);
        if (const auto trampoline = held.original<void (*)()>(); trampoline != nullptr)
        {
            s_trampolines[s_trampoline_count++] = DMK::Region{DMK::Address{trampoline}, k_trampoline_window};
        }
        return held;
    }

    Retirement retire(std::chrono::milliseconds budget) noexcept
    {
        if (s_restore_failed)
        {
            return Retirement::RestoreFailed;
        }
        if (s_order.empty())
        {
            return Retirement::Clean;
        }
        DMK::Logger &logger = DMK::log();

        // Disarm newest-first, the only order a layered target accepts. A disabled hook restores the target bytes
        // but keeps its trampoline, so a detour already running can still chain to its original.
        bool all_disabled = true;
        for (auto it = s_order.rbegin(); it != s_order.rend(); ++it)
        {
            DMK::hook::Hook &hook = **it;
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
        s_order.clear();
        s_trampoline_count = 0;
        s_stack.clear();
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

    std::size_t hook_count() noexcept
    {
        return s_order.size();
    }
} // namespace TPVCamera::DetourGate
