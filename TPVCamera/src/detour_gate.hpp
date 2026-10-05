/**
 * @file detour_gate.hpp
 * @brief Owns the game-thread inline hooks and proves their callers quiescent before the hooks are destroyed.
 *
 * DetourModKit leaves inline-detour quiescence to the caller: hook::inline_at cannot wait for a thread that
 * is inside a detour, so destroying a Hook (which frees its trampoline) or unmapping the image that holds the
 * detour while a game thread still runs that code is a use-after-free. The hot-reload guide's rule is that a
 * fixed sleep proves nothing, and that an in-flight counter alone misses a caller that already took the
 * patched jump but has not reached its counter increment yet. A game inline hook needs an equivalent of
 * "join the only caller" for game-owned threads.
 *
 * This unit is that proof, built from three pieces:
 *   1. Every game-thread detour is compiled into one dedicated code section (TPV_DETOUR) and opens with a
 *      Pass, an RAII in-flight counter whose increment and decrement are locked read-modify-writes (full
 *      barriers, so the increment is the seq_cst store side of DetourModKit's [B-42] / [B-43] drain pattern).
 *   2. retire() first DISABLES every hook newest-first. Hook::disable restores the target bytes but keeps the
 *      trampoline alive, so no new call can enter a detour while one already inside can still finish through
 *      its original.
 *   3. It then drains the counter and sweeps every other thread of the process, suspending one at a time. A
 *      thread that took the patched jump but has not counted itself yet is either on the trampoline's jump to
 *      the detour (the E9-to-trampoline layout routes target -> trampoline epilogue -> detour), in the detour's
 *      prologue, or in a leaf that prologue calls. So a thread whose instruction pointer lies in a recorded
 *      trampoline or in the detour section, or whose top-of-stack return address lies in the detour section,
 *      blocks the proof. A clean sweep followed by a still-zero counter proves that no thread is inside, or
 *      about to enter, any detour body or trampoline.
 *
 * Only after that proof does retire() destroy the hooks (HookStack, newest-first). A backend DetourModKit cannot
 * restore cleanly is retained and booked as a LeakSubsystem::HookManager leak, which retire() latches as a
 * permanent refusal.
 */
#ifndef TPVCAMERA_DETOUR_GATE_HPP
#define TPVCAMERA_DETOUR_GATE_HPP

#include <DetourModKit.hpp>

#include <intrin.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

/**
 * @brief Places a game-thread detour in the dedicated `.tpvdet` code section the quiescence sweep inspects.
 * @details Apply it to every function a hooked game target jumps to. Code the detour inlines lands in the same
 *          section; a call it makes out of the section happens after its Pass, so the counter covers it.
 */
#define TPV_DETOUR __declspec(code_seg(".tpvdet"))

namespace TPVCamera::DetourGate
{
    namespace detail
    {
        /**
         * @brief Count of game threads currently inside a detour body (between Pass construction and destruction).
         * @details Driven through the interlocked compiler intrinsics rather than std::atomic: an intrinsic is
         *          expanded in place in every build configuration, so the increment is always an instruction of
         *          the detour itself (or, at /Od, of the Pass constructor one call deep, which the sweep's
         *          top-of-stack check covers). A std::atomic member call can stay an out-of-line call chain in an
         *          unoptimized build, out of the sweep's reach.
         */
        inline volatile long g_inflight = 0;
    } // namespace detail

    /**
     * @brief In-flight marker for one detour invocation. Construct it as the FIRST statement of every detour.
     * @details Both edges are locked read-modify-writes, which are full barriers on x64: the increment forms the
     *          seq_cst store side of the store-buffering litmus whose load side is the teardown drain ([B-43]),
     *          and the decrement publishes the body's completion to that drain.
     * @note Callback-safe: one locked RMW each way, no allocation, lock, or I/O.
     */
    class Pass
    {
      public:
        Pass() noexcept { (void)_InterlockedIncrement(&detail::g_inflight); }
        ~Pass() noexcept { (void)_InterlockedDecrement(&detail::g_inflight); }
        Pass(const Pass &) = delete;
        Pass &operator=(const Pass &) = delete;
        Pass(Pass &&) = delete;
        Pass &operator=(Pass &&) = delete;
    };

    /**
     * @brief Takes ownership of a freshly installed (disabled) inline hook, publishes its trampoline, then arms it.
     * @param hook The Hook that hook::inline_at returned. It stays owned by the gate even when arming fails, so the
     *        normal teardown retires it.
     * @param original The detour's trampoline slot. Stored BEFORE Hook::enable(), so no call can enter the detour
     *        unchained (`[B-83]`).
     * @return An empty Result once the hook is armed, or the Hook::enable() Error.
     * @note Setup/control-plane only: call from init(), on the init thread, before the gate is retired.
     */
    template <class Fn> [[nodiscard]] DMK::Result<void> arm(DMK::hook::Hook hook, std::atomic<Fn> &original);

    /**
     * @brief Records the code section the sweep inspects. Called once by the first arm().
     * @note Setup/control-plane only: resolves this image's own PE section table.
     */
    void bind_detour_section() noexcept;

    /**
     * @brief Takes ownership of a disabled Hook, records its trampoline for the sweep, and returns the stored handle.
     * @note Setup/control-plane only. Used by arm().
     */
    [[nodiscard]] DMK::hook::Hook &adopt(DMK::hook::Hook hook);

    /// The outcome of retire().
    enum class Retirement : std::uint8_t
    {
        /// Every hook was disabled, its callers proven quiescent, and its backend reclaimed.
        Clean,
        /// A hook could not be disabled, or a caller was still inside or entering a detour when the budget ran out.
        /// The hooks stay installed (disabled where possible) and their trampolines alive. A later retire() retries.
        CallersActive,
        /// A hook backend was retained by DetourModKit at destruction. Latched: every later retire() reports it.
        RestoreFailed,
    };

    /**
     * @brief Disables every hook newest-first, proves its callers quiescent, then destroys the hooks.
     * @param budget Bound on the drain + sweep loop.
     * @return The retirement verdict. Only Clean authorizes unmapping the image that holds the detours.
     * @details Idempotent and retryable: a CallersActive call leaves the hooks in place, so a later call resumes
     *          from the drain. Under the loader lock every Hook::disable refuses (LoaderLockActive), which reports
     *          CallersActive and keeps the hooks, exactly as a ~Hook there would.
     * @note Setup/control-plane only. Run it off the loader lock, after every mod-owned thread that can reach a
     *       detour (or a hooked target) is joined.
     */
    [[nodiscard]] Retirement retire(std::chrono::milliseconds budget) noexcept;

    /// Short label for a Retirement, for log lines.
    [[nodiscard]] std::string_view to_string(Retirement retirement) noexcept;

    /// Number of hooks the gate currently owns.
    [[nodiscard]] std::size_t hook_count() noexcept;

    template <class Fn> DMK::Result<void> arm(DMK::hook::Hook hook, std::atomic<Fn> &original)
    {
        bind_detour_section();
        DMK::hook::Hook &held = adopt(std::move(hook));
        // Publish the trampoline BEFORE enable(): the patched target can call the detour the moment enable()
        // returns, and the detour chains through this slot.
        original.store(held.original<Fn>(), std::memory_order_release);
        return held.enable();
    }
} // namespace TPVCamera::DetourGate

#endif // TPVCAMERA_DETOUR_GATE_HPP
