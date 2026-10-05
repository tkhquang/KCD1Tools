/**
 * @file detour_gate.hpp
 * @brief Proves the game-thread callers of the mod's inline hooks quiescent before the hook stack is destroyed.
 *
 * DetourModKit leaves inline-detour quiescence to the caller: hook::inline_at cannot wait for a thread that
 * is inside a detour, so destroying a Hook (which frees its trampoline) or unmapping the image that holds the
 * detour while a game thread still runs that code is a use-after-free. The hot-reload guide's rule is that a
 * fixed sleep proves nothing, and that an in-flight counter alone misses a caller that already took the
 * patched jump but has not reached its counter increment yet. A game inline hook needs an equivalent of
 * "join the only caller" for game-owned threads. Mid hooks need none of this: DetourModKit owns their
 * callback rundown.
 *
 * The mod owns its hooks in one hook::HookStack (tpv_camera.cpp), exactly as a DetourModKit consumer would.
 * This unit only adds the proof, built from three pieces:
 *   1. Every inline-hook detour opens with a Pass, an RAII in-flight counter whose increment and decrement are
 *      locked read-modify-writes (full barriers, so the increment is the seq_cst store side of DetourModKit's
 *      [B-42] / [B-43] drain pattern).
 *   2. retire() first DISABLES every recorded hook newest-first. Hook::disable restores the target bytes but
 *      keeps the trampoline alive, so no new call can enter a detour while one already inside can still finish
 *      through its original.
 *   3. It then drains the counter and sweeps every other thread of the process, suspending one at a time. A
 *      thread that took the patched jump but has not counted itself yet is either on the trampoline's jump to
 *      the detour (the E9-to-trampoline layout routes target -> trampoline epilogue -> detour), or somewhere in
 *      this image (the detour's prologue, or a leaf that prologue calls). So a thread whose instruction pointer
 *      lies in a recorded trampoline or in this image, or whose top-of-stack return address lies in this image,
 *      blocks the proof. A clean sweep followed by a still-zero counter proves that no thread is inside, or
 *      about to enter, any detour body or trampoline.
 *
 * Only after that proof does retire() clear the HookStack (newest-first). A backend DetourModKit cannot restore
 * cleanly is retained and booked as a LeakSubsystem::HookManager leak, which retire() latches as a permanent
 * refusal. The proof matters only when the image unmaps (the dev build's staged reload); the release ASI is
 * never unloaded, and it runs the same teardown so both builds exercise one path.
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
         *          unoptimized build.
         */
        inline volatile long g_inflight = 0;

        /**
         * @brief Pushes @p hook onto @p hooks and records it for retire()'s newest-first disable and sweep.
         * @return The stored Hook, or an Error when the fixed record table is full (the hook is then destroyed
         *         unarmed, which restores nothing because it was never enabled).
         * @note Setup/control-plane only. Used by arm().
         */
        [[nodiscard]] DMK::Result<DMK::hook::Hook *> adopt(DMK::hook::HookStack &hooks, DMK::hook::Hook hook);
    } // namespace detail

    /**
     * @brief In-flight marker for one inline-hook detour invocation. Construct it as the FIRST statement.
     * @details Both edges are locked read-modify-writes, which are full barriers on x64: the increment forms the
     *          seq_cst store side of the store-buffering litmus whose load side is the teardown drain ([B-43]),
     *          and the decrement publishes the body's completion to that drain. A detour body that needs an SEH
     *          frame keeps it in a separate function (MSVC C2712: __try cannot share a frame with this object).
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
     * @brief Pushes a freshly installed (disabled) inline hook onto @p hooks, publishes its trampoline, then arms it.
     * @param hooks The mod's hook stack. It owns the hook from here on, even when arming fails.
     * @param hook The Hook that hook::inline_at returned.
     * @param original The detour's trampoline slot. Stored BEFORE Hook::enable(), so no call can enter the detour
     *        unchained (`[B-83]`). The order push -> publish -> enable is DetourModKit's staged_reload example's.
     * @return An empty Result once the hook is armed, or the push / Hook::enable() Error.
     * @note Setup/control-plane only: call from init(), on the init thread, before retire().
     */
    template <class Fn>
    [[nodiscard]] DMK::Result<void> arm(DMK::hook::HookStack &hooks, DMK::hook::Hook hook, std::atomic<Fn> &original);

    /**
     * @brief Pushes a freshly installed (disabled) mid hook onto @p hooks, then arms it.
     * @details A mid hook has no trampoline to publish, and DetourModKit owns its callback rundown, so its
     *          callback needs no Pass. It is still recorded so retire() disables it with the others newest-first.
     * @note Setup/control-plane only.
     */
    [[nodiscard]] DMK::Result<void> arm(DMK::hook::HookStack &hooks, DMK::hook::Hook hook);

    /// The outcome of retire().
    enum class Retirement : std::uint8_t
    {
        /// Every hook was disabled, its callers proven quiescent, and its backend reclaimed.
        Clean,
        /**
         * @brief A hook could not be disabled, or a caller was still inside or entering a detour at the deadline.
         * @details The hooks stay installed (disabled where possible) and their trampolines alive. A later
         *          retire() retries.
         */
        CallersActive,
        /// A hook backend was retained by DetourModKit at destruction. Latched: every later retire() reports it.
        RestoreFailed,
    };

    /**
     * @brief Disables every recorded hook newest-first, proves its callers quiescent, then clears @p hooks.
     * @param hooks The stack every arm() pushed onto.
     * @param budget Bound on the drain + sweep loop.
     * @return The retirement verdict. Only Clean authorizes unmapping the image that holds the detours.
     * @details Idempotent and retryable: a CallersActive call leaves the hooks in place, so a later call resumes
     *          from the drain. Under the loader lock every Hook::disable refuses (LoaderLockActive), which reports
     *          CallersActive and keeps the hooks, exactly as a ~Hook there would.
     * @note Setup/control-plane only. Run it off the loader lock, after every mod-owned thread that can reach a
     *       detour (or a hooked target) is joined.
     */
    [[nodiscard]] Retirement retire(DMK::hook::HookStack &hooks, std::chrono::milliseconds budget) noexcept;

    /// Short label for a Retirement, for log lines.
    [[nodiscard]] std::string_view to_string(Retirement retirement) noexcept;

    template <class Fn>
    DMK::Result<void> arm(DMK::hook::HookStack &hooks, DMK::hook::Hook hook, std::atomic<Fn> &original)
    {
        DMK_TRY(held, detail::adopt(hooks, std::move(hook)));
        // Publish the trampoline BEFORE enable(): the patched target can call the detour the moment enable()
        // returns, and the detour chains through this slot.
        original.store(held->template original<Fn>(), std::memory_order_release);
        return held->enable();
    }
} // namespace TPVCamera::DetourGate

#endif // TPVCAMERA_DETOUR_GATE_HPP
