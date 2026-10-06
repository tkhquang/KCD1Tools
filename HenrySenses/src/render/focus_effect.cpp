/**
 * @file render/focus_effect.cpp
 * @brief Focus: the game's VisualArtifacts post effect, masked to everything but the highlighted objects.
 *
 * KCD1 has no coverage mask source (see the header), so the focus only reports itself unavailable.
 */

#include "render/focus_effect.hpp"

#include <DetourModKit.hpp>

#include <atomic>
#include <cstdint>

namespace HenrySenses
{
    namespace
    {
        // The session saw a focus request (an active Focus group with FocusDarken above 0). It is logged once.
        bool s_reported = false;
        // Ticks that asked for the focus, for the state report.
        std::atomic<std::uint64_t> s_requests{0};
    } // namespace

    void
    update_focus_effect(float strength, float darken, std::uint32_t tint, float fade_in, std::int64_t now_ms) noexcept
    {
        (void)tint;
        (void)fade_in;
        (void)now_ms;
        if (strength <= 0.0f || darken <= 0.0f)
        {
            return;
        }
        s_requests.fetch_add(1, std::memory_order_relaxed);
        if (!s_reported)
        {
            s_reported = true;
            (void)DMK::log().try_log(
                DMK::LogLevel::Info,
                "Focus: unavailable on KCD1 (no coverage mask to darken the background by); Focus = true has no "
                "effect"
            );
        }
    }

    void release_focus_effect() noexcept {}

    void log_focus_effect_state()
    {
        DMK::log().info(
            "Focus: unavailable (no coverage mask source), ticks that asked for it={}",
            s_requests.load(std::memory_order_relaxed)
        );
    }

} // namespace HenrySenses
