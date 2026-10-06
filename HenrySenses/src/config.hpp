/**
 * @file config.hpp
 * @brief Configuration model and registration for the Henry's Senses mod.
 *
 * @details LiveSettings holds every value read across threads. Each one is a std::atomic so INI hot reload (the
 *          setters run on DMK's auto-reload watcher thread) never races the game thread, and each is bound with
 *          DMK::config::bind / bind_parsed through a section binder. The [Highlight.<Name>] sections are not bound
 *          here: highlight/groups.cpp reads them itself, with [Settings] Key, Mode, Duration and Radius as their
 *          fallbacks.
 *
 *          KCD1 keeps every KCD2 setting, so an INI written for KCD2 loads unchanged. SeeThrough and RenderAlways need
 *          the mask-pass hook (Feature::MaskState). The native CHudSilhouettes pass has a fixed edge width and no mask
 *          blur, so OutlineWidth and Softness have no effect. Focus has no coverage mask to darken by, so FocusDarken,
 *          FocusTint and FocusFadeIn have no effect either.
 */
#ifndef HENRYSENSES_CONFIG_HPP
#define HENRYSENSES_CONFIG_HPP

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace HenrySenses
{
    /**
     * @enum RenderBackend
     * @brief Which renderer draws the highlight ([Render] Backend).
     */
    enum class RenderBackend : std::uint32_t
    {
        /// Engine silhouettes when the native pass can render, otherwise aux-geom markers.
        Auto = 0,
        /// The native CHudSilhouettes post effect (mesh-accurate). [KCD2 a revived see-through pass]
        Engine = 1,
        /// Aux-geom corner brackets. KCD1 compiles aux geometry out, so this backend draws nothing.
        Markers = 2,
    };

    /**
     * @enum RenderStyle
     * @brief Silhouette look ([Render] Style).
     * @details The KCD1 shader ignores the alpha byte of a word and draws every object with an edge and a fill. So a
     *          style only selects the one global fill: Outline turns it off, Fill and OutlineFill set it to
     *          [Render] FillOpacity.
     */
    enum class RenderStyle : std::uint32_t
    {
        /// Edges only (no global fill). [KCD2 a word with a non-zero alpha]
        Outline = 0,
        /// Edges and the global fill, as OutlineFill. [KCD2 a word with a zero alpha, a flat fill]
        Fill = 1,
        /// Edges and the global fill. [KCD2 an outline word whose interior the composite tints]
        OutlineFill = 2,
    };

    /**
     * @struct LiveSettings
     * @brief Cross-thread settings as atomics, so INI hot reload is race-free against the game thread.
     */
    struct LiveSettings
    {
        // [Settings]
        std::atomic<bool> enabled{true};
        // The fallbacks of the highlight groups: GroupMode, pulse and fade-out seconds, reach in metres.
        std::atomic<std::uint32_t> mode{0};
        std::atomic<float> duration{5.0f};
        std::atomic<float> fade_out{1.0f};
        std::atomic<float> radius{20.0f};
        // [Settings] Key.Consume: the fallback of a group's Key.Consume (hide the key's trigger, a digital controller
        // button or the mouse wheel, from the game while its combo is down).
        std::atomic<bool> key_consume{true};
        std::atomic<int> scan_interval_ms{250};

        // [Render]
        std::atomic<std::uint32_t> backend{static_cast<std::uint32_t>(RenderBackend::Auto)};
        std::atomic<std::uint32_t> style{static_cast<std::uint32_t>(RenderStyle::OutlineFill)};
        // No effect on KCD1: the native pass draws a fixed edge.
        std::atomic<float> outline_width{2.0f};
        // The share of each word's colour the silhouette keeps, 0 to 1. The native composite strength is fixed, so
        // the word carries it. [KCD2 0.5, the composite strength]
        std::atomic<float> strength{1.0f};
        // Style = Fill or OutlineFill: the opacity of the one global fill (HudSilhouettes_FillStr).
        std::atomic<float> fill_opacity{0.35f};
        // Gaussian blur of the silhouette mask before the outline is drawn, in render texels (0 = hard edges). No
        // effect on KCD1.
        std::atomic<float> softness{0.0f};
        std::atomic<float> fade_start{12.0f};
        std::atomic<float> min_opacity{1.0f};
        std::atomic<float> fade_power{1.0f};
        // Draw the silhouette mask without the depth test, so a highlight shows through walls (the mask-pass hook).
        std::atomic<bool> see_through{true};
        // While SeeThrough is on, move highlighted entities into the always-visible list, so occlusion culling does not
        // drop one behind a wall.
        std::atomic<bool> render_always{true};
        // Focus (groups with Focus = true): how much darker the background gets, 0 to 1, the colour it takes
        // (0xRRGGBB, white = neutral), and the seconds the background takes to darken. No effect on KCD1.
        std::atomic<float> focus_darken{0.0f};
        std::atomic<std::uint32_t> focus_tint{0xB8C4D8u};
        std::atomic<float> focus_fade_in{0.4f};

        // [Settings] HideIn: the situations (GameState bits) in which a group that names none of its own hides.
        std::atomic<std::uint32_t> hide_in{1u << 2};

        // [Settings] ExportSignatures: write every built-in signature, with its captured baselines, to
        // KCD1_HenrySenses.signatures.captured.ini.
        std::atomic<bool> export_signatures{false};
    };

    /** @brief Returns the process-wide live settings. */
    [[nodiscard]] LiveSettings &settings() noexcept;

    /**
     * @brief Returns a copy of [Settings] Key, the hotkey of every group that sets none.
     * @return The key as written; empty when unbound.
     * @note Takes a short lock; setup and main-thread use only, never from a hook callback.
     */
    [[nodiscard]] std::string default_key();

    /**
     * @brief The ASCII lower case of @p c, independent of the C locale (every INI token is ASCII).
     */
    [[nodiscard]] constexpr char ascii_lower(char c) noexcept
    {
        return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
    }

    /**
     * @brief Registers the log level and every LiveSettings atomic with DMK::config.
     * @note Must run before DMK::config::load().
     */
    void register_config_items();

} // namespace HenrySenses

#endif // HENRYSENSES_CONFIG_HPP
