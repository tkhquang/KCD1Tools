/**
 * @file render/aux_markers.hpp
 * @brief Aux-geom markers (corner brackets) around loot the engine silhouette cannot draw.
 *
 * KCD1 compiles aux geometry out. CD3D9Renderer::GetIRenderAuxGeom (vtable slot 207) returns the CAuxGeomCB_Null the
 * renderer embeds at +0x2AFC8. Every draw call of it is a no-op, and the image holds no CAuxGeomCB class. So this
 * backend reports itself unavailable and draws nothing: Backend=Markers and Style=Box show nothing, and the controller
 * leaves every marker out. [KCD2 draws the brackets through the main thread's CAuxGeomCB, gEnv + 0x108, slot 199.]
 * The API stays the KCD2 one, so a future marker backend drops in behind it.
 */
#ifndef HENRYSENSES_AUX_MARKERS_HPP
#define HENRYSENSES_AUX_MARKERS_HPP

#include "game_structures.hpp"

#include <DetourModKit/error.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace HenrySenses
{
    /**
     * @struct MarkerRequest
     * @brief One marker to draw this frame.
     */
    struct MarkerRequest
    {
        /// World-space bounds of the highlighted entity.
        game_structures::Aabb bounds{};
        /// Packed 0xRRGGBBAA colour (the alpha byte is replaced by the marker opacity).
        std::uint32_t color_word{0};
    };

    /**
     * @brief Reports why markers cannot be drawn.
     * @return NoMatch: KCD1 has no aux-geometry implementation. [KCD2 an empty value once the aux-geom validators
     *         resolved]
     */
    [[nodiscard]] DMK::Result<void> initialize_aux_markers();

    /** @brief Marks markers unavailable. */
    void shutdown_aux_markers() noexcept;

    /**
     * @brief Reports whether markers can be drawn.
     * @return False: KCD1 has no aux-geometry implementation.
     */
    [[nodiscard]] bool aux_markers_available() noexcept;

    /**
     * @brief Queues corner brackets for this frame.
     * @param markers The markers to draw.
     * @param opacity Marker opacity in [0, 1] (pulse fade).
     * @return The number of markers queued: 0 on KCD1.
     * @note Main thread only (the aux-geom buffer is per thread).
     */
    [[nodiscard]] std::size_t draw_markers(std::span<const MarkerRequest> markers, float opacity) noexcept;

} // namespace HenrySenses

#endif // HENRYSENSES_AUX_MARKERS_HPP
