/**
 * @file render/aux_markers.cpp
 * @brief Corner-bracket markers drawn through the main thread's aux-geom command buffer.
 *
 * KCD1 holds only CAuxGeomCB_Null, so every entry point reports the backend unavailable.
 */

#include "render/aux_markers.hpp"

#include <DetourModKit.hpp>

#include <cstddef>
#include <span>

namespace HenrySenses
{
    DMK::Result<void> initialize_aux_markers()
    {
        // The renderer hands out its embedded CAuxGeomCB_Null, whose draw calls do nothing, so there is nothing to
        // validate or arm.
        return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "aux_markers/null_aux_geom"});
    }

    void shutdown_aux_markers() noexcept {}

    bool aux_markers_available() noexcept
    {
        return false;
    }

    std::size_t draw_markers(std::span<const MarkerRequest> markers, float opacity) noexcept
    {
        (void)markers;
        (void)opacity;
        return 0;
    }

} // namespace HenrySenses
