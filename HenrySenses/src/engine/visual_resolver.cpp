/**
 * @file engine/visual_resolver.cpp
 * @brief Render-node identity helpers: brush identity, the hidden flag and node names.
 */

#include "engine/visual_resolver.hpp"
#include "constants.hpp"
#include "rtti_types.hpp"
#include "engine/engine_env.hpp"
#include "engine/octree_query.hpp"
#include "engine/seh.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <cmath>
#include <cstddef>
#include <optional>
#include <string>

namespace HenrySenses
{
    namespace
    {
        using GetNameFn = const char *(__fastcall *)(std::uintptr_t node);

        /// The longest node name kept.
        constexpr std::size_t MAX_NAME_LENGTH = 160;
        /// A brush recreated by streaming keeps its bounds within this on every axis.
        constexpr float BOUNDS_TOLERANCE = 0.01f;

        /** @brief Calls IRenderNode::GetName under SEH, or returns nullptr on a fault. */
        [[nodiscard]] const char *call_get_name(std::uintptr_t fn, std::uintptr_t node) noexcept
        {
            __try
            {
                return reinterpret_cast<GetNameFn>(fn)(node);
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return nullptr;
            }
        }

        /** @brief True when every bound of @p a lies within BOUNDS_TOLERANCE of the same bound of @p b. */
        [[nodiscard]] bool same_bounds(const game_structures::Aabb &a, const game_structures::Aabb &b) noexcept
        {
            return std::abs(a.min.x - b.min.x) <= BOUNDS_TOLERANCE && std::abs(a.min.y - b.min.y) <= BOUNDS_TOLERANCE &&
                   std::abs(a.min.z - b.min.z) <= BOUNDS_TOLERANCE && std::abs(a.max.x - b.max.x) <= BOUNDS_TOLERANCE &&
                   std::abs(a.max.y - b.max.y) <= BOUNDS_TOLERANCE && std::abs(a.max.z - b.max.z) <= BOUNDS_TOLERANCE;
        }
    } // namespace

    bool is_brush_node(std::uintptr_t node) noexcept
    {
        if (node == 0 || !DMK::memory::is_plausible_ptr(DMK::Address{node}))
        {
            return false;
        }
        const auto vtable = DMK::memory::read<std::uintptr_t>(DMK::Address{node});
        return vtable && vtable_is(GameClass::Brush, *vtable);
    }

    bool brush_matches(std::uintptr_t brush, const game_structures::Aabb &bounds) noexcept
    {
        if (!is_brush_node(brush))
        {
            return false;
        }
        const std::optional<game_structures::Aabb> now = render_node_bounds(brush);
        return now.has_value() && same_bounds(*now, bounds);
    }

    bool render_node_hidden(std::uintptr_t node) noexcept
    {
        // KCD1 render-node flags are a uint32 at IRenderNode + 0x34. [KCD2 uint64 at + 0x28]
        const auto flags = DMK::memory::read<std::uint32_t>(DMK::Address{node + constants::RENDERNODE_RNDFLAGS_OFFSET});
        return !flags || (*flags & constants::ERF_HIDDEN) != 0;
    }

    std::string render_node_name(std::uintptr_t node)
    {
        const std::uintptr_t fn = read_vtable_slot(node, constants::RENDERNODE_VTABLE_GET_NAME_OFFSET);
        if (fn == 0)
        {
            return {};
        }
        const char *text = call_get_name(fn, node);
        return text != nullptr ? read_c_string(reinterpret_cast<std::uintptr_t>(text), MAX_NAME_LENGTH) : std::string{};
    }

} // namespace HenrySenses
