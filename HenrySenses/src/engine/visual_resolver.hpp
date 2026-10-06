/**
 * @file engine/visual_resolver.hpp
 * @brief Render-node identity helpers: brush identity, the hidden flag and node names.
 *
 * KCD1 has one brush class, CBrush, which never moves, and no COwnedBrush, CMovableBrush or RuntimePrefab entity. A
 * brush pointer is trusted only while brush_matches() holds. [KCD2 also finds the mesh behind an interaction trigger
 * here, through its prefab template library and an octree search around the trigger.]
 */
#ifndef HENRYSENSES_VISUAL_RESOLVER_HPP
#define HENRYSENSES_VISUAL_RESOLVER_HPP

#include "game_structures.hpp"

#include <cstdint>
#include <string>

namespace HenrySenses
{
    /**
     * @brief Reports whether a node is a brush.
     * @details KCD1 has one brush class, CBrush, and no class derives from it. [KCD2 also COwnedBrush and
     *          CMovableBrush]
     */
    [[nodiscard]] bool is_brush_node(std::uintptr_t node) noexcept;

    /**
     * @brief Reports whether a brush found earlier can still be touched: still a brush, with the same bounds.
     * @details A freed brush whose memory was reused fails the identity check. A brush that took over the address
     *          fails the bounds check, because a KCD1 brush never moves.
     * @param brush The brush address.
     * @param bounds Its bounds when it was found.
     * @return True when the brush is the one seen earlier.
     * @note Main thread only.
     */
    [[nodiscard]] bool brush_matches(std::uintptr_t brush, const game_structures::Aabb &bounds) noexcept;

    /**
     * @brief Reports whether the game hides a render node (ERF_HIDDEN), or its flags do not read.
     * @return True when the node draws nothing.
     */
    [[nodiscard]] bool render_node_hidden(std::uintptr_t node) noexcept;

    /**
     * @brief Copies a render node's name (a brush's model path, an entity proxy's entity name).
     */
    [[nodiscard]] std::string render_node_name(std::uintptr_t node);

} // namespace HenrySenses

#endif // HENRYSENSES_VISUAL_RESOLVER_HPP
