/**
 * @file render/herb_outline.hpp
 * @brief Outline copies for herbs, static scenery and vegetation-shaded entity meshes.
 *
 * Some objects never carry a silhouette word to the mask. A herb is one instance in a merged-mesh vegetation cell,
 * drawn in one batch with every plant that shares its material. A pickable mushroom is a CVegetation node, whose render
 * never copies a word. A static brush has no word at all. A mesh whose material lacks a CustomRenderPass technique
 * (the Vegetation shader) carries the word but never reaches the mask.
 *
 * For each of these, the static-mesh render hook submits a copy once per frame through CStatObj::Render. The copy
 * uses the exact transform the engine draws the original with. It is a temporary render object at 1 % alpha that
 * carries the word and the camera distance. It draws with a mask material (render/mask_material), whose Illum
 * technique has the custom pass and whose near-zero opacity keeps the copy out of the scene. The scene keeps the
 * original, so a plant in the wind still sways.
 *
 * The render hook reads three published sets: herbs, static objects and entity meshes. [KCD2 marks brushes in place,
 * carries a herb's word through thread-local storage, and draws herbs with their own material.]
 */
#ifndef HENRYSENSES_HERB_OUTLINE_HPP
#define HENRYSENSES_HERB_OUTLINE_HPP

#include "game_structures.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace HenrySenses
{
    /**
     * @struct HerbOutlineItem
     * @brief One object to outline through a copy.
     */
    struct HerbOutlineItem
    {
        /// The transform the engine draws the original with.
        game_structures::Matrix34f world{};
        std::uintptr_t stat_obj{0};
        /// The silhouette word (styled and faded). 0 skips the object.
        std::uint32_t word{0};
        /// The mask material the copy draws with. 0 skips the object.
        std::uintptr_t material{0};
    };

    /**
     * @brief Resolves CStatObj::Render and clears the fault latch of a previous load.
     * @return True when copies can submit (the static-mesh render hook must be enabled as well).
     */
    bool initialize_herb_outline() noexcept;

    /**
     * @brief Drops the published sets.
     * @note Call only after the render hooks have been disabled and drained.
     */
    void shutdown_herb_outline() noexcept;

    /**
     * @brief Reports whether copies can submit: CStatObj::Render resolved and no submission faulted.
     * @return True when a published copy draws.
     */
    [[nodiscard]] bool herb_outline_ready() noexcept;

    /**
     * @brief Publishes the herbs to outline from the next frame on. An empty span stops them.
     * @details A set equal to the published one (same plants, words and materials) is not published again.
     * @note Main thread.
     */
    void publish_herb_outline(std::span<const HerbOutlineItem> items);

    /**
     * @brief Publishes the static objects (brushes) to outline from the next frame on. An empty span stops them.
     * @note Main thread.
     */
    void publish_static_outline(std::span<const HerbOutlineItem> items);

    /**
     * @brief Publishes the entity meshes to outline from the next frame on: the static meshes of highlighted entities
     *        whose material has no CustomRenderPass technique. An empty span stops them.
     * @note Main thread. [KCD2 has no entity copies]
     */
    void publish_entity_outline(std::span<const HerbOutlineItem> items);

    /**
     * @brief Reports whether an entity render proxy draws a static mesh whose material has no CustomRenderPass
     *        technique.
     * @details The silhouette word on the proxy alone never reaches the mask for such a mesh.
     * @param node A render node from render_node_of().
     * @note Main thread.
     */
    [[nodiscard]] bool entity_needs_outline_copy(std::uintptr_t node);

    /**
     * @brief Appends a copy, with @p word, of each static mesh of an entity render proxy that needs one.
     * @details A mesh whose mask material is not built yet is left out until a later call.
     * @param node A render node from render_node_of().
     * @param word The silhouette word on the proxy.
     * @param out Receives the copies.
     * @note Main thread.
     */
    void append_entity_outline(std::uintptr_t node, std::uint32_t word, std::vector<HerbOutlineItem> &out);

    /** @brief Number of herbs in the published set. */
    [[nodiscard]] std::size_t herb_outline_count() noexcept;

    /** @brief Number of entity meshes in the published set. */
    [[nodiscard]] std::size_t entity_outline_count() noexcept;

    /**
     * @brief Submits the published copies once per frame, on the first general-pass static-mesh render.
     * @details The render of a copy re-enters the hook with the same frame id, which the once-per-frame latch stops.
     * @param pass_info The SRenderingPassInfo of that render.
     * @param sorter The render-item sorter of that render (the copies sort with it), or nullptr.
     * @note Called by the static-mesh render hook on 3D-engine job threads.
     */
    void herb_outline_on_render(const void *pass_info, const void *sorter) noexcept;

} // namespace HenrySenses

#endif // HENRYSENSES_HERB_OUTLINE_HPP
