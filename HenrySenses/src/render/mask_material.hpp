/**
 * @file render/mask_material.hpp
 * @brief The materials outline copies are drawn with.
 *
 * The silhouette mask takes only render items whose material has a CustomRenderPass technique (Illum and the other
 * character shaders). A vegetation material has none, so an outline copy of a herb or a brush draws with a mask
 * material instead. That is the source's own .mtl, loaded again with Shader="Illum" and an all but zero opacity. The
 * textures, alpha test and sub-material order stay, so the mask follows the leaf shapes. KCD1's Illum takes its
 * alpha from the material opacity only, because its object alpha factor is commented out. So the opacity keeps the
 * copy out of the scene (see constants::MASK_MATERIAL_OPACITY). A source that does not convert gets a plain Illum
 * material at the same opacity, which masks whole cards.
 */
#ifndef HENRYSENSES_MASK_MATERIAL_HPP
#define HENRYSENSES_MASK_MATERIAL_HPP

#include <cstdint>

namespace HenrySenses
{
    /**
     * @brief Starts a main-thread tick: renews the build budget (constants::MASK_MATERIAL_BUILDS_PER_TICK).
     * @note Main thread.
     */
    void begin_mask_material_tick() noexcept;

    /**
     * @brief Returns the material an outline copy of an object with material @p source is drawn with.
     * @details A source met for the first time is converted when the tick's budget allows, otherwise later.
     * @param source The object's own material (0 when unknown).
     * @return The mask material, or 0 when it is not built yet or none can be made.
     * @note Main thread.
     */
    [[nodiscard]] std::uintptr_t mask_material_for(std::uintptr_t source) noexcept;

    /**
     * @brief Reports whether a model drawn with @p material needs an outline copy.
     * @details A copy is needed when a chunk of its LOD 0 render mesh draws with a shader that has no CustomRenderPass
     *          technique. The object's word alone never reaches the silhouette mask then. Follows the tests of AddRenderElements (0x18028A2A4) and EF_BatchFlags (0x180529E00). A model without a
     *          readable render mesh needs a copy. Cached per model and material until reset_mask_materials().
     * @note Main thread.
     */
    [[nodiscard]] bool mesh_needs_mask_copy(std::uintptr_t stat_obj, std::uintptr_t material);

    /**
     * @brief Reports whether the last tick left a mask material unbuilt for lack of budget.
     * @note Main thread.
     */
    [[nodiscard]] bool mask_materials_pending() noexcept;

    /**
     * @brief Releases the mask materials (a level change or the unload).
     * @details The engine defers the delete, so a render list that still holds one stays valid.
     * @note Main thread, once no copy is published any more.
     */
    void reset_mask_materials() noexcept;

} // namespace HenrySenses

#endif // HENRYSENSES_MASK_MATERIAL_HPP
