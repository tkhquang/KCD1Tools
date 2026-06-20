/**
 * @file render_occlusion.hpp
 * @brief Render-node overhead clamp: keep the third-person camera out of render-only roofs.
 *
 * Some KCD1 roofs (tent / awning canopy cloth) are CBrush render meshes with no ray-collidable
 * physics, so the physics camera collision (RWI fan) glides through them and the cloth buries the
 * camera on a look-down. The renderer sees them via I3DEngine::GetObjectsInBox; this module queries
 * the render octree along the pivot->camera arm and reports the maximum camera distance before an
 * OVERHEAD brush, so the camera stays just below the roof. Every engine call is SEH-guarded and
 * degrades to "no clamp" so a layout or version drift can never crash the game.
 *
 * NOTE: KCD1 is the v1 OVERHEAD-AABB CLAMP ONLY. The KCD2 precise vertex/index render-mesh raster
 * (render_coverage_at / render_coverage_of_brush / render_hit_info) was not reversed for 1.9.7 and
 * is not ported; the clamp here uses each brush's cached world AABB, not its mesh.
 */
#ifndef TPVCAMERA_RENDER_OCCLUSION_HPP
#define TPVCAMERA_RENDER_OCCLUSION_HPP

#include "math_utils.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace TPVCamera
{

    /**
     * @brief Resolves the p3DEngine slot for the GetObjectsInBox render-octree query.
     * @details Best-effort: on a miss the render clamp simply no-ops (the camera still works), so callers
     *          treat a false return as "render occlusion unavailable". GetObjectsInBox itself is reached
     *          through the live C3DEngine vtable slot on each query.
     * @param module_base Base address of the scanned game module (WHGame.dll).
     * @param module_size Size of the scanned module image, in bytes.
     * @param g_env Resolved SSystemGlobalEnvironment base; p3DEngine = g_env + GENV_3DENGINE_OFFSET.
     * @return true once g_env is known.
     */
    [[nodiscard]] bool initialize_render_occlusion(uintptr_t module_base, size_t module_size, uintptr_t g_env);

    /**
     * @brief Maximum camera distance along @p to_camera before an OVERHEAD render-only brush occludes the view.
     * @details Queries the render octree (GetObjectsInBox) in a box bounding the pivot->camera arm and, for each
     *          visible (not ERF_HIDDEN) compact CBrush whose world AABB sits ABOVE the pivot and overlaps the
     *          pivot->camera sightline footprint, computes the camera distance along @p to_camera at which the
     *          arm rises to the brush underside and clamps the camera just below it (keeping @p radius standoff).
     *          This is the v1 overhead-AABB clamp: a brush's cached world AABB stands in for its mesh, so a steep
     *          look-down does not lift the camera into a canopy. World / terrain-scale brushes (largest dimension
     *          over RENDER_OCCLUSION_MAX_BRUSH_SIZE) are rejected. Returns the nearest qualifying limit, or
     *          std::nullopt when the renderer is unavailable or nothing overhead lies on the sightline.
     *          SEH-guarded; a fault returns std::nullopt.
     * @param pivot Camera arm start (inside the player), world space.
     * @param to_camera Pivot->camera vector; its length is the desired follow distance (not normalized).
     * @param radius Standoff kept below the roof underside (the collision radius), meters.
     */
    [[nodiscard]] std::optional<float> render_occlusion_limit(const Vector3 &pivot, const Vector3 &to_camera,
                                                              float radius);

} // namespace TPVCamera

#endif // TPVCAMERA_RENDER_OCCLUSION_HPP
