/**
 * @file render_occlusion.hpp
 * @brief Render-node overhead clamp: keep the third-person camera out of render-only roofs.
 *
 * Some KCD1 roofs (tent / awning canopy cloth) are CBrush render meshes with no ray-collidable
 * physics, so the physics camera collision (RWI fan / PWI sphere) glides through them and the cloth
 * buries the camera on a look-down. The renderer sees them via I3DEngine::GetObjectsInBox; this
 * module queries the render octree along the pivot->camera arm and reports the maximum camera
 * distance before an OVERHEAD brush, so the camera stays just below the roof. Every engine call is
 * SEH-guarded and degrades to "no clamp" so a layout or version drift can never crash the game.
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
     * @brief Resolves the p3DEngine slot for the render-octree queries.
     * @details Best-effort: on a miss the render clamp simply no-ops (the camera still works), so callers
     *          treat a false return as "render occlusion unavailable". The queries themselves are read from
     *          the live C3DEngine vtable whenever the engine object changes.
     * @param module_base Base address of the scanned game module (WHGame.dll).
     * @param module_size Size of the scanned module image, in bytes.
     * @param g_env Resolved SSystemGlobalEnvironment base; p3DEngine = g_env + GENV_3DENGINE_OFFSET.
     * @return true once g_env is known.
     */
    [[nodiscard]] bool initialize_render_occlusion(uintptr_t module_base, size_t module_size, uintptr_t g_env);

    /**
     * @brief Maximum camera distance along @p to_camera before an OVERHEAD render-only brush occludes the view.
     * @details Runs only when the camera sits above the pivot (a look-down), and re-queries only after the camera
     *          moves RENDER_OCCLUSION_REQUERY_DIST. Queries the render octree for the brushes in a box bounding the
     *          pivot->camera arm (the brush-typed GetObjectsByTypeInBox when the engine vtable has the expected
     *          layout, else GetObjectsInBox) and, for each compact CBrush, ray-marches its render-mesh vertices
     *          against the pivot->camera sightline to find the nearest distance at which its cloth lies on the view
     *          ray. A brush counts only when at least RENDER_OCCLUSION_MIN_COLUMN_VERTS of its vertices fall inside
     *          the sightline tube, so a thin beam / rope / rail does not jolt the camera while a canopy clamps.
     *          World / terrain-scale brushes (largest dimension over RENDER_OCCLUSION_MAX_BRUSH_SIZE) are rejected.
     *          Returns the nearest qualifying limit, or std::nullopt when the renderer is unavailable or nothing on
     *          the sightline occludes the view. SEH-guarded; a fault returns std::nullopt.
     * @param pivot Camera arm start (inside the player), world space.
     * @param to_camera Pivot->camera vector; its length is the desired follow distance (not normalized).
     * @param radius Standoff kept below the roof underside (the collision radius), meters.
     */
    [[nodiscard]] std::optional<float> render_occlusion_limit(const Vector3 &pivot, const Vector3 &to_camera,
                                                              float radius);

} // namespace TPVCamera

#endif // TPVCAMERA_RENDER_OCCLUSION_HPP
