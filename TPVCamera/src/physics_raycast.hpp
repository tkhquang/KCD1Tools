/**
 * @file physics_raycast.hpp
 * @brief Thin wrapper over the engine's IPhysicalWorld::RayWorldIntersection.
 *
 * Resolves the p_physical_world global once (a g_env member), then exposes a synchronous world
 * raycast used by the camera for collision (keep the view out of geometry) and aim convergence
 * (land the crosshair on the exact world target). RayWorldIntersection is reached through the LIVE
 * physical-world vtable slot (KCD1 has no AOB-resolvable inline helper). Every call is SEH-guarded
 * and degrades to "no hit" if the engine path faults or the physical world is not ready, so a layout
 * or version drift can never crash the game.
 *
 * KCD1 ports the RWI thin-ray + ray-fan AND the PWI swept-sphere (sphere_world_sweep). The
 * KCD2 silhouette-coverage raster (character_occluded_fraction and the static-brush /
 * collider-footprint helpers) is NOT ported. The PWI SPWIParams layout is the KCD1 1.9.7 fork's
 * (identical to KCD2; see constants.hpp). Every engine call is SEH-guarded.
 */
#ifndef TPVCAMERA_PHYSICS_RAYCAST_HPP
#define TPVCAMERA_PHYSICS_RAYCAST_HPP

#include "math_utils.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace TPVCamera
{

    /**
     * @struct RayHit
     * @brief Decoded subset of the engine ray_hit for a single nearest hit.
     */
    struct RayHit
    {
        /// World distance from the ray origin to the hit.
        float m_distance{0.0f};
        /// World-space hit position.
        Vector3 m_point{};
        /// Surface normal at the hit.
        Vector3 m_normal{};
        /// IPhysicalEntity* of the entity hit (ray path only).
        uintptr_t m_collider{0};
        /// Non-zero when the hit is the global TERRAIN heightmap (ray_hit.bTerrain); 0 for brushes. The
        /// engine's own ground flag -- used to always block the terrain (no under-world clip).
        int m_terrain{0};
    };

    /**
     * @brief Resolves the p_physical_world slot (a g_env member) for the RayWorldIntersection path.
     * @details Best-effort: with no physical world the raycast features simply no-op (the camera
     *          still works), so callers treat a false return as "raycast unavailable". RayWorldIntersection
     *          itself is resolved from the live world vtable slot on each ray, so once g_env is known the
     *          path is always considered available (true).
     * @param g_env Resolved SSystemGlobalEnvironment base; the p_physical_world slot is taken
     *              from g_env + PHYSICAL_WORLD_OFFSET (no second hardcoded address).
     * @return true once g_env is known.
     */
    [[nodiscard]] bool initialize_physics_raycast(uintptr_t module_base, size_t module_size, uintptr_t g_env);

    /**
     * @brief Synchronous world raycast.
     * @param origin Ray start in world space.
     * @param direction Ray vector; its length is the maximum ray length (not normalized).
     * @param objtypes entity_query_flags mask (which entity classes the ray can hit).
     * @param flags rwi_flags mask (pierceability and behaviour).
     * @param skip_ents Optional array of IPhysicalEntity* to ignore (RWI pSkipEnts); nullptr = none.
     * @param n_skip_ents Count of @p skip_ents.
     * @return The nearest hit, or std::nullopt on a miss or when physics is not ready.
     */
    [[nodiscard]] std::optional<RayHit> ray_world_intersection(const Vector3 &origin, const Vector3 &direction,
                                                               int objtypes, unsigned int flags,
                                                               const uintptr_t *skip_ents = nullptr,
                                                               int n_skip_ents = 0);

    /**
     * @brief Multi-ray "fan" approximation of a swept sphere, built on RayWorldIntersection.
     * @details Casts the centre ray plus four rays offset perpendicular to the sweep by @p radius (a square
     *          tube of half-width radius) and returns the NEAREST hit across all five. This approximates a
     *          swept sphere's edge-catching -- so the camera distance does not pump as a single thin ray grazes
     *          edges -- while keeping the CORRECT object-type filtering: RWI takes @p objtypes as a plain
     *          function argument (honoured). KCD1 has no PWI sphere path, so the fan is the only swept primitive.
     * @param origin Sweep start (the camera pivot), world space.
     * @param sweep Sweep vector (pivot -> camera); its length is the max distance (not normalized).
     * @param radius Half-width of the ray tube, world units (the swept-sphere radius / standoff).
     * @param objtypes entity_query_flags mask (world-only for the camera: ent_static | ent_terrain).
     * @param flags rwi_flags mask.
     * @param skip_ents Optional array of IPhysicalEntity* to ignore on every ray (nullptr = none).
     * @param n_skip_ents Count of @p skip_ents.
     * @return The nearest hit across the fan, or std::nullopt if every ray misses.
     */
    [[nodiscard]] std::optional<RayHit> ray_fan_sweep(const Vector3 &origin, const Vector3 &sweep, float radius,
                                                      int objtypes, unsigned int flags,
                                                      const uintptr_t *skip_ents = nullptr, int n_skip_ents = 0);

    /**
     * @brief True swept-sphere world cast via IPhysicalWorld::PrimitiveWorldIntersection (PWI).
     * @details Sweeps a sphere of @p radius from @p origin along @p sweep and returns the nearest contact as a
     *          RayHit whose m_distance is the swept distance (point/normal approximated along the sweep). The
     *          PWI struct's entTypes field is DEAD in this fork (the sphere queries ent_all), so @p p_skip_ents
     *          (the player's physics entities, from resolve_player_physics_skip) is the only way to keep the
     *          sweep off the player body; the caller must also gate the result against the RWI fan's world hit.
     *          SEH-guarded: a layout/version drift degrades to std::nullopt, never a crash.
     * @param origin Sphere centre at the sweep start (the camera pivot), world space.
     * @param radius Sphere radius (the standoff from surfaces), world units.
     * @param sweep Sweep vector (pivot -> camera); its length is the max sweep distance.
     * @param objtypes entity_query_flags (written to the DEAD entTypes slot; defensive no-op on this fork).
     * @param p_skip_ents Optional IPhysicalEntity* array to ignore (the player body/gear); nullptr = none.
     * @param n_skip_ents Count of @p p_skip_ents (impl-clamped to <= 4).
     * @return The nearest swept-sphere contact, or std::nullopt on a miss / when physics is not ready.
     */
    [[nodiscard]] std::optional<RayHit> sphere_world_sweep(const Vector3 &origin, float radius, const Vector3 &sweep,
                                                           int objtypes, const uintptr_t *p_skip_ents = nullptr,
                                                           int n_skip_ents = 0);

    /**
     * @brief Resolves the actor (player body / worn gear / NPC) physics entities on the pivot->camera arm, to
     *        skip on the PWI sphere sweep (whose entTypes filter is dead). Pure RWI: casts a REVERSE fan
     *        (camera -> pivot, since the pivot is inside the body) with the all-types and world-only masks and
     *        collects every collider that the all-types cast sees nearer than the world-only cast.
     * @param origin Sweep start (pivot), world space.   @param sweep Sweep vector (pivot -> camera).
     * @param radius Fan tube half-width (matches the sphere footprint).
     * @param objtypes_all entity_query_flags incl. actors (e.g. ent_all).  @param objtypes_world world-only mask.
     * @param flags rwi_flags.   @param out_skip Output IPhysicalEntity* buffer.   @param max_out Capacity.
     * @return Count of distinct actor colliders written to @p out_skip.
     */
    [[nodiscard]] int resolve_player_physics_skip(const Vector3 &origin, const Vector3 &sweep, float radius,
                                                  int objtypes_all, int objtypes_world, unsigned int flags,
                                                  uintptr_t *out_skip, int max_out);

} // namespace TPVCamera

#endif // TPVCAMERA_PHYSICS_RAYCAST_HPP
