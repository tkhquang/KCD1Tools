/**
 * @file render_occlusion.cpp
 * @brief Implementation of the render-node overhead cloth camera clamp (see render_occlusion.hpp).
 *
 * Ports KCD2's render-only-cloth overhead clamp 1:1 (only the offset / vtable-slot constants differ, see
 * constants.hpp): each candidate CBrush on the pivot->camera sightline has its render-mesh vertices
 * (IStatObj -> IRenderMesh, GetPosPtr / FSL_READ) ray-marched against the sightline tube, so only ACTUAL
 * cloth on the line pulls the camera in. A loose AABB merely grazing the line does NOT clamp (the bug a
 * pure-AABB approach causes: a barn / woodshed roof whose bounding box corner clips the sightline while no
 * real surface is overhead). The KCD2 silhouette-coverage raster (useCoverageCollision) is intentionally
 * NOT ported. GetObjectsInBox / GetPosPtr are reached through live vtable slots (KCD1 has no AOB-resolvable
 * helper) and every engine read is SEH-guarded, so a layout / version drift degrades to "no clamp", never
 * a crash.
 */

#include "render_occlusion.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>

namespace TPVCamera
{

    // I3DEngine::GetObjectsInBox(this, const AABB* bbox, IRenderNode** p_out) -> count (see constants.hpp).
    // bbox is six floats (min.xyz, max.xyz); p_out == null returns the count only, else it memcpys the FULL
    // list with no cap, so the count is read first and the buffer sized to fit (capped at RENDER_OCCLUSION_MAX_NODES).
    using GetObjectsInBoxFn = std::uint32_t(__fastcall *)(void *p3d_engine, const float *bbox, void **out_list);
    // C3DEngine::GetObjectsByTypeInBox(this, EERType type, const AABB* bbox, IRenderNode** p_out) -> count (see
    // constants.hpp).
    using GetObjectsByTypeInBoxFn = std::uint32_t(__fastcall *)(void *p3d_engine, std::uint32_t type, const float *bbox,
                                                                void **out_list);
    // IRenderNode::GetRenderNodeType (vtable slot 7 / +0x38) -> EERType (EERTYPE_BRUSH == 1).
    using GetRenderNodeTypeFn = int(__fastcall *)(void *node);
    // IRenderMesh::GetPosPtr(int& stride, uint flags, int offset) -> uint8* to the engine-decoded float3 CPU
    // position cache (vtable slot, see constants). KCD1 slot 43: returns the cache and sets
    // *stride = 12 (float3); FSL_READ (0x01) takes the cache-decode/build path.
    using GetPosPtrFn = std::uint8_t *(__fastcall *)(void *render_mesh, int *out_stride, unsigned int flags,
                                                     int offset);

    // Address of the p3DEngine global (a g_env member). Read fresh per query: it is set once the 3DEngine
    // is created and is screened before use; deriving it from the patch-resilient g_env base avoids a
    // second hardcoded address.
    static uintptr_t s_p3d_engine_slot_addr = 0;
    // Mapped range of the scanned game module, captured once. A freshly read p3DEngine must carry a vtable
    // inside this image or it is rejected before the indirect call (branch-only contains() test, no syscall).
    static DMK::Region s_game_module{};

    // The octree queries, read from the live engine vtable by refresh_brush_query(): the untyped GetObjectsInBox, and
    // the brush-typed query when that vtable has the expected layout (else null). s_brush_query_vtable is the engine
    // vtable the decision was made for, so it is re-made only when the engine object changes. Render-thread only.
    static GetObjectsInBoxFn s_get_objects_in_box = nullptr;
    static GetObjectsByTypeInBoxFn s_get_objects_by_type_in_box = nullptr;
    static uintptr_t s_brush_query_vtable = 0;

    /**
     * @brief Selects the octree queries for the engine vtable @p p3d_vtable: GetObjectsInBox from its slot, and the
     *        brush-typed query when both slots read as the expected wrapper pair.
     * @details The typed query visits only brushes, which is what every consumer here keeps, instead of every render
     *          node in the box. Both queries are reached through the engine vtable, not an AOB anchor, so the slot
     *          numbering is pinned by the two slot heads (Aob::k_engine3dTypedQueryHead / k_engine3dUntypedQueryHead),
     *          which also prove the typed query's argument layout. Both slots must lie in the game image. The
     *          decision is logged when it changes. Called outside any structured-exception frame, before the guarded
     *          queries.
     * @param p3d_vtable The vtable of the engine object read this call (in-image, screened by the caller).
     */
    static void refresh_brush_query(uintptr_t p3d_vtable)
    {
        if (p3d_vtable == s_brush_query_vtable)
        {
            return;
        }
        s_brush_query_vtable = p3d_vtable;

        const auto untyped_slot = DMK::memory::read<uintptr_t>(
            DMK::Address{p3d_vtable + Constants::ENGINE3D_VTABLE_GET_OBJECTS_IN_BOX_OFFSET});
        const auto typed_slot = DMK::memory::read<uintptr_t>(
            DMK::Address{p3d_vtable + Constants::ENGINE3D_VTABLE_GET_OBJECTS_BY_TYPE_IN_BOX_OFFSET});
        const bool untyped_ok = untyped_slot && s_game_module.contains(DMK::Address{*untyped_slot});
        s_get_objects_in_box = untyped_ok ? reinterpret_cast<GetObjectsInBoxFn>(*untyped_slot) : nullptr;

        GetObjectsByTypeInBoxFn typed = nullptr;
        if (untyped_ok && typed_slot && s_game_module.contains(DMK::Address{*typed_slot}) &&
            code_window_matches(*untyped_slot, Aob::k_engine3dUntypedQueryHead,
                                Aob::k_engine3dUntypedQueryHead.max_match_length(), s_game_module) &&
            code_window_matches(*typed_slot, Aob::k_engine3dTypedQueryHead,
                                Aob::k_engine3dTypedQueryHead.max_match_length(), s_game_module))
        {
            typed = reinterpret_cast<GetObjectsByTypeInBoxFn>(*typed_slot);
        }
        s_get_objects_by_type_in_box = typed;

        if (typed != nullptr)
        {
            (void)DMK::log().try_log(DMK::LogLevel::Debug,
                                     "RenderOcclusion: brush queries through GetObjectsByTypeInBox {}",
                                     DMK::format::format_address(reinterpret_cast<uintptr_t>(typed)));
        }
        else if (!untyped_ok)
        {
            (void)DMK::log().try_log(DMK::LogLevel::Warning,
                                     "RenderOcclusion: the GetObjectsInBox slot of engine vtable {} is not in the game "
                                     "image; render occlusion disabled",
                                     DMK::format::format_address(p3d_vtable));
        }
        else
        {
            (void)DMK::log().try_log(DMK::LogLevel::Warning,
                                     "RenderOcclusion: GetObjectsByTypeInBox is not next to GetObjectsInBox in the "
                                     "engine vtable; brush queries filter the full octree query instead");
        }
    }

    /**
     * @brief Fills @p nodes with the render nodes in @p bbox that can be brushes and returns how many it wrote.
     * @details The brush-typed query when refresh_brush_query() selected it, else the untyped one (whose other node
     *          types the caller's own EERTYPE_BRUSH filter drops). Both copy their full result without a
     *          size limit, so the count is taken first and the list is filled only when it fits with
     *          RENDER_OCCLUSION_NODE_SLACK to spare, covering nodes registered between the two calls. The return is
     *          the FILL call's count (a node removed in between must not leave a stale slot in range), bounded by
     *          the buffer. POD-only: called inside the caller's structured-exception frame, which contains a fault.
     * @param p3d The engine object.
     * @param bbox Query box {min.xyz, max.xyz}.
     * @param nodes Buffer of RENDER_OCCLUSION_MAX_NODES entries.
     * @return The number of entries written, 0 when the box is empty or holds more candidates than fit.
     */
    static std::uint32_t query_brush_nodes(void *p3d, const float *bbox, void **nodes) noexcept
    {
        constexpr auto k_capacity = static_cast<std::uint32_t>(Constants::RENDER_OCCLUSION_MAX_NODES);
        constexpr auto k_fit =
            static_cast<std::uint32_t>(Constants::RENDER_OCCLUSION_MAX_NODES - Constants::RENDER_OCCLUSION_NODE_SLACK);
        const GetObjectsByTypeInBoxFn typed = s_get_objects_by_type_in_box;
        const auto brush_type = static_cast<std::uint32_t>(Constants::EERTYPE_BRUSH);

        const std::uint32_t count =
            (typed != nullptr) ? typed(p3d, brush_type, bbox, nullptr) : s_get_objects_in_box(p3d, bbox, nullptr);
        if (count == 0 || count > k_fit)
        {
            return 0;
        }
        const std::uint32_t copied =
            (typed != nullptr) ? typed(p3d, brush_type, bbox, nodes) : s_get_objects_in_box(p3d, bbox, nodes);
        return (copied < k_capacity) ? copied : k_capacity;
    }

    bool initialize_render_occlusion(uintptr_t module_base, size_t module_size, uintptr_t g_env)
    {
        DMK::Logger &logger = DMK::log();

        if (g_env == 0)
        {
            logger.warning("RenderOcclusion: g_env not resolved; render occlusion unavailable");
            return false;
        }

        s_p3d_engine_slot_addr = g_env + Constants::GENV_3DENGINE_OFFSET;
        s_game_module = DMK::Region{DMK::Address{module_base}, module_size};

        logger.info(
            "RenderOcclusion: GetObjectsInBox via C3DEngine vtable slot {}, p3DEngine slot at {}",
            DMK::format::format_address(static_cast<uintptr_t>(Constants::ENGINE3D_VTABLE_GET_OBJECTS_IN_BOX_OFFSET)),
            DMK::format::format_address(s_p3d_engine_slot_addr));
        return true;
    }

    // Sentinel: this brush has no readable cloth on the sightline (unreadable mesh, or fewer than
    // RENDER_OCCLUSION_MIN_COLUMN_VERTS vertices on the tube); the caller maps it to "no clamp".
    static constexpr float k_cloth_unavailable = 1e9f;

    // Identity of the cloth the clamp selected, captured for trace logging so false positives (a sign / pole /
    // wall chunk that passed the filters instead of a real canopy) can be identified. POD, so it is filled
    // inside the SEH frame and read / logged outside it.
    struct RoofHitInfo
    {
        void *node = nullptr;
        void *statobj = nullptr;
        float roof_z = 0.0f;
        float min_x = 0.0f, min_y = 0.0f, min_z = 0.0f;
        float max_x = 0.0f, max_y = 0.0f, max_z = 0.0f;
    };

    // Best-effort, SEH-guarded copy of a brush's full .cgf path for trace logging only. The field at
    // statobj + STATOBJ_CGF_NAME_OFFSET is a CryString (a POINTER to the path chars), so it is dereferenced
    // once. POD body; non-printable bytes become '.', so a wrong offset / null / bad pointer logs harmlessly.
    static void copy_brush_name(void *statobj, char *out, int cap) noexcept
    {
        if (cap > 0)
        {
            out[0] = '\0';
        }
        if (statobj == nullptr || cap <= 1)
        {
            return;
        }
        __try
        {
            const char *p = *reinterpret_cast<const char *const *>(reinterpret_cast<std::byte *>(statobj) +
                                                                   Constants::STATOBJ_CGF_NAME_OFFSET);
            if (p == nullptr)
            {
                return;
            }
            int i = 0;
            for (; i < cap - 1; ++i)
            {
                const char c = p[i];
                if (c == '\0')
                {
                    break;
                }
                out[i] = (c >= 32 && c < 127) ? c : '.';
            }
            out[i] = '\0';
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            out[0] = '\0';
        }
    }

    /**
     * @brief Furthest the camera may sit from the pivot before this brush's cloth occludes the sightline.
     * @details node is the CBrush. Walks node -> IStatObj -> IRenderMesh, reads the engine-decoded float3 CPU
     *          position cache (GetPosPtr / FSL_READ), transforms each vertex to world by the brush Matrix34, and
     *          returns the SMALLEST distance d along the pivot->camera arm at which a cloth vertex comes within
     *          RENDER_OCCLUSION_COLUMN_RADIUS of the sightline - i.e. the camera at distance d would just begin to
     *          see cloth between itself and the character. An analytic ray-march of the view ray against the cloth
     *          point cloud (each vertex stands in for the surface; the tube radius covers the gaps and doubles as
     *          the standoff). It naturally ignores the tent's vertical walls / skirts: once the camera is below the
     *          canopy the short remaining sightline to the central character clears them. @p dir is the unit
     *          pivot->camera direction and @p arm_len its length. Returns k_cloth_unavailable when the mesh is
     *          unreadable or fewer than RENDER_OCCLUSION_MIN_COLUMN_VERTS vertices lie on the sightline. POD-only
     *          (runs in the caller's SEH frame).
     */
    static float cloth_sightline_block_distance(void *node, Vector3 pivot, Vector3 dir, float arm_len, uintptr_t mod_lo,
                                                uintptr_t mod_hi)
    {
        auto *bytes = reinterpret_cast<std::byte *>(node);
        void *statobj = *reinterpret_cast<void **>(bytes + Constants::CBRUSH_STATOBJ_OFFSET);
        if (statobj == nullptr)
        {
            return k_cloth_unavailable;
        }
        void *rmesh =
            *reinterpret_cast<void **>(reinterpret_cast<std::byte *>(statobj) + Constants::STATOBJ_RENDERMESH_OFFSET);
        if (rmesh == nullptr)
        {
            return k_cloth_unavailable;
        }
        const int n_verts =
            *reinterpret_cast<int *>(reinterpret_cast<std::byte *>(rmesh) + Constants::RENDERMESH_NVERTS_OFFSET);
        if (n_verts <= 0 || n_verts > Constants::RENDER_OCCLUSION_VERT_MAX)
        {
            return k_cloth_unavailable;
        }

        void **rm_vt = *reinterpret_cast<void ***>(rmesh);
        const auto get_pos = reinterpret_cast<GetPosPtrFn>(rm_vt[Constants::RENDERMESH_VTABLE_GETPOSPTR_OFFSET / 8]);
        const auto get_pos_addr = reinterpret_cast<uintptr_t>(get_pos);
        if (get_pos_addr < mod_lo || get_pos_addr >= mod_hi)
        {
            return k_cloth_unavailable; // vtable slot does not point into the game image (patched / wrong layout)
        }

        int stride = 0;
        const std::uint8_t *pos = get_pos(rmesh, &stride, Constants::IRENDERMESH_FSL_READ, 0);
        if (pos == nullptr)
        {
            return k_cloth_unavailable;
        }
        if (stride <= 0)
        {
            stride = 12; // decoded position cache is tightly packed float3
        }

        // Brush world matrix (row-major Matrix34: row r = M[4r..4r+3], translation in column 3).
        const float *M = reinterpret_cast<const float *>(bytes + Constants::CBRUSH_MATRIX_OFFSET);

        const float colr = Constants::RENDER_OCCLUSION_COLUMN_RADIUS;
        const float colr2 = colr * colr;
        float best = k_cloth_unavailable;
        int hits = 0;
        for (int v = 0; v < n_verts; ++v)
        {
            const auto *lp = reinterpret_cast<const float *>(pos + static_cast<size_t>(v) * stride);
            const float lx = lp[0], ly = lp[1], lz = lp[2];
            const float wx = M[0] * lx + M[1] * ly + M[2] * lz + M[3];
            const float wy = M[4] * lx + M[5] * ly + M[6] * lz + M[7];
            const float wz = M[8] * lx + M[9] * ly + M[10] * lz + M[11];
            // Project the vertex onto the arm: tpar = signed distance from the pivot along dir; the leftover is
            // the perpendicular (off-axis) distance. Only vertices BETWEEN the character and the camera matter.
            const float rx = wx - pivot.x, ry = wy - pivot.y, rz = wz - pivot.z;
            const float tpar = rx * dir.x + ry * dir.y + rz * dir.z;
            if (tpar <= 0.0f || tpar > arm_len)
            {
                continue;
            }
            const float ex = rx - tpar * dir.x, ey = ry - tpar * dir.y, ez = rz - tpar * dir.z;
            const float perp2 = ex * ex + ey * ey + ez * ez;
            if (perp2 > colr2)
            {
                continue; // cloth is too far off the sightline to occlude it
            }
            // Distance along the arm at which this vertex first enters the colr tube of the growing sightline:
            // the camera must stop short of it. (At this distance the vertex is exactly colr away = the standoff.)
            const float d = tpar - std::sqrt(colr2 - perp2);
            if (d <= 0.0f)
            {
                // The cloth is within colr of the pivot itself: the CHARACTER is in / touching it (e.g. standing
                // amid hanging laundry), not occluded by it from a distance. No camera pull-in helps, so it is
                // NOT an occluder - otherwise the camera would collapse onto the character (the blockDist=0 bug).
                continue;
            }
            ++hits;
            if (d < best)
            {
                best = d;
            }
        }
        return (hits >= Constants::RENDER_OCCLUSION_MIN_COLUMN_VERTS) ? best : k_cloth_unavailable;
    }

    /**
     * @brief SEH-isolated octree query plus sightline ray-march over the candidate brushes. POD-only body so
     *        the structured handler shares no frame with C++ unwinding; any fault becomes "no occluder". Returns
     *        the SMALLEST clear distance along the pivot->camera arm over every brush whose cloth lies on the
     *        sightline (k_cloth_unavailable when none do). Fills @p out_hit with the binding brush's identity.
     */
    static float nearest_sightline_block_guarded(void *p3d, const float *bbox, Vector3 pivot, Vector3 camera,
                                                 uintptr_t mod_lo, uintptr_t mod_hi, RoofHitInfo *out_hit) noexcept
    {
        float best_dist = k_cloth_unavailable;
        __try
        {
            Vector3 dir = camera - pivot;
            const float arm_len = dir.magnitude();
            if (arm_len < 1e-3f)
            {
                return k_cloth_unavailable;
            }
            dir.x /= arm_len;
            dir.y /= arm_len;
            dir.z /= arm_len;

            void *nodes[Constants::RENDER_OCCLUSION_MAX_NODES];
            const std::uint32_t count = query_brush_nodes(p3d, bbox, nodes);
            if (count == 0)
            {
                return k_cloth_unavailable;
            }

            const float colr = Constants::RENDER_OCCLUSION_COLUMN_RADIUS;
            const float los_min_x = (pivot.x < camera.x ? pivot.x : camera.x) - colr;
            const float los_max_x = (pivot.x > camera.x ? pivot.x : camera.x) + colr;
            const float los_min_y = (pivot.y < camera.y ? pivot.y : camera.y) - colr;
            const float los_max_y = (pivot.y > camera.y ? pivot.y : camera.y) + colr;

            for (std::uint32_t i = 0; i < count; ++i)
            {
                void *node = nodes[i];
                if (node == nullptr)
                {
                    continue;
                }
                // No ERF_HIDDEN gate here, unlike KCD2. GetObjectsInBox is a spatial query, not a visibility one, so
                // it returns hidden placements too, but KCD1's IRenderNode::m_dwRndFlags offset is unknown: the dword
                // at +0x34 is a render-state word whose bit 8 is SET on many VISIBLE brushes, so gating on it would
                // skip real canopies before the ray-march. The per-vertex ray-march below clamps only on cloth
                // actually on the sightline (at least RENDER_OCCLUSION_MIN_COLUMN_VERTS vertices in the tube), which
                // in every observed case rejects the conditional rag and laundry placements that gate exists for.

                void **vt = *reinterpret_cast<void ***>(node);
                const auto vtaddr = reinterpret_cast<uintptr_t>(vt);
                if (vtaddr < mod_lo || vtaddr >= mod_hi)
                {
                    continue; // vtable not in the game image -> not a render node we can trust
                }
                const auto get_type =
                    reinterpret_cast<GetRenderNodeTypeFn>(vt[Constants::RENDERNODE_VTABLE_GETTYPE_OFFSET / 8]);
                if (get_type(node) != Constants::EERTYPE_BRUSH)
                {
                    continue; // only solid static brushes are roofs (skip lights / particles / fog / decals)
                }

                // KCD1 reads the cached world AABB directly (+0xAC / +0xB8) for the cheap size +
                // footprint pre-reject; KCD2 calls IRenderNode::GetBBox() for the same world AABB. Equivalent data:
                // the per-VERTEX ray-march below (not the AABB) decides occlusion, so this is only a coarse gate.
                auto *bytes = reinterpret_cast<std::byte *>(node);
                const float *bmin = reinterpret_cast<const float *>(bytes + Constants::CBRUSH_AABB_MIN_OFFSET);
                const float *bmax = reinterpret_cast<const float *>(bytes + Constants::CBRUSH_AABB_MAX_OFFSET);
                const float min_x = bmin[0], min_y = bmin[1], min_z = bmin[2];
                const float max_x = bmax[0], max_y = bmax[1], max_z = bmax[2];
                const float sx = max_x - min_x, sy = max_y - min_y, sz = max_z - min_z;
                if (!std::isfinite(sx) || !std::isfinite(sy) || !std::isfinite(sz) || sx < 0.0f || sy < 0.0f ||
                    sz < 0.0f)
                {
                    continue; // degenerate / unreadable AABB
                }

                // Skip world / terrain (merged static cells, building shells): only compact props are roofs.
                if (sx > Constants::RENDER_OCCLUSION_MAX_BRUSH_SIZE ||
                    sy > Constants::RENDER_OCCLUSION_MAX_BRUSH_SIZE || sz > Constants::RENDER_OCCLUSION_MAX_BRUSH_SIZE)
                {
                    continue;
                }
                // NOTE: no brush-level "overhead" (min_z > pivot.z) gate here. Tent / awning brushes whose
                // posts and skirts reach the ground have a bbox bottom BELOW the pivot, yet their canopy cloth
                // hangs above it - a coarse bbox test wrongly rejected exactly the brushes that cover the view.
                // Occlusion is decided per VERTEX in cloth_sightline_block_distance (only cloth on the
                // pivot->camera sightline counts), so the ground under the character is naturally excluded.

                // Cheap reject: the brush must overlap the sightline footprint in XY (pivot->camera AABB,
                // expanded by the tube radius). A camera parked at a tent edge still has a sightline back to
                // the character that passes under the canopy, so this is a sightline test, not "camera under it".
                if (max_x < los_min_x || min_x > los_max_x || max_y < los_min_y || min_y > los_max_y)
                {
                    continue;
                }

                // Ray-march this brush's cloth: the furthest arm distance still clear of it. Only ACTUAL cloth
                // vertices on the sightline count (no AABB fallback); a brush the sightline misses returns
                // k_cloth_unavailable and is skipped. The nearest occluder across all brushes wins.
                const float d = cloth_sightline_block_distance(node, pivot, dir, arm_len, mod_lo, mod_hi);
                if (d >= k_cloth_unavailable)
                {
                    continue;
                }
                if (d < best_dist)
                {
                    best_dist = d;
                    out_hit->node = node;
                    out_hit->statobj = *reinterpret_cast<void **>(bytes + Constants::CBRUSH_STATOBJ_OFFSET);
                    out_hit->roof_z = pivot.z + d * dir.z; // world-Z of the block point on the sightline
                    out_hit->min_x = min_x;
                    out_hit->min_y = min_y;
                    out_hit->min_z = min_z;
                    out_hit->max_x = max_x;
                    out_hit->max_y = max_y;
                    out_hit->max_z = max_z;
                }
            }

            // Intentionally NO body-silhouette coverage gate: an overhead canopy sits ABOVE the character body
            // box, so its projected silhouette coverage is ~0 and a coverage gate would reject exactly the cloth
            // it is meant to clamp. Thin beams / ropes are rejected instead by cloth_sightline_block_distance,
            // which requires RENDER_OCCLUSION_MIN_COLUMN_VERTS cloth vertices on the pivot->camera tube to count.
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return k_cloth_unavailable;
        }
        return best_dist;
    }

    std::optional<float> render_occlusion_limit(const Vector3 &pivot, const Vector3 &to_camera, float radius)
    {
        DMK_PROFILE_SCOPE("camera.render_occlusion");
        if (s_p3d_engine_slot_addr == 0)
        {
            return std::nullopt;
        }

        const float desired = to_camera.magnitude();
        if (desired < 1e-3f)
        {
            return std::nullopt;
        }
        const Vector3 camera = pivot + to_camera;

        // Overhead-only fast reject: a render-only roof can occlude the sightline only when the camera sits ABOVE
        // the pivot (a look-down raises it over the character). When the camera is at or below the pivot the
        // pivot->camera sightline only descends, so no overhead brush can lie on it - skip the whole octree query.
        // This removes the render-octree cost from level and upward looks, which is most of normal play.
        if (camera.z <= pivot.z)
        {
            return std::nullopt;
        }

        // Throttle: the cloth is a STATIC brush, so the octree query + sightline ray-march is re-run only when
        // the camera has moved more than RENDER_OCCLUSION_REQUERY_DIST from the last query; otherwise the cached
        // clear distance is reused (the collision easing still runs smoothly). This collapses the per-frame cost
        // to ~nothing while standing still. Single render-thread caller, so plain statics are race-free.
        static bool s_cache_valid = false;
        static Vector3 s_cache_cam{};
        static float s_cache_block = k_cloth_unavailable;

        const float requery_d2 = Constants::RENDER_OCCLUSION_REQUERY_DIST * Constants::RENDER_OCCLUSION_REQUERY_DIST;
        const Vector3 dcam = camera - s_cache_cam;
        const float moved2 = dcam.x * dcam.x + dcam.y * dcam.y + dcam.z * dcam.z;
        if (!s_cache_valid || moved2 > requery_d2)
        {
            float block = k_cloth_unavailable;
            RoofHitInfo hit{};

            // Resolve p3DEngine fresh and screen it (set once the 3DEngine exists; must carry an in-image vtable),
            // then select the octree queries from the live C3DEngine vtable (refresh_brush_query).
            const auto p3d = DMK::memory::read<uintptr_t>(DMK::Address{s_p3d_engine_slot_addr});
            if (p3d && *p3d != 0 && DMK::memory::is_plausible_ptr(DMK::Address{*p3d}))
            {
                const auto vtable = DMK::memory::read<uintptr_t>(DMK::Address{*p3d});
                if (vtable && DMK::memory::is_plausible_ptr(DMK::Address{*vtable}) &&
                    s_game_module.contains(DMK::Address{*vtable}))
                {
                    refresh_brush_query(*vtable);
                    if (s_get_objects_in_box != nullptr)
                    {
                        // Query box bounding the pivot->camera arm, expanded by the standoff.
                        const float margin = radius + 0.05f;
                        float bbox[6];
                        bbox[0] = std::min(pivot.x, camera.x) - margin;
                        bbox[1] = std::min(pivot.y, camera.y) - margin;
                        bbox[2] = std::min(pivot.z, camera.z) - margin;
                        bbox[3] = std::max(pivot.x, camera.x) + margin;
                        bbox[4] = std::max(pivot.y, camera.y) + margin;
                        bbox[5] = std::max(pivot.z, camera.z) + margin;
                        block =
                            nearest_sightline_block_guarded(reinterpret_cast<void *>(*p3d), bbox, pivot, camera,
                                                            s_game_module.base.raw(), s_game_module.end().raw(), &hit);
                    }
                }
            }

            s_cache_block = block;
            s_cache_cam = camera;
            s_cache_valid = true;

            // Trace WHAT the clamp latched onto, so a false positive (a prop / wall chunk on the sightline
            // instead of a real canopy) is identifiable by name + size + position. Logged only on a re-query
            // that produced a REAL clamp (block < desired), so it neither spams every frame nor logs misses.
            if (block < desired && DMK::log().is_enabled(DMK::LogLevel::Trace))
            {
                char name[256];
                copy_brush_name(hit.statobj, name, static_cast<int>(sizeof(name)));
                DMK::log().trace("RenderOcclusion HIT: cgf=\"{}\" node={} statobj={} blockDist={} of {} blockZ={} "
                                 "sizeXYZ=({}, {}, {}) bboxMin=({}, {}, {}) cam=({}, {}, {}) pivot=({}, {}, {})",
                                 name, DMK::format::format_address(reinterpret_cast<uintptr_t>(hit.node)),
                                 DMK::format::format_address(reinterpret_cast<uintptr_t>(hit.statobj)), block, desired,
                                 hit.roof_z, hit.max_x - hit.min_x, hit.max_y - hit.min_y, hit.max_z - hit.min_z,
                                 hit.min_x, hit.min_y, hit.min_z, camera.x, camera.y, camera.z, pivot.x, pivot.y,
                                 pivot.z);
            }
        }

        // The cached clear distance IS the allowed camera distance from the pivot: cloth occludes beyond it.
        if (s_cache_block >= desired)
        {
            return std::nullopt; // no cloth on the sightline within reach
        }
        return std::max(0.0f, s_cache_block);
    }

} // namespace TPVCamera
