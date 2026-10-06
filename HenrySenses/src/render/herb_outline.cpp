/**
 * @file render/herb_outline.cpp
 * @brief Outline copies for herbs, static scenery and vegetation-shaded entity meshes.
 */

#include "render/herb_outline.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "render/engine_silhouette.hpp"
#include "render/mask_material.hpp"
#include "engine/entity_access.hpp"
#include "engine/seh.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace HenrySenses
{
    namespace
    {
        using StatObjRenderFn = void(__fastcall *)(std::uintptr_t stat_obj, const void *params, const void *pass_info);

        using Snapshot = std::vector<HerbOutlineItem>;

        /**
         * @brief The view cone a herb copy must touch to be submitted: cos 80 degrees, wider than any field of view.
         * @details PLANT_RADIUS widens it for the size of the plant. Each submission builds a temporary render object
         *          the render thread compiles, so the cone spares it the plants behind the player. Static and entity
         *          copies are few and large, so they skip it.
         */
        constexpr float VIEW_CONE_COS = 0.17364818f;
        constexpr float PLANT_RADIUS = 1.0f;

        std::atomic<std::uintptr_t> s_render_fn{0};
        std::atomic<bool> s_faulted{false};
        std::atomic<std::shared_ptr<const Snapshot>> s_snapshot{};
        std::atomic<std::shared_ptr<const Snapshot>> s_static_snapshot{};
        std::atomic<std::shared_ptr<const Snapshot>> s_entity_snapshot{};
        std::atomic<std::size_t> s_count{0};
        std::atomic<std::size_t> s_static_count{0};
        std::atomic<std::size_t> s_entity_count{0};
        /// An entity draws a few meshes. More slots than this are left out.
        constexpr std::size_t ENTITY_MESHES_MAX = 8;
        /// The frame whose copies were submitted. A copy's own render re-enters the hook with the same frame and stops.
        std::atomic<std::int32_t> s_last_frame{std::numeric_limits<std::int32_t>::min()};

        /// Submission cost, reported every REPORT_MS.
        constexpr std::int64_t REPORT_MS = 10000;
        std::atomic<std::uint64_t> s_submit_frames{0};
        std::atomic<std::uint64_t> s_submit_plants{0};
        std::atomic<std::uint64_t> s_submit_drawn{0};
        std::atomic<std::uint64_t> s_submit_us{0};
        std::atomic<std::int64_t> s_next_report_ms{0};

        [[nodiscard]] std::int64_t steady_us() noexcept
        {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                       std::chrono::steady_clock::now().time_since_epoch()
            )
                .count();
        }

        [[nodiscard]] bool
        guarded_render(std::uintptr_t fn, std::uintptr_t stat_obj, const void *params, const void *pass_info) noexcept
        {
            __try
            {
                reinterpret_cast<StatObjRenderFn>(fn)(stat_obj, params, pass_info);
                return true;
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return false;
            }
        }

        /** @brief The pass camera's position and unit view direction. */
        struct CameraView
        {
            game_structures::Vec3f eye{};
            game_structures::Vec3f forward{};
        };

        /**
         * @brief Reads the pass camera's world matrix: the translation column is its position, the Y column its view
         *        direction (CCamera::GetViewdir).
         * @param pass_info The SRenderingPassInfo the hook was handed (live for the call, so read directly).
         */
        [[nodiscard]] bool guarded_camera_view(const void *pass_info, CameraView *out) noexcept
        {
            static_assert(
                constants::CAMERA_POSITION_X_OFFSET == 0x0C && constants::CAMERA_POSITION_Y_OFFSET == 0x1C &&
                    constants::CAMERA_POSITION_Z_OFFSET == 0x2C,
                "The camera position is the translation column of a Matrix34 at the camera's start."
            );
            const auto *pass = static_cast<const std::uint8_t *>(pass_info);
            const auto camera = *reinterpret_cast<const std::uintptr_t *>(pass + constants::PASS_INFO_CAMERA_OFFSET);
            if (!DMK::memory::is_plausible_ptr(DMK::Address{camera}))
            {
                return false;
            }
            const auto world = DMK::memory::read<game_structures::Matrix34f>(DMK::Address{camera});
            if (!world)
            {
                return false;
            }
            out->eye = game_structures::Vec3f{world->m[0][3], world->m[1][3], world->m[2][3]};
            const game_structures::Vec3f f{world->m[0][1], world->m[1][1], world->m[2][1]};
            const float length = std::sqrt(f.x * f.x + f.y * f.y + f.z * f.z);
            if (!std::isfinite(out->eye.x) || !std::isfinite(out->eye.y) || !std::isfinite(out->eye.z) ||
                !std::isfinite(length) || length < 1e-3f)
            {
                return false;
            }
            out->forward = game_structures::Vec3f{f.x / length, f.y / length, f.z / length};
            return true;
        }

        /**
         * @struct PlantSight
         * @brief A plant's distance from the pass camera and whether the camera can see it.
         */
        struct PlantSight
        {
            float distance{0.0f};
            /// False behind the camera or well outside any field of view.
            bool in_view{true};
        };

        /** @brief Measures a plant's distance from the pass camera and tests it against the view cone. */
        [[nodiscard]] PlantSight plant_sight(const game_structures::Matrix34f &world, const CameraView &view) noexcept
        {
            const float dx = world.m[0][3] - view.eye.x;
            const float dy = world.m[1][3] - view.eye.y;
            const float dz = world.m[2][3] - view.eye.z;
            const float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
            const float along = dx * view.forward.x + dy * view.forward.y + dz * view.forward.z;
            return PlantSight{distance, distance <= PLANT_RADIUS || along >= distance * VIEW_CONE_COS - PLANT_RADIUS};
        }

        /**
         * @brief Scales @p world about the camera so the herb sits constants::HERB_DEPTH_PULL nearer.
         * @details Every vertex stays on its own view ray, so the herb covers exactly the same pixels and only its
         *          depth changes.
         */
        [[nodiscard]] game_structures::Matrix34f
        pulled_toward_camera(const game_structures::Matrix34f &world, const game_structures::Vec3f &camera) noexcept
        {
            const float eye[3] = {camera.x, camera.y, camera.z};
            const float dx = world.m[0][3] - eye[0];
            const float dy = world.m[1][3] - eye[1];
            const float dz = world.m[2][3] - eye[2];
            const float distance = std::sqrt(dx * dx + dy * dy + dz * dz);
            if (distance <= 0.0f)
            {
                return world;
            }
            const float k =
                std::max(1.0f - constants::HERB_DEPTH_PULL / distance, constants::HERB_DEPTH_PULL_MIN_SCALE);
            game_structures::Matrix34f pulled{};
            for (int row = 0; row < 3; ++row)
            {
                for (int column = 0; column < 3; ++column)
                {
                    pulled.m[row][column] = world.m[row][column] * k;
                }
                pulled.m[row][3] = world.m[row][3] * k + eye[row] * (1.0f - k);
            }
            return pulled;
        }

        /**
         * @brief The LOD a copy asks for: LOD 1 for a merged-mesh deformable model, LOD 0 otherwise.
         * @details CStatObj::RenderObject skips LOD 0 of a model flagged for merged-mesh deformation, and its clamp
         *          falls back to LOD 0 when the model has no LOD 1.
         */
        [[nodiscard]] std::int16_t copy_lod(std::uintptr_t stat_obj) noexcept
        {
            const auto flags =
                DMK::memory::read<std::uint32_t>(DMK::Address{stat_obj + constants::STAT_OBJ_FLAGS2_OFFSET});
            return flags && (*flags & constants::STAT_OBJ_MERGED_DEFORM_FLAG) != 0 ? 1 : 0;
        }

        /**
         * @brief Submits the items of @p snapshot.
         * @details The view cone culls herb copies. With the mask depth test on, they are also pulled toward the
         *          camera (see constants::HERB_DEPTH_PULL), so they win the depth test against their wind-bent
         *          originals. A static or entity copy draws exactly where its original draws, so it needs
         *          neither. A cone test or pull about the pivot misplaces a large object.
         * @param herbs The snapshot holds herb copies.
         * @return The number submitted.
         */
        std::size_t submit(
            const Snapshot &snapshot,
            std::uintptr_t fn,
            const void *pass_info,
            std::uint32_t sorter,
            bool herbs
        ) noexcept
        {
            DMK_PROFILE_FUNCTION();
            CameraView view{};
            const bool have_view = guarded_camera_view(pass_info, &view);
            const bool pull = herbs && have_view && !engine_see_through_active();
            game_structures::Matrix34f pulled{};
            alignas(16) std::byte params[constants::SRENDPARAMS_BUFFER_SIZE];
            constexpr float alpha = constants::HERB_PROXY_ALPHA;
            constexpr float quality = 1.0f;
            // Before water: the mask pass draws an after-water transparent item with a MIN alpha blend. That blend
            // keeps the cleared alpha, so such a copy tints the fill and draws no outline. [KCD2 submits after water]
            constexpr std::uint8_t after_water = 0;
            std::size_t drawn = 0;
            for (const HerbOutlineItem &item : snapshot)
            {
                if (item.stat_obj == 0 || item.word == 0 || item.material == 0)
                {
                    continue;
                }
                PlantSight sight{};
                if (have_view)
                {
                    sight = plant_sight(item.world, view);
                    if (herbs && !sight.in_view)
                    {
                        continue;
                    }
                }
                ++drawn;
                // A default SRendParams without a render node: CStatObj::Render takes a temporary render object and
                // fills it from these fields only.
                std::memset(params, 0, sizeof(params));
                const game_structures::Matrix34f *matrix = &item.world;
                if (pull)
                {
                    pulled = pulled_toward_camera(item.world, view.eye);
                    matrix = &pulled;
                }
                std::memcpy(params + constants::SRENDPARAMS_MATRIX_OFFSET, &matrix, sizeof(matrix));
                std::memcpy(params + constants::SRENDPARAMS_MATERIAL_OFFSET, &item.material, sizeof(item.material));
                std::memcpy(params + constants::SRENDPARAMS_ALPHA_OFFSET, &alpha, sizeof(alpha));
                // The render object's camera distance: the silhouette pass sorts its items far to near by it, so a
                // herb left at 0 would always draw last and paint over nearer outlined objects. The true (not
                // pulled) distance keeps the herb in order with them.
                std::memcpy(params + constants::SRENDPARAMS_DISTANCE_OFFSET, &sight.distance, sizeof(sight.distance));
                std::memcpy(params + constants::SRENDPARAMS_QUALITY_OFFSET, &quality, sizeof(quality));
                std::memcpy(params + constants::SRENDPARAMS_HUD_SILHOUETTE_OFFSET, &item.word, sizeof(item.word));
                const std::int16_t lod[2] = {copy_lod(item.stat_obj), -1};
                std::memcpy(params + constants::SRENDPARAMS_LOD_OFFSET, lod, sizeof(lod));
                std::memcpy(params + constants::SRENDPARAMS_AFTER_WATER_OFFSET, &after_water, sizeof(after_water));
                std::memcpy(params + constants::SRENDPARAMS_SORTER_OFFSET, &sorter, sizeof(sorter));
                if (!guarded_render(fn, item.stat_obj, params, pass_info))
                {
                    s_faulted.store(true, std::memory_order_relaxed);
                    (void)DMK::log().try_log(
                        DMK::LogLevel::Error,
                        "HerbOutline: CStatObj::Render faulted on 0x{:016X}. Outline copies stay off until the next "
                        "load of the mod",
                        item.stat_obj
                    );
                    return drawn;
                }
            }
            return drawn;
        }

        /** @brief Publishes @p items into @p snapshot unless they equal the published set. */
        void publish_into(
            std::atomic<std::shared_ptr<const Snapshot>> &snapshot,
            std::atomic<std::size_t> &count,
            std::span<const HerbOutlineItem> items
        )
        {
            if (items.empty())
            {
                if (count.exchange(0, std::memory_order_relaxed) != 0)
                {
                    snapshot.store(nullptr, std::memory_order_release);
                }
                return;
            }
            // The scan and the restyle ticks republish every second and on every intensity step. A set that did not
            // change keeps the published copy instead of allocating and copying another one.
            if (const std::shared_ptr<const Snapshot> current = snapshot.load(std::memory_order_acquire);
                current && std::equal(
                               current->begin(),
                               current->end(),
                               items.begin(),
                               items.end(),
                               [](const HerbOutlineItem &a, const HerbOutlineItem &b)
                               {
                                   return a.stat_obj == b.stat_obj && a.word == b.word && a.material == b.material &&
                                          std::memcmp(&a.world, &b.world, sizeof(a.world)) == 0;
                               }
                           ))
            {
                return;
            }
            snapshot.store(std::make_shared<const Snapshot>(items.begin(), items.end()), std::memory_order_release);
            count.store(items.size(), std::memory_order_relaxed);
        }
    } // namespace

    bool initialize_herb_outline() noexcept
    {
        const std::uintptr_t fn = gated_anchor_address(Feature::OutlineCopies, AnchorId::StatObjRender);
        s_render_fn.store(fn, std::memory_order_release);
        s_faulted.store(false, std::memory_order_relaxed);
        s_last_frame.store(std::numeric_limits<std::int32_t>::min(), std::memory_order_relaxed);
        if (fn == 0)
        {
            (void)DMK::log().try_log(
                DMK::LogLevel::Warning,
                "HerbOutline: CStatObj::Render did not resolve; herbs keep their markers"
            );
            return false;
        }
        (void)DMK::log().try_log(DMK::LogLevel::Info, "HerbOutline: ready (CStatObj::Render 0x{:016X})", fn);
        return true;
    }

    void shutdown_herb_outline() noexcept
    {
        s_render_fn.store(0, std::memory_order_release);
        s_snapshot.store(nullptr, std::memory_order_release);
        s_static_snapshot.store(nullptr, std::memory_order_release);
        s_entity_snapshot.store(nullptr, std::memory_order_release);
        s_count.store(0, std::memory_order_relaxed);
        s_static_count.store(0, std::memory_order_relaxed);
        s_entity_count.store(0, std::memory_order_relaxed);
    }

    bool herb_outline_ready() noexcept
    {
        return s_render_fn.load(std::memory_order_acquire) != 0 && !s_faulted.load(std::memory_order_relaxed);
    }

    void publish_herb_outline(std::span<const HerbOutlineItem> items)
    {
        publish_into(s_snapshot, s_count, items);
    }

    void publish_static_outline(std::span<const HerbOutlineItem> items)
    {
        publish_into(s_static_snapshot, s_static_count, items);
    }

    void publish_entity_outline(std::span<const HerbOutlineItem> items)
    {
        publish_into(s_entity_snapshot, s_entity_count, items);
    }

    bool entity_needs_outline_copy(std::uintptr_t node)
    {
        std::array<EntityMeshSlot, ENTITY_MESHES_MAX> meshes{};
        const std::size_t count = entity_mesh_slots(node, meshes);
        return std::any_of(
            meshes.begin(),
            meshes.begin() + static_cast<std::ptrdiff_t>(count),
            [](const EntityMeshSlot &mesh) { return mesh_needs_mask_copy(mesh.stat_obj, mesh.material); }
        );
    }

    void append_entity_outline(std::uintptr_t node, std::uint32_t word, std::vector<HerbOutlineItem> &out)
    {
        std::array<EntityMeshSlot, ENTITY_MESHES_MAX> meshes{};
        const std::size_t count = entity_mesh_slots(node, meshes);
        for (std::size_t i = 0; i < count; ++i)
        {
            const EntityMeshSlot &mesh = meshes[i];
            if (!mesh_needs_mask_copy(mesh.stat_obj, mesh.material))
            {
                continue;
            }
            if (const std::uintptr_t mask = mask_material_for(mesh.material); mask != 0)
            {
                out.push_back(HerbOutlineItem{mesh.world, mesh.stat_obj, word, mask});
            }
        }
    }

    std::size_t herb_outline_count() noexcept
    {
        return s_count.load(std::memory_order_relaxed);
    }

    std::size_t entity_outline_count() noexcept
    {
        return s_entity_count.load(std::memory_order_relaxed);
    }

    void herb_outline_on_render(const void *pass_info, const void *sorter) noexcept
    {
        if (pass_info == nullptr ||
            (s_count.load(std::memory_order_relaxed) == 0 && s_static_count.load(std::memory_order_relaxed) == 0 &&
             s_entity_count.load(std::memory_order_relaxed) == 0) ||
            s_faulted.load(std::memory_order_relaxed))
        {
            return;
        }
        const std::uintptr_t fn = s_render_fn.load(std::memory_order_acquire);
        const auto *pass = static_cast<const std::uint8_t *>(pass_info);
        if (fn == 0 || pass[constants::PASS_INFO_RECURSION_OFFSET] != 0 ||
            pass[constants::PASS_INFO_SHADOW_OFFSET] != 0)
        {
            return;
        }
        std::int32_t frame = 0;
        std::memcpy(&frame, pass + constants::PASS_INFO_FRAME_ID_OFFSET, sizeof(frame));
        std::int32_t last = s_last_frame.load(std::memory_order_relaxed);
        if (last == frame || !s_last_frame.compare_exchange_strong(last, frame, std::memory_order_acq_rel))
        {
            return;
        }
        const std::shared_ptr<const Snapshot> snapshot = s_snapshot.load(std::memory_order_acquire);
        const std::shared_ptr<const Snapshot> statics = s_static_snapshot.load(std::memory_order_acquire);
        const std::shared_ptr<const Snapshot> entities = s_entity_snapshot.load(std::memory_order_acquire);
        if ((!snapshot || snapshot->empty()) && (!statics || statics->empty()) && (!entities || entities->empty()))
        {
            return;
        }
        std::uint32_t sort_key = 0;
        if (sorter != nullptr)
        {
            std::memcpy(&sort_key, sorter, sizeof(sort_key));
        }
        const std::int64_t start = steady_us();
        std::size_t submitted = 0;
        std::size_t total = 0;
        if (snapshot)
        {
            submitted += submit(*snapshot, fn, pass_info, sort_key, true);
            total += snapshot->size();
        }
        if (statics && !s_faulted.load(std::memory_order_relaxed))
        {
            submitted += submit(*statics, fn, pass_info, sort_key, false);
            total += statics->size();
        }
        if (entities && !s_faulted.load(std::memory_order_relaxed))
        {
            submitted += submit(*entities, fn, pass_info, sort_key, false);
            total += entities->size();
        }
        const std::int64_t now = steady_us();
        const std::uint64_t frames = s_submit_frames.fetch_add(1, std::memory_order_relaxed) + 1;
        const std::uint64_t plants = s_submit_plants.fetch_add(total, std::memory_order_relaxed) + total;
        const std::uint64_t drawn = s_submit_drawn.fetch_add(submitted, std::memory_order_relaxed) + submitted;
        const std::uint64_t busy =
            s_submit_us.fetch_add(static_cast<std::uint64_t>(now - start), std::memory_order_relaxed) +
            static_cast<std::uint64_t>(now - start);
        std::int64_t next = s_next_report_ms.load(std::memory_order_relaxed);
        if (now / 1000 >= next &&
            s_next_report_ms.compare_exchange_strong(next, now / 1000 + REPORT_MS, std::memory_order_relaxed))
        {
            s_submit_frames.store(0, std::memory_order_relaxed);
            s_submit_plants.store(0, std::memory_order_relaxed);
            s_submit_drawn.store(0, std::memory_order_relaxed);
            s_submit_us.store(0, std::memory_order_relaxed);
            if (next != 0)
            {
                (void)DMK::log().try_log(
                    DMK::LogLevel::Debug,
                    "HerbOutline: {} frame(s), {:.0f} object(s) per frame, {:.0f} in view and submitted, {:.3f} ms per "
                    "frame (one 3D-engine job thread)",
                    frames,
                    static_cast<double>(plants) / static_cast<double>(frames),
                    static_cast<double>(drawn) / static_cast<double>(frames),
                    static_cast<double>(busy) / 1000.0 / static_cast<double>(frames)
                );
            }
        }
    }

} // namespace HenrySenses
