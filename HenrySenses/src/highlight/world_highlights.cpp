/**
 * @file highlight/world_highlights.cpp
 * @brief Outline set for interactive world objects.
 */

#include "highlight/world_highlights.hpp"
#include "constants.hpp"
#include "engine/visual_resolver.hpp"
#include "render/engine_silhouette.hpp"
#include "render/herb_outline.hpp"
#include "render/mask_material.hpp"

#include <DetourModKit.hpp>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace HenrySenses
{
    namespace
    {
        /**
         * @brief One outlined object and the state the mod changed on its node.
         */
        struct Entry
        {
            EntityId entity_id{0};
            std::uintptr_t brush{0};
            game_structures::Aabb brush_bounds{};
            // KCD1 has no CMovableBrush, so no entry keeps a model to recognise a moved brush by.
            std::uint32_t color_word{0};
            float distance{-1.0f};
            float fade_radius{20.0f};
            float intensity{1.0f};
            GroupStyle style{GroupStyle::Outline};
            // The word currently written to the node (0 = none written).
            std::uint32_t applied_word{0};
            // The node the state was applied to; compared, never dereferenced, after the frame it was resolved in.
            std::uintptr_t node{0};
            bool render_always_applied{false};
            // A static mesh of the node has a material without a CustomRenderPass technique (see registry.cpp).
            bool outline_copy{false};
            bool wanted{false};
        };

        std::vector<Entry> s_entries;
        std::atomic<std::size_t> s_count{0};
        /// The last apply allowed silhouette words, so the brush entries want outline copies.
        bool s_brush_words = false;

        [[nodiscard]] bool same_object(const Entry &entry, const WorldHighlightRequest &request) noexcept
        {
            return request.entity_id != 0 ? entry.entity_id == request.entity_id
                                          : entry.entity_id == 0 && entry.brush == request.brush;
        }

        /**
         * @brief Resolves the node an entry shows now: the entity's render proxy.
         * @details A brush entry has no node to write a word to: its outline copy comes from static_item(). [KCD2 also
         *          resolves a brush that still matches the bounds or the model it was found with.]
         */
        [[nodiscard]] std::uintptr_t resolve_node(const Entry &entry) noexcept
        {
            if (entry.entity_id == 0)
            {
                return 0;
            }
            const std::uintptr_t entity = entity_from_id(entry.entity_id);
            return entity != 0 ? render_node_of(entity) : 0;
        }

        /**
         * @brief The outline copy of a brush entry: the brush's transform, model and mask material, and the styled
         *        word.
         * @return The copy, or nullopt when the brush no longer matches the bounds it was found with, is hidden or has
         *         no model.
         */
        [[nodiscard]] std::optional<HerbOutlineItem> static_item(const Entry &entry)
        {
            if (entry.brush == 0 || !brush_matches(entry.brush, entry.brush_bounds) || render_node_hidden(entry.brush))
            {
                return std::nullopt;
            }
            const auto world = DMK::memory::read<game_structures::Matrix34f>(
                DMK::Address{entry.brush + constants::BRUSH_MATRIX_OFFSET}
            );
            const auto stat_obj =
                DMK::memory::read<std::uintptr_t>(DMK::Address{entry.brush + constants::BRUSH_STAT_OBJ_OFFSET});
            if (!world || !stat_obj || !DMK::memory::is_plausible_ptr(DMK::Address{*stat_obj}))
            {
                return std::nullopt;
            }
            std::uintptr_t material = 0;
            if (const auto own =
                    DMK::memory::read<std::uintptr_t>(DMK::Address{entry.brush + constants::BRUSH_MATERIAL_OFFSET});
                own && DMK::memory::is_plausible_ptr(DMK::Address{*own}))
            {
                material = *own;
            }
            else if (const auto model = DMK::memory::read<std::uintptr_t>(
                         DMK::Address{*stat_obj + constants::STATOBJ_MATERIAL_OFFSET}
                     );
                     model && DMK::memory::is_plausible_ptr(DMK::Address{*model}))
            {
                material = *model;
            }
            return HerbOutlineItem{
                *world,
                *stat_obj,
                styled_word(entry.color_word, entry.distance, entry.fade_radius, entry.intensity, entry.style),
                mask_material_for(material)
            };
        }

        void forget(Entry &entry) noexcept
        {
            entry.applied_word = 0;
            entry.render_always_applied = false;
            entry.outline_copy = false;
            entry.node = 0;
        }

        /**
         * @brief Restores one entry's node state.
         * @details Runs only while the object still resolves to the very node the mod changed and the loot set has not
         *          taken that node over; a gone node took its word with it and was purged from the always-visible list
         *          by the engine.
         */
        void restore_entry(Entry &entry) noexcept
        {
            const std::uintptr_t node = resolve_node(entry);
            if (node == 0 || node != entry.node || registry_owns_node(node))
            {
                forget(entry);
                return;
            }
            if (entry.applied_word != 0)
            {
                (void)write_hud_word(node, 0);
                (void)invalidate_render_object(node);
            }
            if (entry.render_always_applied)
            {
                const RenderAlwaysResult result = remove_render_always(node, false);
                if (result != RenderAlwaysResult::Applied)
                {
                    (void)DMK::log().try_log(
                        DMK::LogLevel::Warning,
                        "WorldHighlights: 0x{:016X} could not leave the always-visible list",
                        node
                    );
                }
            }
            forget(entry);
        }

        void apply_entry(Entry &entry, const ApplyOptions &options)
        {
            const std::uintptr_t node = resolve_node(entry);
            const bool first_time = entry.node == 0 && entry.applied_word == 0 && !entry.render_always_applied;
            if (node != entry.node)
            {
                // A new proxy never carries the old one's state, and a brush that stopped matching is gone.
                forget(entry);
            }
            if (node == 0)
            {
                return;
            }
            if (registry_owns_node(node))
            {
                // The loot set outlines this node already, in its own colour.
                forget(entry);
                return;
            }

            if (options.write_words)
            {
                const std::uint32_t word =
                    styled_word(entry.color_word, entry.distance, entry.fade_radius, entry.intensity, entry.style);
                if (word != entry.applied_word && write_hud_word(node, word))
                {
                    (void)invalidate_render_object(node);
                    entry.applied_word = word;
                }
            }
            else if (entry.applied_word != 0)
            {
                (void)write_hud_word(node, 0);
                (void)invalidate_render_object(node);
                entry.applied_word = 0;
            }

            const bool want_always = options.write_words && options.render_always;
            RenderAlwaysResult always_result = RenderAlwaysResult::NotRegistered;
            if (want_always && !entry.render_always_applied)
            {
                always_result = apply_render_always(node);
                entry.render_always_applied = always_result == RenderAlwaysResult::Applied;
            }
            else if (!want_always && entry.render_always_applied)
            {
                (void)remove_render_always(node, false);
                entry.render_always_applied = false;
            }
            entry.node = node;
            entry.outline_copy = entry.applied_word != 0 && entity_needs_outline_copy(node);

            if (first_time)
            {
                (void)DMK::log().try_log(
                    DMK::LogLevel::Debug,
                    "WorldHighlights: + entity {:#x} dist={:.1f} node=0x{:016X} word={:#010x} always={}",
                    entry.entity_id,
                    entry.distance,
                    node,
                    entry.applied_word,
                    entry.render_always_applied
                );
            }
        }
    } // namespace

    void apply_world_highlights(std::span<const WorldHighlightRequest> requests, const ApplyOptions &options) noexcept
    {
        DMK_PROFILE_FUNCTION();
        try
        {
            for (Entry &entry : s_entries)
            {
                entry.wanted = false;
            }
            std::size_t added = 0;
            const bool copies = engine_brush_outline_available();
            for (const WorldHighlightRequest &request : requests)
            {
                // A brush is outlined through an outline copy, which needs the static-mesh render hook.
                if (request.entity_id == 0 && (request.brush == 0 || !copies))
                {
                    continue;
                }
                auto it = std::find_if(
                    s_entries.begin(),
                    s_entries.end(),
                    [&](const Entry &entry) { return same_object(entry, request); }
                );
                if (it == s_entries.end())
                {
                    s_entries.push_back(
                        Entry{
                            .entity_id = request.entity_id,
                            .brush = request.entity_id != 0 ? 0 : request.brush,
                            .brush_bounds = request.brush_bounds,
                        }
                    );
                    it = std::prev(s_entries.end());
                    ++added;
                }
                else if (it->wanted)
                {
                    // Two triggers on one object (the seats of a bench) keep the nearer one's distance.
                    continue;
                }
                it->wanted = true;
                if (it->entity_id == 0)
                {
                    // A brush that took over the address of an earlier one brings its own bounds.
                    it->brush_bounds = request.brush_bounds;
                }
                it->color_word = request.color_word;
                it->distance = request.distance;
                it->fade_radius = request.fade_radius;
                it->intensity = request.intensity;
                it->style = request.style;
            }

            std::size_t removed = 0;
            for (Entry &entry : s_entries)
            {
                if (!entry.wanted)
                {
                    restore_entry(entry);
                    ++removed;
                }
            }
            std::erase_if(s_entries, [](const Entry &entry) { return !entry.wanted; });

            std::size_t words = 0;
            s_brush_words = options.write_words;
            for (Entry &entry : s_entries)
            {
                if (entry.entity_id != 0)
                {
                    apply_entry(entry, options);
                    words += entry.applied_word != 0 ? 1 : 0;
                }
                else if (options.write_words && brush_matches(entry.brush, entry.brush_bounds) &&
                         !render_node_hidden(entry.brush))
                {
                    ++words;
                }
            }
            s_count.store(s_entries.size(), std::memory_order_relaxed);
            if (added != 0 || removed != 0)
            {
                (void)DMK::log().try_log(
                    DMK::LogLevel::Debug,
                    "WorldHighlights: {} object(s) ({} added, {} removed), {} outlined",
                    s_entries.size(),
                    added,
                    removed,
                    words
                );
            }
        }
        catch (...)
        {
            (void)DMK::log().log_noexcept(DMK::LogLevel::Error, "WorldHighlights: apply failed (allocation)");
        }
    }

    void clear_world_highlights() noexcept
    {
        for (Entry &entry : s_entries)
        {
            restore_entry(entry);
        }
        if (!s_entries.empty())
        {
            (void)DMK::log().try_log(DMK::LogLevel::Debug, "WorldHighlights: cleared {} object(s)", s_entries.size());
        }
        s_entries.clear();
        s_brush_words = false;
        publish_static_outline({});
        s_count.store(0, std::memory_order_relaxed);
    }

    void maintain_world_highlights() noexcept
    {
        DMK_PROFILE_FUNCTION();
        for (Entry &entry : s_entries)
        {
            if (!entry.render_always_applied)
            {
                continue;
            }
            const std::uintptr_t node = resolve_node(entry);
            if (node == 0 || node != entry.node)
            {
                forget(entry);
                continue;
            }
            const std::optional<bool> bit = read_render_always(node);
            if (bit.has_value() && !*bit)
            {
                (void)remove_render_always(node, false);
                entry.render_always_applied = false;
                (void)DMK::log().try_log(
                    DMK::LogLevel::Warning,
                    "WorldHighlights: 0x{:016X} lost ERF_RENDER_ALWAYS outside the mod; moved back into "
                    "the octree",
                    node
                );
            }
        }
    }

    void collect_world_entity_outline_items(std::vector<HerbOutlineItem> &out)
    {
        for (const Entry &entry : s_entries)
        {
            if (entry.entity_id == 0 || !entry.outline_copy || entry.applied_word == 0)
            {
                continue;
            }
            // A node the loot set took over gets its copy from the loot set alone.
            const std::uintptr_t node = resolve_node(entry);
            if (node != 0 && node == entry.node && !registry_owns_node(node))
            {
                append_entity_outline(node, entry.applied_word, out);
            }
        }
    }

    void collect_world_static_outline_items(std::vector<HerbOutlineItem> &out)
    {
        if (!s_brush_words)
        {
            return;
        }
        for (const Entry &entry : s_entries)
        {
            if (entry.entity_id != 0)
            {
                continue;
            }
            if (const std::optional<HerbOutlineItem> item = static_item(entry))
            {
                out.push_back(*item);
            }
        }
    }

    std::size_t world_highlight_count() noexcept
    {
        return s_count.load(std::memory_order_relaxed);
    }

    void world_highlight_nodes_in(const game_structures::Aabb &box, std::vector<std::uintptr_t> &out) noexcept
    {
        try
        {
            for (const Entry &entry : s_entries)
            {
                // Only a node moved to the always-visible list has left the octree; the rest is found by the query.
                if (!entry.render_always_applied || entry.node == 0)
                {
                    continue;
                }
                // The bounds the object was requested with (a door swings within them) rule out the far entries
                // before anything is read.
                const game_structures::Aabb &b = entry.brush_bounds;
                if (b.max.x < box.min.x || b.min.x > box.max.x || b.max.y < box.min.y || b.min.y > box.max.y ||
                    b.max.z < box.min.z || b.min.z > box.max.z)
                {
                    continue;
                }
                if (resolve_node(entry) == entry.node && std::find(out.begin(), out.end(), entry.node) == out.end())
                {
                    out.push_back(entry.node);
                }
            }
        }
        catch (...)
        {
            (void)DMK::log().log_noexcept(DMK::LogLevel::Error, "WorldHighlights: node lookup failed (allocation)");
        }
    }

} // namespace HenrySenses
