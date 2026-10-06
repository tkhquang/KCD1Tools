/**
 * @file engine/interactables.cpp
 * @brief Native detection of the interactive objects around a point.
 */

#include "engine/interactables.hpp"
#include "constants.hpp"
#include "engine/engine_env.hpp"
#include "engine/entity_access.hpp"
#include "engine/game_natives.hpp"

#include <DetourModKit.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace HenrySenses
{
    namespace
    {
        // What a class's entities need beyond their kind.
        // A helper without a visible mesh of its own, placed on the object it belongs to (every *Trigger class and a
        // few others). KCD1 looks up no such mesh, so a helper keeps its box and gets no outline. [KCD2 looks the
        // mesh up]
        constexpr std::uint8_t TRAIT_HELPER = 0x01;
        // Interactive only when its script says so (a book the player can read in place).
        constexpr std::uint8_t TRAIT_READABLE = 0x04;

        /**
         * @brief An entity class whose script offers the player an action, its display group, and what else its
         *        entities need.
         */
        struct InteractiveClass
        {
            std::string_view name;
            InteractKind kind;
            std::uint8_t traits{0};
        };

        // Every class below defines GetActions in its entity script (Scripts.pak, Scripts/Entities). Actors, stashes,
        // pickable items and carryable items are loot, handled by the loot scan. KCD1 registers Book, LedgerBook and
        // RecipesBook as item classes (Scripts/Entities/Items/XML), every other class from its .ent file. Chair is not
        // listed: its KCD1 script keeps GetActions commented out. AlchemyItem is not listed: it offers actions only
        // inside the alchemy minigame. [KCD2 also lists Smithery, ForgeBuilderTrigger, DiceInteractor,
        // StoneThrowingPile, BedTrigger, ActionTrigger, the water, kettle, food and indulgence triggers, Lockpickable,
        // CarryItemPile, WHCartMountPoint and InteractiveObjectEx. KCD1 has none of them, or no action in its script.]
        constexpr std::array INTERACTIVE_CLASSES{
            InteractiveClass{"AnimDoor", InteractKind::Door},
            // The CryEngine door classes, whose KCD1 scripts still offer actions. [KCD2 lists neither]
            InteractiveClass{"AdvancedDoor", InteractKind::Door},
            InteractiveClass{"Door", InteractKind::Door},
            InteractiveClass{"Grindstone", InteractKind::Station},
            InteractiveClass{"AlchemyTable", InteractKind::Station},
            InteractiveClass{"TranscriptionTable", InteractKind::Station},
            InteractiveClass{"DiceMinigameCup", InteractKind::Station},
            // A book offers reading in place only with Properties.bIsDirectlyReadable; any other book is an item.
            InteractiveClass{"Book", InteractKind::Station, TRAIT_READABLE},
            // The ledger follows the rule of a book. [KCD2 lists no LedgerBook]
            InteractiveClass{"LedgerBook", InteractKind::Station, TRAIT_READABLE},
            InteractiveClass{"RecipesBook", InteractKind::Station},
            InteractiveClass{"Bed", InteractKind::Bed},
            // The TriggerBase use triggers: a helper cylinder on the object they belong to.
            InteractiveClass{"InteractionTrigger", InteractKind::UseSpot, TRAIT_HELPER},
            InteractiveClass{"SequenceTrigger", InteractKind::UseSpot, TRAIT_HELPER},
            InteractiveClass{"SmartObjectTrigger", InteractKind::UseSpot, TRAIT_HELPER},
            InteractiveClass{"Ladder", InteractKind::Other},
            InteractiveClass{"Hole", InteractKind::Other, TRAIT_HELPER},
            // An inscription to read: an invisible box on a grave, a sign or a cross.
            InteractiveClass{"CaptionObject", InteractKind::Other, TRAIT_HELPER},
        };

        // Entity links read per trigger.
        constexpr int MAX_LINKS = 8;
        // The world is walked again this long after the last walk finished, for the objects spawned or removed since.
        // A walk keeps every interactive entity of the level with its position, so moving needs no new walk (a walk
        // every 3 s and every 6 m cost ~6 ms of main-thread time each, back to back while riding). A collect reads the
        // live position of the candidates whose walk position lies within WALK_MARGIN of the reach, which also
        // covers an object that moved since (a cart's mount point).
        constexpr std::int64_t REWALK_MS = 10000;
        constexpr float WALK_MARGIN = 8.0f;
        // Main-thread time one frame may spend walking, and the entities taken between two clock reads.
        constexpr std::int64_t WALK_BUDGET_US = 1000;
        constexpr std::size_t WALK_BATCH = 1024;
        // A walk longer than this many entities is cut short (the world holds about 100k).
        constexpr std::size_t MAX_WALK_ENTITIES = 400000;
        // Entities without usable geometry (script triggers) get a box of this half size around their position.
        constexpr float MIN_HALF_EXTENT = 0.15f;
        constexpr float DEFAULT_HALF_EXTENT = 0.35f;
        // Bounds larger than this on any axis (trigger areas, merged prefabs) are replaced by the default box.
        constexpr float MAX_EXTENT = 12.0f;
        constexpr std::size_t SURVEY_TOP = 60;

        /** @brief A class's display group (-1: not interactive) and traits. */
        struct ClassInfo
        {
            std::int8_t kind{-1};
            std::uint8_t traits{0};
        };

        /** @brief A cached interactive entity of the last walk. */
        struct Candidate
        {
            EntityId id{0};
            InteractKind kind{InteractKind::Other};
            std::uint8_t traits{0};
            // Where the walk saw it.
            game_structures::Vec3f position{};
        };

        /**
         * @brief The mesh found for one candidate, cached per entity.
         * @details In KCD1 it is always the candidate's own render proxy. [KCD2 also caches the brush or entity mesh
         *          a trigger lookup found, its retry state and its source]
         */
        struct VisualCache
        {
            EntityId owner{0};
            game_structures::Aabb bounds{};
            // The mesh entity is kept invisible by the game for now (entity_flags_game_hidden): it keeps its outline
            // state but shows a marker until the game draws it again.
            bool game_hidden{false};
            InteractKind kind{InteractKind::Other};
        };

        /** @brief State of a cached mesh at the time of a collect. */
        enum class VisualState : std::uint8_t
        {
            Alive,
            // The owner entity is hidden right now; the cache stays.
            Hidden,
            // The mesh is gone or no longer matches; it is looked up again.
            Gone,
        };

        /** @brief Per-class tally of a survey walk. */
        struct SurveyEntry
        {
            std::uintptr_t sample_entity{0};
            std::size_t count{0};
        };

        /** @brief One target of the last collect and the mesh it shows. */
        struct TargetState
        {
            InteractTarget target{};
            bool has_visual{false};
            InteractVisual visual{};
        };

        std::atomic<bool> s_available{false};
        std::atomic<bool> s_survey_requested{false};

        // Main-thread state.
        std::unordered_map<std::uintptr_t, ClassInfo> s_class_infos;
        // s_class_infos's fast path for the walk.
        ClassMemo<ClassInfo> s_class_memo;
        std::unordered_map<std::uintptr_t, std::string> s_class_names;
        std::unordered_map<EntityId, VisualCache> s_visuals;
        std::unordered_set<EntityId> s_logged_ids;
        // Whether a book can be read in place, per entity.
        std::unordered_map<EntityId, bool> s_readable_books;

        EntityWalk s_walk;
        std::vector<WalkedEntity> s_batch;
        std::vector<Candidate> s_pending;
        std::vector<Candidate> s_candidates;
        std::unordered_map<std::uintptr_t, SurveyEntry> s_survey;
        // The entities nearest the player in a survey walk (distance, id), listed by name.
        std::vector<std::pair<float, EntityId>> s_survey_nearest;
        constexpr std::size_t SURVEY_NEAREST = 20;
        bool s_surveying = false;
        game_structures::Vec3f s_pending_center{};
        float s_pending_radius = 0.0f;
        std::size_t s_walk_entities = 0;
        std::int64_t s_walk_started_ms = 0;
        std::int64_t s_walk_busy_us = 0;
        std::uint32_t s_walk_frames = 0;

        std::int64_t s_walk_done_ms = 0;
        bool s_walk_valid = false;
        std::size_t s_last_count = static_cast<std::size_t>(-1);

        // The last collect's targets, its kind mask and reach.
        std::vector<TargetState> s_targets;
        float s_collect_radius = 0.0f;

        [[nodiscard]] std::int64_t steady_us() noexcept
        {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                       std::chrono::steady_clock::now().time_since_epoch()
            )
                .count();
        }

        [[nodiscard]] float distance_between(const game_structures::Vec3f &a, const game_structures::Vec3f &b) noexcept
        {
            const float dx = a.x - b.x;
            const float dy = a.y - b.y;
            const float dz = a.z - b.z;
            return std::sqrt(dx * dx + dy * dy + dz * dz);
        }

        /**
         * @brief Name of an entity's class, cached per class pointer.
         */
        [[nodiscard]] const std::string &class_name(std::uintptr_t klass, std::uintptr_t entity)
        {
            auto it = s_class_names.find(klass);
            if (it == s_class_names.end())
            {
                it = s_class_names.emplace(klass, entity_class_name(entity)).first;
            }
            return it->second;
        }

        /**
         * @brief Interactive group (-1: none) and traits of an entity's class, resolved once per class pointer.
         */
        [[nodiscard]] ClassInfo class_info(std::uintptr_t klass, std::uintptr_t entity)
        {
            if (const ClassInfo *memo = s_class_memo.find(klass))
            {
                return *memo;
            }
            if (const auto it = s_class_infos.find(klass); it != s_class_infos.end())
            {
                s_class_memo.store(klass, it->second);
                return it->second;
            }
            const std::string &name = class_name(klass, entity);
            ClassInfo info{};
            for (const InteractiveClass &entry : INTERACTIVE_CLASSES)
            {
                if (entry.name == name)
                {
                    info = ClassInfo{static_cast<std::int8_t>(entry.kind), entry.traits};
                    break;
                }
            }
            s_class_infos.emplace(klass, info);
            return info;
        }

        /**
         * @brief Logs how many entities of each class the survey walk found within the radius, most frequent first.
         */
        void log_survey()
        {
            std::vector<std::pair<std::size_t, std::string>> sorted;
            std::size_t within = 0;
            sorted.reserve(s_survey.size());
            for (const auto &[klass, entry] : s_survey)
            {
                within += entry.count;
                std::string name = class_name(klass, entry.sample_entity);
                if (const ClassInfo info = class_info(klass, entry.sample_entity); info.kind >= 0)
                {
                    name += std::format("[{}]", interact_kind_name(static_cast<InteractKind>(info.kind)));
                }
                sorted.emplace_back(entry.count, std::move(name));
            }
            std::sort(
                sorted.begin(),
                sorted.end(),
                [](const auto &a, const auto &b)
                { return a.first != b.first ? a.first > b.first : a.second < b.second; }
            );
            std::string text;
            for (std::size_t i = 0; i < sorted.size() && i < SURVEY_TOP; ++i)
            {
                text += std::format("{}{} x{}", i == 0 ? "" : ", ", sorted[i].second, sorted[i].first);
            }
            (void)DMK::log().try_log(
                DMK::LogLevel::Info,
                "Interactables: survey of {} entities within {:.0f} m ({} classes): {}",
                within,
                s_pending_radius,
                sorted.size(),
                text
            );
            std::sort(s_survey_nearest.begin(), s_survey_nearest.end());
            std::string nearest;
            for (std::size_t i = 0; i < s_survey_nearest.size() && i < SURVEY_NEAREST; ++i)
            {
                const auto [distance, id] = s_survey_nearest[i];
                // Resolved again: the walk ran over several frames.
                const std::uintptr_t entity = entity_from_id(id);
                if (entity == 0)
                {
                    continue;
                }
                nearest += std::format(
                    "\n    {:.1f} m {:#x} {} {}",
                    distance,
                    id,
                    entity_class_name(entity),
                    entity_name(entity)
                );
            }
            (void)DMK::log().try_log(DMK::LogLevel::Info, "Interactables: nearest entities:{}", nearest);
            s_survey_nearest.clear();
        }

        /**
         * @brief Classifies one batch of walked entities into the pending candidates (and the survey tally).
         */
        void process_batch()
        {
            for (std::size_t i = 0; i < s_batch.size(); ++i)
            {
                // The walk hands over the class; the survey reads every entity's position, otherwise only an
                // interactive class's is read.
                if (s_surveying && i + PREFETCH_DISTANCE < s_batch.size())
                {
                    prefetch_entity(s_batch[i + PREFETCH_DISTANCE].entity, true);
                }
                const std::uintptr_t entity = s_batch[i].entity;
                const std::uintptr_t klass = s_batch[i].klass;
                if (klass == 0)
                {
                    continue;
                }
                std::optional<game_structures::Vec3f> position{};
                if (s_surveying)
                {
                    position = entity_world_position(entity);
                    if (position.has_value() && distance_between(*position, s_pending_center) <= s_pending_radius)
                    {
                        SurveyEntry &entry = s_survey[klass];
                        s_survey_nearest.emplace_back(distance_between(*position, s_pending_center), s_batch[i].id);
                        entry.sample_entity = entity;
                        ++entry.count;
                    }
                }
                const ClassInfo info = class_info(klass, entity);
                if (info.kind < 0)
                {
                    continue;
                }
                if (!s_surveying)
                {
                    position = entity_world_position(entity);
                }
                if (!position.has_value())
                {
                    continue;
                }
                if (const EntityId id = s_batch[i].id; id != 0)
                {
                    s_pending.push_back(Candidate{id, static_cast<InteractKind>(info.kind), info.traits, *position});
                }
            }
            s_walk_entities += s_batch.size();
            s_batch.clear();
        }

        void finish_walk(bool complete)
        {
            s_candidates.swap(s_pending);
            s_pending.clear();
            s_walk_done_ms = steady_us() / 1000;
            s_walk_valid = true;
            (void)DMK::log().try_log(
                DMK::LogLevel::Debug,
                "Interactables: walked {} entities ({}{}) over {} frame(s), {:.2f} ms busy, {} ms "
                "wall; {} interactive in the level, {} classes known",
                s_walk_entities,
                complete ? "complete" : "cut short",
                s_surveying ? ", survey" : "",
                s_walk_frames,
                static_cast<double>(s_walk_busy_us) / 1000.0,
                s_walk_done_ms - s_walk_started_ms,
                s_candidates.size(),
                s_class_infos.size()
            );
            if (s_surveying)
            {
                log_survey();
                s_survey.clear();
                s_surveying = false;
            }
        }

        [[nodiscard]] bool walk_due() noexcept
        {
            return !s_walk_valid || steady_us() / 1000 - s_walk_done_ms >= REWALK_MS ||
                   s_survey_requested.load(std::memory_order_relaxed);
        }

        /**
         * @brief Marker bounds of an interactive entity: its world bounds, or a small box at its position when the
         *        bounds are empty, degenerate or an area far larger than the object.
         */
        [[nodiscard]] game_structures::Aabb
        marker_bounds(std::uintptr_t entity, const game_structures::Vec3f &position, bool &fallback) noexcept
        {
            const std::optional<game_structures::Aabb> bounds = entity_world_bounds(entity);
            if (bounds.has_value())
            {
                const float ex = bounds->max.x - bounds->min.x;
                const float ey = bounds->max.y - bounds->min.y;
                const float ez = bounds->max.z - bounds->min.z;
                if (std::isfinite(ex) && std::isfinite(ey) && std::isfinite(ez) && ex >= 0.0f && ey >= 0.0f &&
                    ez >= 0.0f && std::max({ex, ey, ez}) <= MAX_EXTENT &&
                    std::max({ex, ey, ez}) >= 2.0f * MIN_HALF_EXTENT)
                {
                    fallback = false;
                    return *bounds;
                }
            }
            fallback = true;
            const float h = DEFAULT_HALF_EXTENT;
            return game_structures::Aabb{
                {position.x - h, position.y - h, position.z},
                {position.x + h, position.y + h, position.z + 2.0f * h}
            };
        }

        /**
         * @brief Describes a trigger's entity links (name, target class and name, and whether the target has a mesh),
         *        for the log.
         */
        [[nodiscard]] std::string describe_links(std::uintptr_t entity)
        {
            constexpr std::size_t max_link_name_length = 47;
            std::string text;
            auto link = DMK::memory::read<std::uintptr_t>(DMK::Address{entity + constants::ENTITY_LINKS_OFFSET});
            for (int i = 0; i < MAX_LINKS && link && *link != 0 && DMK::memory::is_plausible_ptr(DMK::Address{*link});
                 ++i)
            {
                const std::uintptr_t node = *link;
                std::string name;
                if (const auto text_ptr =
                        DMK::memory::read<std::uintptr_t>(DMK::Address{node + constants::ENTITY_LINK_NAME_OFFSET});
                    text_ptr && DMK::memory::is_plausible_ptr(DMK::Address{*text_ptr}))
                {
                    name = read_c_string(*text_ptr, max_link_name_length);
                }
                const auto target_id =
                    DMK::memory::read<std::uint32_t>(DMK::Address{node + constants::ENTITY_LINK_TARGET_OFFSET});
                const std::uintptr_t target = target_id ? entity_from_id(*target_id) : 0;
                std::string target_text = "-";
                if (target != 0)
                {
                    const std::uintptr_t target_node = render_node_of(target);
                    const std::optional<game_structures::Aabb> bounds = entity_world_bounds(target);
                    target_text = std::format(
                        "{} {} node={}{}",
                        entity_class_name(target),
                        entity_name(target),
                        DMK::format::format_address(target_node),
                        bounds.has_value() ? std::format(
                                                 " size={:.2f}x{:.2f}x{:.2f}",
                                                 bounds->max.x - bounds->min.x,
                                                 bounds->max.y - bounds->min.y,
                                                 bounds->max.z - bounds->min.z
                                             )
                                           : std::string{" no bounds"}
                    );
                }
                text += std::format("\n    link \"{}\" -> {:#x} {}", name, target_id ? *target_id : 0, target_text);
                link = DMK::memory::read<std::uintptr_t>(DMK::Address{node + constants::ENTITY_LINK_NEXT_OFFSET});
            }
            return text.empty() ? std::string{" (no links)"} : text;
        }

        /**
         * @brief Logs a target the first time a collect places it.
         * @details A helper also logs its entity links, the objects a later mesh lookup can start from. [KCD2 logs
         *          the links with the result of its mesh lookup]
         */
        void
        log_new_target(std::uintptr_t entity, const Candidate &candidate, const InteractTarget &target, bool fallback)
        {
            if (!DMK::log().is_enabled(DMK::LogLevel::Debug) || !s_logged_ids.insert(target.entity_id).second)
            {
                return;
            }
            const game_structures::Aabb &b = target.bounds;
            const bool helper = (candidate.traits & TRAIT_HELPER) != 0;
            (void)DMK::log().try_log(
                DMK::LogLevel::Debug,
                "Interactables: + id={:#x} {} class={} name={} dist={:.1f} "
                "size={:.2f}x{:.2f}x{:.2f}{} node=0x{:016X}{}",
                target.entity_id,
                interact_kind_name(target.kind),
                entity_class_name(entity),
                entity_name(entity),
                target.distance,
                b.max.x - b.min.x,
                b.max.y - b.min.y,
                b.max.z - b.min.z,
                fallback ? " (position box)" : "",
                render_node_of(entity),
                helper ? " helper (no mesh lookup, no outline)" + describe_links(entity) : std::string{}
            );
        }

        /**
         * @brief Takes a candidate's own render proxy as its mesh, given marker bounds that fit the object.
         * @details KCD1 looks up no other mesh, so only an object with its own render proxy gets one. [KCD2 looks a
         *          trigger's mesh up at its template pose or by a search]
         */
        [[nodiscard]] VisualCache
        resolve_visual(const Candidate &candidate, const game_structures::Aabb &bounds) noexcept
        {
            return VisualCache{
                .owner = candidate.id,
                .bounds = bounds,
                .kind = candidate.kind,
            };
        }

        /**
         * @brief Re-checks a cached mesh: its bounds now (a door swings) and whether the game keeps the entity
         * invisible
         *        for now.
         */
        [[nodiscard]] VisualState check_visual(VisualCache &cache) noexcept
        {
            const std::uintptr_t owner = entity_from_id(cache.owner);
            if (owner == 0)
            {
                return VisualState::Gone;
            }
            // Unreadable flags count as hidden, as entity_is_hidden has them.
            const std::optional<std::uint32_t> flags = entity_flags(owner);
            if (!flags.has_value() || (*flags & constants::ENTITY_FLAG_HIDDEN) != 0)
            {
                return VisualState::Hidden;
            }
            // An invisible entity keeps its node and its outline state; it just is not drawn until the game shows it.
            cache.game_hidden = entity_flags_game_hidden(*flags);
            if (const std::optional<game_structures::Aabb> bounds = entity_world_bounds(owner); bounds.has_value())
            {
                cache.bounds = *bounds;
            }
            return VisualState::Alive;
        }

        void log_visual(std::uintptr_t entity, const Candidate &candidate, const VisualCache &cache)
        {
            // Its arguments read names, so they are skipped for a log that drops the line.
            if (!DMK::log().is_enabled(DMK::LogLevel::Debug))
            {
                return;
            }
            const game_structures::Aabb &b = cache.bounds;
            (void)DMK::log().try_log(
                DMK::LogLevel::Debug,
                "Interactables: mesh of id={:#x} {} class={} -> own mesh size={:.2f}x{:.2f}x{:.2f}",
                candidate.id,
                interact_kind_name(cache.kind),
                entity_class_name(entity),
                b.max.x - b.min.x,
                b.max.y - b.min.y,
                b.max.z - b.min.z
            );
        }

        /** @brief True when a candidate may show as one of the kinds in @p mask. */
        [[nodiscard]] bool kind_wanted(const Candidate &candidate, std::uint32_t mask) noexcept
        {
            return (mask & interact_kind_bit(candidate.kind)) != 0;
        }

        /**
         * @brief True when a book can be read in place (only such a book is a station), read once per book.
         */
        [[nodiscard]] bool book_readable(EntityId id, std::uintptr_t entity)
        {
            if (const auto it = s_readable_books.find(id); it != s_readable_books.end())
            {
                return it->second;
            }
            const bool readable = script_table_bool(entity, "Properties", "bIsDirectlyReadable").value_or(false);
            s_readable_books.emplace(id, readable);
            (void)DMK::log().try_log(
                DMK::LogLevel::Debug,
                "Interactables: book {:#x} {} {}",
                id,
                entity_name(entity),
                readable ? "can be read in place (station)" : "is an item, not a place"
            );
            return readable;
        }

        /**
         * @brief Logs that the game started or stopped keeping a candidate's mesh entity invisible.
         */
        void log_game_hidden(const Candidate &candidate, const VisualCache &cache)
        {
            if (!DMK::log().is_enabled(DMK::LogLevel::Debug))
            {
                return;
            }
            const std::uintptr_t owner = entity_from_id(cache.owner);
            const std::string what = std::format(
                "id={:#x} {} '{}'{}",
                cache.owner,
                owner != 0 ? entity_class_name(owner) : std::string{"-"},
                owner != 0 ? entity_name(owner) : std::string{"-"},
                cache.owner != candidate.id ? std::format(" (mesh of id={:#x})", candidate.id) : std::string{}
            );
            if (cache.game_hidden)
            {
                const std::optional<std::uint32_t> flags = owner != 0 ? entity_flags(owner) : std::nullopt;
                (void)DMK::log().try_log(
                    DMK::LogLevel::Debug,
                    "Interactables: {} hidden by the game{} -> marker",
                    what,
                    flags.has_value() && !entity_flags_active(*flags) ? " (inactive)" : ""
                );
            }
            else
            {
                (void)DMK::log().try_log(DMK::LogLevel::Debug, "Interactables: {} shown again -> outline", what);
            }
        }

        /**
         * @brief Adds one candidate in reach to the targets, with its own render proxy as its mesh when it has one.
         * @details A helper, or an object without a render proxy or with unfit bounds, keeps its box and no mesh.
         *          [KCD2 queues a lookup for such a target]
         */
        void place_target(
            const Candidate &candidate,
            std::uintptr_t entity,
            const game_structures::Vec3f &position,
            float distance
        )
        {
            bool fallback = false;
            InteractTarget target{candidate.id, candidate.kind, marker_bounds(entity, position, fallback), distance};
            log_new_target(entity, candidate, target, fallback);
            auto it = s_visuals.find(candidate.id);
            // An object with a mesh of its own (a door, a book) needs no search: it is taken at once.
            if (it == s_visuals.end() && (candidate.traits & TRAIT_HELPER) == 0 && !fallback &&
                render_node_of(entity) != 0)
            {
                const VisualCache own = resolve_visual(candidate, target.bounds);
                log_visual(entity, candidate, own);
                it = s_visuals.insert_or_assign(candidate.id, own).first;
            }
            TargetState state{target, false, {}};
            if (it != s_visuals.end())
            {
                VisualCache &cache = it->second;
                const bool was_game_hidden = cache.game_hidden;
                switch (check_visual(cache))
                {
                case VisualState::Alive:
                    if (cache.game_hidden != was_game_hidden)
                    {
                        log_game_hidden(candidate, cache);
                    }
                    // The marker sits on the mesh the player sees.
                    state.target.bounds = cache.bounds;
                    state.target.has_mesh = true;
                    // The outline state stays on the mesh (the visual below), so it is back the frame the game draws
                    // the entity again. Until then the target keeps its marker.
                    state.target.game_hidden = cache.game_hidden;
                    state.has_visual = true;
                    state.visual = InteractVisual{cache.owner, 0, cache.bounds, cache.kind, distance};
                    break;
                case VisualState::Gone:
                    // The entity went since the last collect: the next one takes its mesh again.
                    s_visuals.erase(it);
                    break;
                case VisualState::Hidden:
                default:
                    break;
                }
            }
            s_targets.push_back(state);
        }

        /** @brief Writes the targets, nearest first, and their meshes (one per mesh) to the caller's vectors. */
        void publish(std::vector<InteractTarget> &out, std::vector<InteractVisual> *visuals)
        {
            std::sort(
                s_targets.begin(),
                s_targets.end(),
                [](const TargetState &a, const TargetState &b) { return a.target.distance < b.target.distance; }
            );
            out.clear();
            out.reserve(s_targets.size());
            for (const TargetState &state : s_targets)
            {
                out.push_back(state.target);
            }
            if (visuals != nullptr)
            {
                visuals->clear();
                // Two triggers on one object (the seats of a bench) share its mesh; the nearer one keeps it.
                std::unordered_set<std::uint64_t> seen;
                for (const TargetState &state : s_targets)
                {
                    if (!state.has_visual)
                    {
                        continue;
                    }
                    const InteractVisual &v = state.visual;
                    const std::uint64_t key = v.entity_id != 0 ? v.entity_id : static_cast<std::uint64_t>(v.brush);
                    if (seen.insert(key).second)
                    {
                        visuals->push_back(v);
                    }
                }
            }
            if (out.size() != s_last_count)
            {
                s_last_count = out.size();
                std::array<std::size_t, INTERACT_KIND_COUNT> per_kind{};
                std::size_t meshes = 0;
                for (const TargetState &state : s_targets)
                {
                    ++per_kind[static_cast<std::size_t>(state.target.kind)];
                    meshes += state.has_visual ? 1 : 0;
                }
                (void)DMK::log().try_log(
                    DMK::LogLevel::Debug,
                    "Interactables: {} marker(s) within {:.1f} m, {} with a mesh (door={} station={} bed={} seat={} "
                    "use={} other={})",
                    out.size(),
                    s_collect_radius,
                    meshes,
                    per_kind[0],
                    per_kind[1],
                    per_kind[2],
                    per_kind[3],
                    per_kind[4],
                    per_kind[5]
                );
            }
        }
    } // namespace

    std::string_view interact_kind_name(InteractKind kind) noexcept
    {
        switch (kind)
        {
        case InteractKind::Door:
            return "door";
        case InteractKind::Station:
            return "station";
        case InteractKind::Bed:
            return "bed";
        case InteractKind::Seat:
            return "seat";
        case InteractKind::UseSpot:
            return "use";
        case InteractKind::Other:
        default:
            return "other";
        }
    }

    DMK::Result<void> initialize_interactables()
    {
        if (!entity_access_available())
        {
            (void)DMK::log().try_log(
                DMK::LogLevel::Warning,
                "Interactables: entity access is unavailable; interactive objects are off"
            );
            return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "interactables/entity_access"});
        }
        reset_interactables();
        s_available.store(true, std::memory_order_release);
        (void)DMK::log().try_log(
            DMK::LogLevel::Info,
            "Interactables: ready ({} interactive classes, walk budget {} us per frame, no trigger mesh lookup)",
            INTERACTIVE_CLASSES.size(),
            WALK_BUDGET_US
        );
        return {};
    }

    void shutdown_interactables() noexcept
    {
        s_available.store(false, std::memory_order_release);
        reset_interactables();
    }

    bool interactables_available() noexcept
    {
        return s_available.load(std::memory_order_acquire);
    }

    void reset_interactables() noexcept
    {
        // Class objects live for the session, but a new level reuses entity ids and addresses.
        s_walk.cancel();
        s_batch.clear();
        s_pending.clear();
        s_candidates.clear();
        s_survey.clear();
        s_surveying = false;
        s_logged_ids.clear();
        s_visuals.clear();
        s_readable_books.clear();
        s_targets.clear();
        s_walk_valid = false;
        s_last_count = static_cast<std::size_t>(-1);
    }

    void request_interactables_survey() noexcept
    {
        s_survey_requested.store(true, std::memory_order_relaxed);
    }

    bool advance_interactables(const game_structures::Vec3f &center, float radius)
    {
        DMK_PROFILE_FUNCTION();
        if (!interactables_available() || !(radius > 0.0f))
        {
            return false;
        }
        const std::int64_t start_us = steady_us();
        if (!s_walk.active())
        {
            if (!walk_due())
            {
                return false;
            }
            if (!s_walk.begin())
            {
                return false;
            }
            s_pending.clear();
            s_batch.clear();
            s_pending_center = center;
            s_pending_radius = radius;
            s_walk_entities = 0;
            s_walk_frames = 0;
            s_walk_busy_us = 0;
            s_walk_started_ms = start_us / 1000;
            s_surveying = s_survey_requested.exchange(false, std::memory_order_relaxed);
            s_survey.clear();
        }
        ++s_walk_frames;
        bool finished = false;
        for (;;)
        {
            const EntityWalk::Step step = s_walk.step(s_batch, WALK_BATCH);
            process_batch();
            if (step != EntityWalk::Step::More)
            {
                finish_walk(step == EntityWalk::Step::Done);
                finished = true;
                break;
            }
            if (s_walk_entities >= MAX_WALK_ENTITIES)
            {
                s_walk.cancel();
                finish_walk(false);
                finished = true;
                break;
            }
            if (steady_us() - start_us >= WALK_BUDGET_US)
            {
                break;
            }
        }
        s_walk_busy_us += steady_us() - start_us;
        return finished;
    }

    std::size_t collect_interactables(
        const game_structures::Vec3f &center,
        float radius,
        std::uint32_t kind_mask,
        std::vector<InteractTarget> &out,
        std::vector<InteractVisual> *visuals
    )
    {
        DMK_PROFILE_FUNCTION();
        out.clear();
        if (visuals != nullptr)
        {
            visuals->clear();
        }
        s_targets.clear();
        if (!interactables_available() || kind_mask == 0 || !(radius > 0.0f))
        {
            return 0;
        }
        s_collect_radius = radius;
        for (const Candidate &candidate : s_candidates)
        {
            // The walk's position rules out the rest of the level before anything is read.
            if (!kind_wanted(candidate, kind_mask) ||
                distance_between(candidate.position, center) > radius + WALK_MARGIN)
            {
                continue;
            }
            // Re-resolving by id drops an entity removed since the walk before anything reads it.
            const std::uintptr_t entity = entity_from_id(candidate.id);
            if (entity == 0 || entity_is_hidden(entity))
            {
                continue;
            }
            const std::optional<game_structures::Vec3f> position = entity_world_position(entity);
            if (!position.has_value())
            {
                continue;
            }
            const float distance = distance_between(*position, center);
            if (distance > radius)
            {
                continue;
            }
            if ((candidate.traits & TRAIT_READABLE) != 0 && !book_readable(candidate.id, entity))
            {
                continue;
            }
            place_target(candidate, entity, *position, distance);
        }
        publish(out, visuals);
        return out.size();
    }

    bool advance_interactable_visuals(
        const game_structures::Vec3f & /*center*/,
        std::vector<InteractTarget> & /*out*/,
        std::vector<InteractVisual> * /*visuals*/,
        std::int64_t /*budget_us*/,
        OutlinedNodesFn /*outlined*/
    )
    {
        // KCD1 has no prefab template library and no trigger mesh search, so collect_interactables() queues no
        // lookup and nothing changes here. [KCD2 looks the queued trigger meshes up here]
        return false;
    }

} // namespace HenrySenses
