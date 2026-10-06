/**
 * @file engine/game_natives.cpp
 * @brief The game's gameplay predicates reached natively (see game_natives.hpp for the object map).
 */

#include "engine/game_natives.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "global_state.hpp"
#include "rtti_types.hpp"
#include "engine/engine_env.hpp"
#include "engine/entity_access.hpp"
#include "engine/seh.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace HenrySenses
{
    namespace
    {
        // Safety bounds on the engine structures walked here.
        constexpr std::size_t MAX_TREE_DEPTH = 64;

        /**
         * @brief Calls @p fn(args...) under SEH.
         * @return True when the call returned.
         */
        template <typename R, typename... A>
        [[nodiscard]] bool guarded_call(std::uintptr_t fn, R *out, A... args) noexcept
        {
            __try
            {
                *out = reinterpret_cast<R(__fastcall *)(A...)>(fn)(args...);
                return true;
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return false;
            }
        }

        /**
         * @brief Calls the virtual at @p slot of @p object, whose vtable and target must lie in the game image.
         * @return The result, or std::nullopt when the slot is not plausible or the call faulted.
         */
        template <typename R, typename... A>
        [[nodiscard]] std::optional<R> vcall(std::uintptr_t object, std::ptrdiff_t slot, A... args) noexcept
        {
            const std::uintptr_t fn = read_vtable_slot(object, slot);
            if (fn == 0)
            {
                return std::nullopt;
            }
            R result{};
            if (!guarded_call<R>(fn, &result, object, args...))
            {
                return std::nullopt;
            }
            return result;
        }

        /** @brief A plausible, 8-byte aligned pointer: the structural screen before a guarded read of an engine node.
         */
        [[nodiscard]] bool node_pointer(std::uintptr_t p) noexcept
        {
            return DMK::memory::is_plausible_ptr(DMK::Address{p}) && (p & 7) == 0;
        }

        /** @brief The entity's world position is within @p reach_sq (squared metres) of @p center. */
        [[nodiscard]] bool
        entity_within(std::uintptr_t entity, const game_structures::Vec3f &center, float reach_sq) noexcept
        {
            if (!node_pointer(entity))
            {
                return false;
            }
            const std::optional<game_structures::Vec3f> position = entity_world_position(entity);
            if (!position.has_value())
            {
                return false;
            }
            const float dx = position->x - center.x;
            const float dy = position->y - center.y;
            const float dz = position->z - center.z;
            return dx * dx + dy * dy + dz * dz <= reach_sq;
        }

        // A node of the actor system's list, read whole: next, prev, then the (EntityId, IActor *) pair.
        using ActorNodeWords = std::array<std::uintptr_t, 4>;
        constexpr std::size_t ACTOR_NODE_NEXT = 0;
        constexpr std::size_t ACTOR_NODE_KEY = constants::ACTOR_NODE_KEY_OFFSET / sizeof(std::uintptr_t);
        constexpr std::size_t ACTOR_NODE_VALUE = constants::ACTOR_NODE_VALUE_OFFSET / sizeof(std::uintptr_t);
        static_assert(
            constants::ACTOR_NODE_KEY_OFFSET % sizeof(std::uintptr_t) == 0 &&
                constants::ACTOR_NODE_VALUE_OFFSET % sizeof(std::uintptr_t) == 0 &&
                ACTOR_NODE_VALUE < std::tuple_size_v<ActorNodeWords>,
            "The actor node fields must be whole words of ActorNodeWords."
        );

        // A node of the item system's map, read whole: left, parent, right, the colour and nil bytes, then the
        // (EntityId, C_PickableItem *) pair.
        using ItemNodeWords = std::array<std::uintptr_t, 6>;
        constexpr std::size_t ITEM_NODE_LEFT = 0;
        constexpr std::size_t ITEM_NODE_RIGHT = 2;
        constexpr std::size_t ITEM_NODE_KEY = constants::ITEM_NODE_KEY_OFFSET / sizeof(std::uintptr_t);
        constexpr std::size_t ITEM_NODE_VALUE = constants::ITEM_NODE_VALUE_OFFSET / sizeof(std::uintptr_t);
        static_assert(
            constants::ITEM_NODE_KEY_OFFSET % sizeof(std::uintptr_t) == 0 &&
                constants::ITEM_NODE_VALUE_OFFSET % sizeof(std::uintptr_t) == 0 &&
                ITEM_NODE_VALUE < std::tuple_size_v<ItemNodeWords> &&
                constants::ITEM_NODE_IS_NIL_OFFSET < sizeof(ItemNodeWords),
            "The item node fields must lie inside ItemNodeWords."
        );

        // A slot of the item manager's salt buffer, read whole: the salt in the low 16 bits of word 0, the C_Item in
        // word 2.
        using ItemSaltSlotWords = std::array<std::uint64_t, 3>;
        static_assert(
            sizeof(ItemSaltSlotWords) == constants::ITEM_SALT_SLOT_STRIDE &&
                constants::ITEM_SALT_SLOT_ITEM_OFFSET == 2 * sizeof(std::uint64_t),
            "The item salt slot fields must be the words of ItemSaltSlotWords."
        );

        /**
         * @brief One object of a level-wide map (an actor or a pickable item) on its way through the near pick.
         */
        struct NodeRef
        {
            EntityId id{0};
            std::uintptr_t object{0};
            std::uintptr_t entity{0};
        };

        // Main-thread scratch of the near picks, reused so a pick does not allocate.
        std::vector<NodeRef> s_actor_refs;
        std::vector<NodeRef> s_item_refs;

        /**
         * @class NodeHistory
         * @brief The node addresses a map walk read last time, in order, so this walk can prefetch its next nodes.
         * @details A linked walk cannot look ahead (each next pointer sits in the node being read), but a level's maps
         *          change little between two picks, so the node read k steps on is most likely the one read k steps on
         *          last time. A wrong guess costs only a wasted prefetch. Main thread only.
         */
        class NodeHistory
        {
        public:
            /** @brief Starts a walk. */
            void begin() noexcept { m_current.clear(); }

            /**
             * @brief Records the node about to be read and prefetches the one last walk read PREFETCH_DISTANCE on.
             * @param node The node.
             * @param size The bytes read from it.
             */
            void visit(std::uintptr_t node, std::size_t size)
            {
                if (const std::size_t ahead = m_current.size() + PREFETCH_DISTANCE; ahead < m_last.size())
                {
                    prefetch_line(m_last[ahead]);
                    prefetch_line(m_last[ahead] + size - 1);
                }
                m_current.push_back(node);
            }

            /** @brief Ends a walk: its nodes are the guesses of the next one. */
            void finish() noexcept { m_last.swap(m_current); }

        private:
            std::vector<std::uintptr_t> m_last;
            std::vector<std::uintptr_t> m_current;
        };

        NodeHistory s_actor_history;
        NodeHistory s_item_history;

        /**
         * @brief Reads each object's entity pointer, then keeps the objects whose entity lies within reach.
         * @details The map walk itself is a chain of dependent reads, but these two passes read independent objects,
         *          so each prefetches a few entries ahead and the cache misses overlap instead of adding up (the actor
         *          pick over ~2400 actors went from ~1.5 ms to ~1 ms, the item pick from ~0.8 ms to ~0.55 ms).
         * @param refs The objects in map order; left holding the ones within reach, in the same order.
         * @param entity_offset Where the object keeps its CEntity pointer.
         */
        void keep_within(
            std::vector<NodeRef> &refs,
            std::ptrdiff_t entity_offset,
            const game_structures::Vec3f &center,
            float reach_sq
        ) noexcept
        {
            const std::size_t count = refs.size();
            for (std::size_t i = 0; i < count; ++i)
            {
                if (i + PREFETCH_DISTANCE < count)
                {
                    prefetch_line(refs[i + PREFETCH_DISTANCE].object + entity_offset);
                }
                const auto entity = DMK::memory::read<std::uintptr_t>(DMK::Address{refs[i].object + entity_offset});
                refs[i].entity = entity ? *entity : 0;
            }
            std::size_t kept = 0;
            for (std::size_t i = 0; i < count; ++i)
            {
                if (i + PREFETCH_DISTANCE < count)
                {
                    prefetch_entity(refs[i + PREFETCH_DISTANCE].entity, true);
                }
                if (entity_within(refs[i].entity, center, reach_sq))
                {
                    refs[kept++] = refs[i];
                }
            }
            refs.resize(kept);
        }

        /**
         * @brief Reads an item map node whole.
         * @param node The node.
         * @param words Receives its words.
         * @return True for a readable node that is not the map's nil sentinel.
         */
        [[nodiscard]] bool load_item_node(std::uintptr_t node, ItemNodeWords &words) noexcept
        {
            if (!node_pointer(node))
            {
                return false;
            }
            const auto read = DMK::memory::read<ItemNodeWords>(DMK::Address{node});
            if (!read)
            {
                return false;
            }
            words = *read;
            constexpr std::size_t nil_word = constants::ITEM_NODE_IS_NIL_OFFSET / sizeof(std::uintptr_t);
            constexpr std::size_t nil_shift = constants::ITEM_NODE_IS_NIL_OFFSET % sizeof(std::uintptr_t) * 8;
            return static_cast<std::uint8_t>(words[nil_word] >> nil_shift) == 0;
        }

        [[nodiscard]] std::uintptr_t read_ptr(std::uintptr_t address) noexcept
        {
            const auto value = DMK::memory::read<std::uintptr_t>(DMK::Address{address});
            return value && DMK::memory::is_plausible_ptr(DMK::Address{*value}) ? *value : 0;
        }

        /** @brief The global context (module registry), or 0. */
        [[nodiscard]] std::uintptr_t context() noexcept
        {
            std::byte *const slot = g_global_context_ptr_address.load(std::memory_order_relaxed);
            return slot != nullptr ? read_ptr(reinterpret_cast<std::uintptr_t>(slot)) : 0;
        }

        /** @brief A context module, class-checked. */
        [[nodiscard]] std::uintptr_t context_module(std::ptrdiff_t offset, GameClass klass) noexcept
        {
            const std::uintptr_t ctx = context();
            const std::uintptr_t module = ctx != 0 ? read_ptr(ctx + offset) : 0;
            return object_is(klass, module) ? module : 0;
        }

        /** @brief A member object of the C_EntityModule (its inventory or item manager), class-checked. */
        [[nodiscard]] std::uintptr_t entity_module_member(std::ptrdiff_t offset, GameClass klass) noexcept
        {
            const std::uintptr_t module =
                context_module(constants::CONTEXT_ENTITY_MODULE_OFFSET, GameClass::EntityModule);
            const std::uintptr_t member = module != 0 ? read_ptr(module + offset) : 0;
            return object_is(klass, member) ? member : 0;
        }

        [[nodiscard]] std::uintptr_t actor_system() noexcept
        {
            const std::uintptr_t cry = cry_action();
            const std::uintptr_t system = cry != 0 ? read_ptr(cry + constants::CRYACTION_ACTOR_SYSTEM_OFFSET) : 0;
            return object_is(GameClass::ActorSystem, system) ? system : 0;
        }

        /** @brief The IItemSystem interface of CItemSystem. */
        [[nodiscard]] std::uintptr_t item_system() noexcept
        {
            const std::uintptr_t cry = cry_action();
            const std::uintptr_t system = cry != 0 ? read_ptr(cry + constants::CRYACTION_ITEM_SYSTEM_OFFSET) : 0;
            return object_is(GameClass::ItemSystem, system) ? system + constants::ITEM_SYSTEM_INTERFACE_OFFSET : 0;
        }

        [[nodiscard]] bool wuid_type_is(Wuid wuid, std::uint8_t type) noexcept
        {
            return static_cast<std::uint8_t>(wuid >> 56) == type && (wuid & 0xFFFF) != 0;
        }

        /**
         * @brief Resolves a WUID in one of the game's handle tables (index in the low 16 bits, generation in the next
         *        16).
         * @return The object, or 0 when the slot is empty or holds another generation.
         */
        [[nodiscard]] std::uintptr_t wuid_table_lookup(std::uintptr_t table, Wuid wuid) noexcept
        {
            const std::uintptr_t index = static_cast<std::uintptr_t>(wuid & 0xFFFF);
            const std::uint16_t generation = static_cast<std::uint16_t>((wuid >> 16) & 0xFFFF);
            const std::uintptr_t entry = table + index * constants::WUID_TABLE_STRIDE;
            const auto stored =
                DMK::memory::read<std::uint16_t>(DMK::Address{entry + constants::WUID_TABLE_GENERATION_OFFSET});
            if (!stored || *stored != generation)
            {
                return 0;
            }
            return read_ptr(entry + constants::WUID_TABLE_OBJECT_OFFSET);
        }

        /** @brief The u64 an inventory keeps at +0x00 (its own WUID), unchecked. */
        [[nodiscard]] Wuid inventory_wuid_field(std::uintptr_t inventory) noexcept
        {
            if (!node_pointer(inventory))
            {
                return 0;
            }
            const auto wuid =
                DMK::memory::read<std::uint64_t>(DMK::Address{inventory + constants::INVENTORY_WUID_OFFSET});
            return wuid ? *wuid : 0;
        }

        /**
         * @brief Validates an inventory, which has no vtable to test.
         * @details Its own WUID must name an inventory, and the inventory manager must resolve that WUID back to this
         *          object.
         */
        [[nodiscard]] bool inventory_valid(std::uintptr_t inventory) noexcept
        {
            const Wuid wuid = inventory_wuid_field(inventory);
            return wuid_type_is(wuid, constants::WUID_TYPE_INVENTORY) && inventory_from_wuid(wuid) == inventory;
        }

        /**
         * @brief Resolves an item WUID through the C_ItemManager's salt buffer (the lookup C_PickableItem::CanUse
         *        runs, sub_180454638): the slot in the low 17 bits, the salt above them.
         * @return The C_Item, or 0 when the slot is out of range, holds another salt or another item.
         */
        [[nodiscard]] std::uintptr_t item_from_wuid(Wuid wuid) noexcept
        {
            if (static_cast<std::uint8_t>(wuid >> 56) != constants::WUID_TYPE_ITEM)
            {
                return 0;
            }
            const auto low = static_cast<std::uint32_t>(wuid);
            const std::uint32_t slot = low & ((1u << constants::ITEM_WUID_SLOT_BITS) - 1);
            const auto salt = static_cast<std::uint16_t>(low >> constants::ITEM_WUID_SLOT_BITS);
            if (slot == 0 || slot > constants::ITEM_SALT_LAST_SLOT)
            {
                return 0;
            }
            const std::uintptr_t manager =
                entity_module_member(constants::ENTITY_MODULE_ITEM_MANAGER_OFFSET, GameClass::ItemManager);
            if (manager == 0)
            {
                return 0;
            }
            const auto words = DMK::memory::read<ItemSaltSlotWords>(DMK::Address{
                manager + constants::ITEM_MANAGER_SALT_BUFFER_OFFSET + slot * constants::ITEM_SALT_SLOT_STRIDE
            });
            if (!words || static_cast<std::uint16_t>((*words)[0] & 0xFFFF) != salt)
            {
                return 0;
            }
            const auto item = static_cast<std::uintptr_t>((*words)[2]);
            if (!object_is(GameClass::Item, item))
            {
                return 0;
            }
            const auto stored = DMK::memory::read<std::uint64_t>(DMK::Address{item + constants::ITEM_WUID_OFFSET});
            return stored && *stored == wuid ? item : 0;
        }

        /** @brief The C_Item of a C_PickableItem (the WUID at +0x58, resolved), or 0. */
        [[nodiscard]] std::uintptr_t pickable_item_data(std::uintptr_t pickable) noexcept
        {
            const auto wuid =
                DMK::memory::read<std::uint64_t>(DMK::Address{pickable + constants::PICKABLE_ITEM_DATA_OFFSET});
            return wuid ? item_from_wuid(*wuid) : 0;
        }

        [[nodiscard]] ActorKind kind_of_vtable(std::uintptr_t actor) noexcept
        {
            // One guarded vtable read, then a compare per class (every actor of a pick comes through here).
            if (actor == 0 || !DMK::memory::is_plausible_ptr(DMK::Address{actor}))
            {
                return ActorKind::None;
            }
            const auto vtable = DMK::memory::read<std::uintptr_t>(DMK::Address{actor});
            if (!vtable)
            {
                return ActorKind::None;
            }
            if (vtable_is(GameClass::NpcActor, *vtable))
            {
                return ActorKind::Human;
            }
            if (vtable_is(GameClass::Player, *vtable))
            {
                return ActorKind::Player;
            }
            if (vtable_is(GameClass::Horse, *vtable))
            {
                return ActorKind::Horse;
            }
            if (vtable_is(GameClass::Dog, *vtable))
            {
                return ActorKind::Dog;
            }
            if (vtable_is(GameClass::Animal, *vtable))
            {
                return ActorKind::Animal;
            }
            return ActorKind::None;
        }

        [[nodiscard]] bool read_view(std::uintptr_t actor, EntityId id, ActorView &view) noexcept
        {
            view.kind = kind_of_vtable(actor);
            if (view.kind == ActorKind::None)
            {
                return false;
            }
            view.actor = actor;
            view.id = id;
            view.entity = read_ptr(actor + constants::ACTOR_ENTITY_OFFSET);
            if (!object_is(GameClass::Entity, view.entity))
            {
                return false;
            }
            view.soul = actor_soul(actor);
            return true;
        }

        /**
         * @struct ScriptAnyValue
         * @brief The engine's ScriptAnyValue: the requested (then read) type at +0, the payload at +8.
         */
        struct alignas(8) ScriptAnyValue
        {
            std::int32_t type;
            std::int32_t pad;
            union
            {
                // The engine's bool, read as its byte: a foreign byte other than 0 or 1 is not a valid bool.
                std::uint8_t boolean;
                float number;
                std::uint64_t handle;
            };
            std::byte rest[constants::SCRIPT_ANY_VALUE_SIZE - 16];
        };
        static_assert(sizeof(ScriptAnyValue) == constants::SCRIPT_ANY_VALUE_SIZE);

        /**
         * @brief Reads one script-table field of an entity with the requested type.
         * @return True when the field exists and converted to @p type.
         */
        [[nodiscard]] bool
        read_script_value(std::uintptr_t entity, const char *key, std::int32_t type, ScriptAnyValue &value) noexcept
        {
            const std::uintptr_t proxy = entity_proxy(entity, constants::ENTITY_PROXY_SCRIPT);
            if (proxy == 0)
            {
                return false;
            }
            const std::optional<std::uintptr_t> table =
                vcall<std::uintptr_t>(proxy, constants::SCRIPT_PROXY_VTABLE_GET_TABLE_OFFSET);
            if (!table || !DMK::memory::is_plausible_ptr(DMK::Address{*table}))
            {
                return false;
            }
            value = ScriptAnyValue{};
            value.type = type;
            const std::optional<bool> read =
                vcall<bool>(*table, constants::SCRIPT_TABLE_VTABLE_GET_VALUE_ANY_OFFSET, key, &value, false);
            return read.value_or(false) && value.type == type;
        }

        /**
         * @brief Drops the reference a table read handed over (IScriptTable::Release, which frees the wrapper and its
         *        registry reference at zero).
         */
        void release_script_table(std::uintptr_t table) noexcept
        {
            const std::uintptr_t fn = read_vtable_slot(table, constants::SCRIPT_TABLE_VTABLE_RELEASE_OFFSET);
            if (fn == 0)
            {
                return;
            }
            __try
            {
                reinterpret_cast<void(__fastcall *)(std::uintptr_t)>(fn)(table);
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
            }
        }

        /// The body owners whose loot verdict was logged. Cleared when full, so a long session keeps logging.
        std::unordered_set<Wuid> s_logged_body_owners;
        constexpr std::size_t LOGGED_BODY_OWNERS_MAX = 256;

        /**
         * @brief Logs, once per owner and at Debug, the loot-window verdict of a body and the player's hunting permit,
         *        which decides wild game.
         */
        void
        log_body_owner_once(Wuid owner, bool legal, std::optional<std::uintptr_t> place, std::uintptr_t player) noexcept
        {
            if (!DMK::log().is_enabled(DMK::LogLevel::Debug))
            {
                return;
            }
            try
            {
                if (s_logged_body_owners.size() >= LOGGED_BODY_OWNERS_MAX)
                {
                    s_logged_body_owners.clear();
                }
                if (!s_logged_body_owners.insert(owner).second)
                {
                    return;
                }
            }
            catch (...)
            {
                return;
            }
            const std::optional<bool> permit =
                vcall<bool>(player, constants::SOUL_VTABLE_HAS_ABILITY_OFFSET, constants::SOUL_ABILITY_HUNTING_PERMIT);
            (void)DMK::log().try_log(
                DMK::LogLevel::Debug,
                "LootScan: body owner {:#x} legal={} faction location={} (player HuntingPermit={})",
                owner,
                legal,
                place.has_value() ? (*place != 0 ? "yes" : "none") : (legal ? "n/a" : "unreadable"),
                permit.has_value() ? (*permit ? "yes" : "no") : "unreadable"
            );
        }
    } // namespace

    DMK::Result<void> initialize_game_natives()
    {
        struct Feature
        {
            AnchorId anchor;
            const char *effect;
        };
        constexpr std::array<Feature, 5> features = {{
            {AnchorId::CanLoot, "corpses are never offered as loot (the game's CanLoot test is not available)"},
            {AnchorId::LegalToTake, "no animal carcass counts as stolen (the game's theft test is not available)"},
            {AnchorId::InventoryOwner, "containers are never flagged as stealing"},
            {AnchorId::PublicEnemyRelation, "public enemies are not told apart (no corpse counts as illegal to loot)"},
            {AnchorId::FactionManager, "public enemies are not told apart (no corpse counts as illegal to loot)"},
        }};
        std::size_t missing = 0;
        for (const Feature &feature : features)
        {
            if (anchor_address(feature.anchor) == 0)
            {
                ++missing;
                DMK::log().warning("GameNatives: {} did not resolve; {}", anchor_label(feature.anchor), feature.effect);
            }
        }
        DMK::log().info("GameNatives: ready ({} of {} anchors resolved)", features.size() - missing, features.size());
        return {};
    }

    void shutdown_game_natives() noexcept {}

    // Actors and souls

    bool collect_actors_near(
        std::vector<ActorView> &out,
        const game_structures::Vec3f &center,
        float reach,
        std::size_t max_actors,
        std::size_t *total
    )
    {
        DMK_PROFILE_FUNCTION();
        out.clear();
        if (total != nullptr)
        {
            *total = 0;
        }
        const std::uintptr_t system = actor_system();
        const std::uintptr_t head = system != 0 ? read_ptr(system + constants::ACTOR_SYSTEM_LIST_HEAD_OFFSET) : 0;
        if (head == 0)
        {
            return false;
        }
        std::uintptr_t node = read_ptr(head);
        if (node == 0)
        {
            return false;
        }
        s_actor_refs.clear();
        s_actor_history.begin();
        std::size_t visited = 0;
        while (node != head)
        {
            if (!node_pointer(node) || ++visited > max_actors)
            {
                break;
            }
            s_actor_history.visit(node, sizeof(ActorNodeWords));
            const auto words = DMK::memory::read<ActorNodeWords>(DMK::Address{node});
            if (!words)
            {
                break;
            }
            const auto id = static_cast<std::uint32_t>((*words)[ACTOR_NODE_KEY]);
            const std::uintptr_t actor = (*words)[ACTOR_NODE_VALUE];
            if (id != 0 && node_pointer(actor))
            {
                s_actor_refs.push_back(NodeRef{.id = id, .object = actor});
            }
            node = (*words)[ACTOR_NODE_NEXT];
        }
        s_actor_history.finish();
        keep_within(s_actor_refs, constants::ACTOR_ENTITY_OFFSET, center, reach * reach);
        for (const NodeRef &ref : s_actor_refs)
        {
            ActorView view{};
            if (read_view(ref.object, ref.id, view))
            {
                out.push_back(view);
            }
        }
        if (total != nullptr)
        {
            *total = visited;
        }
        return node == head;
    }

    std::uintptr_t actor_of(EntityId id) noexcept
    {
        const std::uintptr_t system = actor_system();
        if (system == 0 || id == 0)
        {
            return 0;
        }
        const std::optional<std::uintptr_t> actor =
            vcall<std::uintptr_t>(system, constants::ACTOR_SYSTEM_VTABLE_GET_ACTOR_OFFSET, id);
        return actor && kind_of_vtable(*actor) != ActorKind::None ? *actor : 0;
    }

    std::uintptr_t actor_soul(std::uintptr_t actor) noexcept
    {
        const std::uintptr_t soul = actor != 0 ? read_ptr(actor + constants::ACTOR_SOUL_OFFSET) : 0;
        return object_is(GameClass::Soul, soul) ? soul : 0;
    }

    bool actor_despawned(std::uintptr_t /*actor*/) noexcept
    {
        // No verified KCD1 field tells a disposed body from one asleep out of view.
        return false;
    }

    std::optional<bool> actor_is_dead(std::uintptr_t actor) noexcept
    {
        const std::optional<float> health = actor_health(actor);
        return health.has_value() ? std::optional<bool>{*health <= 0.0f} : std::nullopt;
    }

    std::optional<float> actor_health(std::uintptr_t actor) noexcept
    {
        return actor != 0 ? vcall<float>(actor, constants::ACTOR_VTABLE_GET_HEALTH_OFFSET) : std::nullopt;
    }

    std::optional<bool> soul_is_unconscious(std::uintptr_t soul) noexcept
    {
        return soul != 0 ? vcall<bool>(soul, constants::SOUL_VTABLE_IS_UNCONSCIOUS_OFFSET) : std::nullopt;
    }

    std::optional<bool> soul_is_public_enemy(std::uintptr_t soul) noexcept
    {
        const std::uintptr_t manager = gated_anchor_address(Feature::PublicEnemy, AnchorId::FactionManager);
        if (soul == 0 || manager == 0 || !object_is(GameClass::Soul, soul) ||
            !object_is(GameClass::FactionManager, manager))
        {
            return std::nullopt;
        }
        const std::uintptr_t fn = validated_vtable_slot(
            manager,
            constants::FACTION_MANAGER_VTABLE_RELATION_OFFSET,
            AnchorId::PublicEnemyRelation
        );
        if (fn == 0)
        {
            return std::nullopt;
        }
        float relation = 0.0f;
        if (!guarded_call<float>(fn, &relation, manager, constants::PUBLIC_ENEMY_FACTION, soul))
        {
            return std::nullopt;
        }
        return relation < 0.0f;
    }

    std::optional<bool> soul_is_legal_to_loot(std::uintptr_t soul) noexcept
    {
        return soul_is_public_enemy(soul);
    }

    std::optional<bool>
    body_loot_is_legal(std::uintptr_t body_soul, std::uintptr_t player_soul, Wuid player_soul_wuid) noexcept
    {
        const std::uintptr_t fn = gated_anchor_address(Feature::LegalToTake, AnchorId::LegalToTake);
        if (fn == 0 || body_soul == 0 || player_soul == 0)
        {
            return std::nullopt;
        }
        const std::uintptr_t inventory = soul_inventory(body_soul);
        const std::optional<Wuid> owner_wuid = inventory != 0 ? inventory_owner(inventory) : std::optional<Wuid>{};
        if (!owner_wuid.has_value())
        {
            return std::nullopt;
        }
        // An item without an owner, or one the player owns, is never stolen (CanSteal 0x18045299C).
        if (*owner_wuid == constants::WUID_INVALID || *owner_wuid == player_soul_wuid)
        {
            return true;
        }
        const std::uintptr_t owner = soul_from_wuid(*owner_wuid);
        if (owner == 0 || owner == player_soul)
        {
            return true;
        }
        bool legal = false;
        if (!guarded_call<bool>(fn, &legal, std::uintptr_t{0}, std::uintptr_t{0}, owner, player_soul))
        {
            return std::nullopt;
        }
        // The loot window marks an item stolen only when it can name the owner's faction location (0x18112BB98).
        const std::optional<std::uintptr_t> place =
            legal ? std::optional<std::uintptr_t>{}
                  : vcall<std::uintptr_t>(owner, constants::SOUL_VTABLE_FACTION_LOCATION_OFFSET);
        log_body_owner_once(*owner_wuid, legal, place, player_soul);
        if (legal)
        {
            return true;
        }
        if (!place.has_value())
        {
            return std::nullopt;
        }
        return *place == 0;
    }

    Wuid soul_wuid(std::uintptr_t soul) noexcept
    {
        if (soul == 0)
        {
            return 0;
        }
        const auto wuid = DMK::memory::read<std::uint64_t>(DMK::Address{soul + constants::SOUL_WUID_OFFSET});
        return wuid ? *wuid : 0;
    }

    std::uintptr_t soul_from_wuid(Wuid wuid) noexcept
    {
        if (!wuid_type_is(wuid, constants::WUID_TYPE_SOUL))
        {
            return 0;
        }
        const std::uintptr_t souls = context_module(constants::CONTEXT_SOUL_LIST_OFFSET, GameClass::SoulList);
        if (souls == 0)
        {
            return 0;
        }
        const std::uintptr_t soul = wuid_table_lookup(souls + constants::SOUL_MANAGER_TABLE_OFFSET, wuid);
        return object_is(GameClass::Soul, soul) && soul_wuid(soul) == wuid ? soul : 0;
    }

    std::uintptr_t soul_inventory(std::uintptr_t soul) noexcept
    {
        const std::uintptr_t inventory = soul != 0 ? read_ptr(soul + constants::SOUL_INVENTORY_OFFSET) : 0;
        return inventory_valid(inventory) ? inventory : 0;
    }

    std::optional<bool> soul_loot_pending(std::uintptr_t soul) noexcept
    {
        if (!object_is(GameClass::Soul, soul))
        {
            return std::nullopt;
        }
        const auto health = DMK::memory::read<float>(DMK::Address{soul + constants::SOUL_HEALTH_OFFSET});
        const auto generated =
            DMK::memory::read<std::uint8_t>(DMK::Address{soul + constants::SOUL_LOOT_GENERATED_OFFSET});
        const std::uintptr_t row = read_ptr(soul + constants::SOUL_CLASS_ROW_OFFSET);
        if (!health || !generated || row == 0)
        {
            return std::nullopt;
        }
        const auto preset = DMK::memory::read<std::array<std::uint64_t, 2>>(
            DMK::Address{row + constants::SOUL_CLASS_DEFAULT_PRESET_OFFSET}
        );
        if (!preset)
        {
            return std::nullopt;
        }
        return *health <= 0.0f && *generated == 0 && ((*preset)[0] != 0 || (*preset)[1] != 0);
    }

    std::optional<bool> actor_can_loot(std::uintptr_t looter, EntityId victim) noexcept
    {
        const std::uintptr_t fn = gated_anchor_address(Feature::CanLoot, AnchorId::CanLoot);
        if (fn == 0 || victim == 0 || kind_of_vtable(looter) == ActorKind::None)
        {
            return std::nullopt;
        }
        bool allowed = false;
        if (!guarded_call<bool>(fn, &allowed, looter, victim))
        {
            return std::nullopt;
        }
        return allowed;
    }

    // Inventories

    std::optional<std::size_t> inventory_item_count(std::uintptr_t inventory) noexcept
    {
        if (!inventory_valid(inventory))
        {
            return std::nullopt;
        }
        const auto count =
            DMK::memory::read<std::uint64_t>(DMK::Address{inventory + constants::INVENTORY_ITEM_COUNT_OFFSET});
        return count ? std::optional<std::size_t>{static_cast<std::size_t>(*count)} : std::nullopt;
    }

    std::optional<bool> inventory_is_empty_for_player(std::uintptr_t /*inventory*/) noexcept
    {
        return std::nullopt;
    }

    std::optional<bool> inventory_is_usable(std::uintptr_t inventory) noexcept
    {
        if (!inventory_valid(inventory))
        {
            return std::nullopt;
        }
        const auto read_only =
            DMK::memory::read<std::uint8_t>(DMK::Address{inventory + constants::INVENTORY_READ_ONLY_OFFSET});
        if (!read_only)
        {
            return std::nullopt;
        }
        if (*read_only == 0)
        {
            return true;
        }
        const std::optional<std::size_t> count = inventory_item_count(inventory);
        return count.has_value() ? std::optional<bool>{*count != 0} : std::nullopt;
    }

    std::uintptr_t inventory_from_wuid(Wuid wuid) noexcept
    {
        if (!wuid_type_is(wuid, constants::WUID_TYPE_INVENTORY))
        {
            return 0;
        }
        const std::uintptr_t manager =
            entity_module_member(constants::ENTITY_MODULE_INVENTORY_MANAGER_OFFSET, GameClass::InventoryManager);
        if (manager == 0)
        {
            return 0;
        }
        const std::uintptr_t inventory = wuid_table_lookup(manager + constants::INVENTORY_MANAGER_TABLE_OFFSET, wuid);
        return inventory != 0 && inventory_wuid_field(inventory) == wuid ? inventory : 0;
    }

    std::optional<Wuid> inventory_owner(std::uintptr_t inventory) noexcept
    {
        const std::uintptr_t fn = gated_anchor_address(Feature::InventoryOwner, AnchorId::InventoryOwner);
        if (fn == 0 || !inventory_valid(inventory))
        {
            return std::nullopt;
        }
        std::uint64_t owner = 0;
        std::uint64_t *returned = nullptr;
        if (!guarded_call<std::uint64_t *>(fn, &returned, inventory, &owner))
        {
            return std::nullopt;
        }
        return owner;
    }

    // World items

    bool collect_items_near(
        std::vector<ItemView> &out,
        const game_structures::Vec3f &center,
        float reach,
        std::size_t max_items,
        std::size_t *total
    )
    {
        DMK_PROFILE_FUNCTION();
        out.clear();
        if (total != nullptr)
        {
            *total = 0;
        }
        const std::uintptr_t system = item_system();
        const std::uintptr_t head = system != 0 ? read_ptr(system + constants::ITEM_MAP_HEAD_OFFSET) : 0;
        if (head == 0)
        {
            return false;
        }
        const auto root = DMK::memory::read<std::uintptr_t>(DMK::Address{head + sizeof(std::uintptr_t)});
        if (!root)
        {
            return false;
        }
        s_item_refs.clear();
        s_item_history.begin();
        auto load = [](std::uintptr_t node, ItemNodeWords &into)
        {
            s_item_history.visit(node, sizeof(ItemNodeWords));
            return load_item_node(node, into);
        };
        // In-order walk from the root (the head's parent) with an explicit stack of whole nodes, so each node is read
        // once.
        std::array<ItemNodeWords, MAX_TREE_DEPTH> stack{};
        std::size_t depth = 0;
        ItemNodeWords words{};
        bool have = load(*root, words);
        std::size_t visited = 0;
        bool complete = true;
        while (have || depth != 0)
        {
            while (have)
            {
                if (depth == stack.size())
                {
                    complete = false;
                    break;
                }
                stack[depth++] = words;
                have = load(words[ITEM_NODE_LEFT], words);
            }
            if (!complete || depth == 0)
            {
                break;
            }
            const ItemNodeWords current = stack[--depth];
            if (++visited > max_items)
            {
                complete = false;
                break;
            }
            const auto id = static_cast<std::uint32_t>(current[ITEM_NODE_KEY]);
            const std::uintptr_t item = current[ITEM_NODE_VALUE];
            if (id != 0 && node_pointer(item))
            {
                s_item_refs.push_back(NodeRef{.id = id, .object = item});
            }
            have = load(current[ITEM_NODE_RIGHT], words);
        }
        s_item_history.finish();
        keep_within(s_item_refs, constants::PICKABLE_ITEM_ENTITY_OFFSET, center, reach * reach);
        for (const NodeRef &ref : s_item_refs)
        {
            if (object_is(GameClass::PickableItem, ref.object) && object_is(GameClass::Entity, ref.entity) &&
                entity_id_of(ref.entity) == ref.id)
            {
                // KCD1 keeps the item's WUID here, which the item manager resolves. [KCD2 a C_Item pointer]
                const std::uintptr_t data = pickable_item_data(ref.object);
                if (data != 0)
                {
                    out.push_back(ItemView{ref.id, ref.object, data, ref.entity});
                }
            }
        }
        if (total != nullptr)
        {
            *total = visited;
        }
        return complete;
    }

    std::optional<std::size_t> item_map_size() noexcept
    {
        const std::uintptr_t system = item_system();
        if (system == 0)
        {
            return std::nullopt;
        }
        const auto size = DMK::memory::read<std::uint64_t>(DMK::Address{system + constants::ITEM_MAP_SIZE_OFFSET});
        return size ? std::optional<std::size_t>{static_cast<std::size_t>(*size)} : std::nullopt;
    }

    bool item_still_on(const ItemView &item, std::uintptr_t entity) noexcept
    {
        if (entity == 0 || entity != item.entity)
        {
            return false;
        }
        const auto stored =
            DMK::memory::read<std::uintptr_t>(DMK::Address{item.item + constants::PICKABLE_ITEM_ENTITY_OFFSET});
        return stored && *stored == entity;
    }

    EntityPresence entity_presence(
        std::uintptr_t entity,
        EntityId id,
        std::uintptr_t klass,
        const game_structures::Vec3f &center,
        float reach
    ) noexcept
    {
        if (!node_pointer(entity))
        {
            return EntityPresence::Gone;
        }
        const auto stored_id = DMK::memory::read<std::uint32_t>(DMK::Address{entity + constants::ENTITY_ID_OFFSET});
        if (!stored_id || *stored_id != id)
        {
            return EntityPresence::Gone;
        }
        const auto stored_class =
            DMK::memory::read<std::uintptr_t>(DMK::Address{entity + constants::ENTITY_CLASS_OFFSET});
        if (!stored_class || *stored_class != klass)
        {
            return EntityPresence::Gone;
        }
        return entity_within(entity, center, reach * reach) ? EntityPresence::Near : EntityPresence::Far;
    }

    std::optional<ItemView> item_of(EntityId id) noexcept
    {
        const std::uintptr_t system = item_system();
        if (system == 0 || id == 0)
        {
            return std::nullopt;
        }
        const std::optional<std::uintptr_t> item =
            vcall<std::uintptr_t>(system, constants::ITEM_SYSTEM_VTABLE_GET_ITEM_OFFSET, id);
        if (!item || !object_is(GameClass::PickableItem, *item))
        {
            return std::nullopt;
        }
        const std::uintptr_t data = pickable_item_data(*item);
        const std::uintptr_t entity = read_ptr(*item + constants::PICKABLE_ITEM_ENTITY_OFFSET);
        if (data == 0 || !object_is(GameClass::Entity, entity))
        {
            return std::nullopt;
        }
        return ItemView{id, *item, data, entity};
    }

    std::optional<bool> item_is_pickable(const ItemView &item) noexcept
    {
        const std::optional<bool> used = item_in_use(item);
        if (!used.has_value())
        {
            return std::nullopt;
        }
        if (*used)
        {
            return false;
        }
        // A C_Item without a class falls back to the game's default class, which the mod does not resolve.
        const std::uintptr_t klass = read_ptr(item.data + constants::ITEM_CLASS_OFFSET);
        if (klass == 0)
        {
            return std::nullopt;
        }
        const std::optional<std::uint32_t> flags =
            vcall<std::uint32_t>(klass, constants::ITEM_CLASS_VTABLE_FLAGS_OFFSET);
        return flags.has_value() ? std::optional<bool>{(*flags & constants::ITEM_CLASS_PLAYER_ITEM) != 0}
                                 : std::nullopt;
    }

    std::optional<bool> item_in_use(const ItemView &item) noexcept
    {
        const auto state =
            DMK::memory::read<std::uint8_t>(DMK::Address{item.item + constants::PICKABLE_ITEM_STATE_OFFSET});
        return state ? std::optional<bool>{(*state & constants::PICKABLE_ITEM_IN_USE) != 0} : std::nullopt;
    }

    std::optional<bool> item_is_npc_only(const ItemView &item) noexcept
    {
        return script_bool(item.entity, "npcOnly");
    }

    std::uintptr_t item_owner(const ItemView &item) noexcept
    {
        const auto wuid = DMK::memory::read<std::uint64_t>(DMK::Address{item.data + constants::ITEM_INVENTORY_OFFSET});
        return wuid ? inventory_from_wuid(*wuid) : 0;
    }

    ItemHolder item_holder(const ItemView &item) noexcept
    {
        const auto wuid = DMK::memory::read<std::uint64_t>(DMK::Address{item.data + constants::ITEM_INVENTORY_OFFSET});
        if (!wuid)
        {
            return ItemHolder::Unknown;
        }
        if (*wuid == constants::WUID_INVALID)
        {
            return ItemHolder::None;
        }
        // Only an inventory stamps its WUID here, so any other value is a value the mod does not know.
        return wuid_type_is(*wuid, constants::WUID_TYPE_INVENTORY) ? ItemHolder::Inventory : ItemHolder::Unknown;
    }

    std::optional<bool> item_can_steal(const ItemView &item, EntityId user) noexcept
    {
        return vcall<bool>(item.item, constants::PICKABLE_ITEM_VTABLE_CAN_STEAL_OFFSET, user);
    }

    std::optional<bool> item_is_from_shop(const ItemView &item) noexcept
    {
        const auto flags = DMK::memory::read<std::uint32_t>(DMK::Address{item.data + constants::ITEM_FLAGS_OFFSET});
        return flags ? std::optional<bool>{(*flags & constants::ITEM_FLAG_SHOP) != 0} : std::nullopt;
    }

    // Stashes and shops

    // Script-table fields

    std::optional<bool> script_bool(std::uintptr_t entity, const char *key) noexcept
    {
        ScriptAnyValue value{};
        if (!read_script_value(entity, key, constants::SCRIPT_ANY_BOOLEAN, value))
        {
            return std::nullopt;
        }
        return value.boolean != 0;
    }

    std::optional<Wuid> script_handle(std::uintptr_t entity, const char *key) noexcept
    {
        ScriptAnyValue value{};
        if (!read_script_value(entity, key, constants::SCRIPT_ANY_HANDLE, value))
        {
            return std::nullopt;
        }
        return value.handle;
    }

    std::optional<bool> script_table_bool(std::uintptr_t entity, const char *table_key, const char *key) noexcept
    {
        ScriptAnyValue table{};
        const bool found = read_script_value(entity, table_key, constants::SCRIPT_ANY_TABLE, table);
        // An empty value asks the engine for a new table wrapper that holds one reference; it is dropped below
        // whatever the nested read finds.
        const auto nested = static_cast<std::uintptr_t>(table.handle);
        if (table.type != constants::SCRIPT_ANY_TABLE || nested == 0 ||
            !DMK::memory::is_plausible_ptr(DMK::Address{nested}))
        {
            return std::nullopt;
        }
        std::optional<bool> result{};
        if (found)
        {
            ScriptAnyValue value{};
            value.type = constants::SCRIPT_ANY_BOOLEAN;
            const std::optional<bool> read =
                vcall<bool>(nested, constants::SCRIPT_TABLE_VTABLE_GET_VALUE_ANY_OFFSET, key, &value, false);
            if (read.value_or(false) && value.type == constants::SCRIPT_ANY_BOOLEAN)
            {
                result = value.boolean != 0;
            }
        }
        release_script_table(nested);
        return result;
    }

} // namespace HenrySenses
