/**
 * @file engine/game_natives.hpp
 * @brief The game's own gameplay predicates, called natively: actors and souls, world items, inventories, stashes
 *        and shops.
 *
 * Every function here is the C++ the game's script binds run (C_ScriptBindActor, C_ScriptBindSoul,
 * C_ScriptBindPickableItem, C_ScriptBindInventory, C_ScriptBindEntityModule), reached without Lua:
 *
 * - Actors: IGameFramework::GetIActorSystem (CCryAction + 0x508) holds every actor in an EntityId hash map. An actor
 *   keeps its CEntity at +0x38 and its C_Soul at +0x650. Its class (C_Player, C_NPCActor, C_Horse, C_Dog, C_Animal)
 *   is its kind. GetHealth is an actor virtual, and an actor is dead at 0 health (BasicActor:IsDead). IsUnconscious
 *   is a soul virtual, the inventory a soul field. [KCD2 CCryAction + 0x518, soul +0x668, an IsDead virtual]
 * - World items: IGameFramework::GetIItemSystem (CCryAction + 0x510, interface at +8) holds every C_PickableItem in
 *   an EntityId map. Its C_Item WUID is at +0x58, and the C_ItemManager resolves it. The C_Item keeps the WUID of
 *   the inventory that holds it at +0x68. [KCD2 CCryAction + 0x520, a C_Item * at +0x58, an owner object]
 * - The global context (AnchorId::Context) is a module registry. C_EntityModule sits at +0xB0, and its
 *   C_InventoryManager (+0x108) and C_ItemManager (+0x110) resolve inventory and item WUIDs. C_SoulList sits at
 *   +0x158 and resolves souls. [KCD2 C_EntityModule +0xE0, souls through C_RPGModule +0x130, shops through
 *   C_ShopModule +0x110]
 * - KCD1 has no C_Stash extension, no script contexts, no butcher action and no shop goods walk. A container opens
 *   the inventory its script holds (inventoryId), and a shop item carries a flag in its C_Item. The functions of the
 *   absent parts keep their API and answer "unavailable".
 *
 * Objects are validated by class before any virtual is called, every call runs under SEH, and nothing is cached
 * across calls except per-session lookups the caller keys itself. Main thread only: the script-table reads enter the
 * game's Lua state, and the engine maps are not synchronised.
 */
#ifndef HENRYSENSES_GAME_NATIVES_HPP
#define HENRYSENSES_GAME_NATIVES_HPP

#include "game_structures.hpp"
#include "engine/entity_access.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace HenrySenses
{
    /// The game's 64-bit object handle (souls, inventories, items); type in the top byte.
    using Wuid = std::uint64_t;

    /**
     * @enum ActorKind
     * @brief The class of an actor.
     */
    enum class ActorKind : std::uint8_t
    {
        /// Not an actor, or an actor class the mod does not know.
        None,
        /// The local player (C_Player).
        Player,
        /// A human NPC (C_NPCActor).
        Human,
        /// A horse (C_Horse).
        Horse,
        /// A dog (C_Dog).
        Dog,
        /// Any other animal (C_Animal): game, livestock, birds.
        Animal,
    };

    /**
     * @struct ActorView
     * @brief One actor of the actor system.
     */
    struct ActorView
    {
        EntityId id{0};
        std::uintptr_t actor{0};
        std::uintptr_t entity{0};
        std::uintptr_t soul{0};
        ActorKind kind{ActorKind::None};
    };

    /**
     * @struct ItemView
     * @brief One world item (C_PickableItem) of the item system.
     */
    struct ItemView
    {
        EntityId id{0};
        std::uintptr_t item{0};
        /// Its C_Item (resolved from the WUID at C_PickableItem + 0x58). [KCD2 the pointer at +0x58]
        std::uintptr_t data{0};
        /// Its CEntity.
        std::uintptr_t entity{0};
    };

    /**
     * @enum ItemHolder
     * @brief What holds a world item.
     */
    enum class ItemHolder : std::uint8_t
    {
        /// Nothing: it lies loose in the world (dropped, thrown, fallen from a body).
        None,
        /// An inventory: worn, wielded, carried, or on a body.
        Inventory,
        /// Something else, or the holder does not read.
        Unknown,
    };

    /**
     * @brief Checks the anchors the natives need and reports which features are available.
     * @return Always succeeds; missing anchors disable only the tests that need them (logged).
     */
    [[nodiscard]] DMK::Result<void> initialize_game_natives();

    /** @brief Drops the cached module pointers. */
    void shutdown_game_natives() noexcept;

    // Actors and souls

    /**
     * @brief Copies the actors of the actor system whose entity lies within @p reach of @p center.
     * @details The map holds every actor of the level, so it is walked with plain reads under SEH and only the actors
     *          in reach are validated (class checks, entity, soul).
     * @param out Receives the actors (cleared first); the kind and soul are filled, unknown classes are skipped.
     * @param center The centre.
     * @param reach The distance in metres.
     * @param max_actors Safety bound on the walk.
     * @param total Receives the number of actors walked, when not null.
     * @return True when the map was walked to its end.
     */
    [[nodiscard]] bool collect_actors_near(
        std::vector<ActorView> &out,
        const game_structures::Vec3f &center,
        float reach,
        std::size_t max_actors,
        std::size_t *total = nullptr
    );

    /**
     * @brief Returns the actor of an entity (IActorSystem::GetActor), validated as a known actor class.
     * @param id The entity id.
     * @return The actor, or 0.
     */
    [[nodiscard]] std::uintptr_t actor_of(EntityId id) noexcept;

    /**
     * @brief Returns an actor's C_Soul (+0x650), class-checked. [KCD2 +0x668]
     * @param actor An actor.
     * @return The soul, or 0.
     */
    [[nodiscard]] std::uintptr_t actor_soul(std::uintptr_t actor) noexcept;

    /**
     * @brief Reports whether the game took an actor out of the world: its AI let go of it.
     * @details KCD1 keeps no verified counterpart of the KCD2 test (the bound EntityId of wh::xgenaimodule::C_NPC),
     *          so this answers false for every actor. [KCD2 reads constants::AI_NPC_ACTOR_ID_OFFSET]
     * @param actor An actor.
     * @return False.
     */
    [[nodiscard]] bool actor_despawned(std::uintptr_t actor) noexcept;

    /**
     * @brief actor:IsDead(): KCD1 BasicActor:IsDead() is GetHealth() <= 0. [KCD2 actor vtable slot 38]
     */
    [[nodiscard]] std::optional<bool> actor_is_dead(std::uintptr_t actor) noexcept;

    /** @brief actor:GetHealth() (actor vtable slot 28). [KCD2 slot 30] */
    [[nodiscard]] std::optional<float> actor_health(std::uintptr_t actor) noexcept;

    /** @brief actor:IsUnconscious() (soul vtable slot 6: the consciousness stat at 0). [KCD2 slot 7] */
    [[nodiscard]] std::optional<bool> soul_is_unconscious(std::uintptr_t soul) noexcept;

    /**
     * @brief RPG.IsPublicEnemy for a soul: the faction manager's relation of faction 3 to the soul's faction is below
     *        0. [KCD2 the soul's reputation component (soul vtable slot 50) against the public-enemy faction tag]
     */
    [[nodiscard]] std::optional<bool> soul_is_public_enemy(std::uintptr_t soul) noexcept;

    /**
     * @brief Whether the loot of a soul's body is legal: true only for a public enemy.
     * @details BasicAIActions:AddLootAction offers the plain loot prompt only for a public enemy. [KCD2
     *          soul:IsLegalToLoot(), a public enemy or a soul with script context 84]
     * @param soul A soul.
     * @return The verdict, or std::nullopt when a part could not be evaluated.
     */
    [[nodiscard]] std::optional<bool> soul_is_legal_to_loot(std::uintptr_t soul) noexcept;

    /**
     * @brief Reports whether the player can take the loot of a body legally, the way the loot window decides it.
     * @details The loot of a body belongs to the owner of the body's inventory. That is the body's own soul, or the
     *          player for the horse the player rides. The loot is legal without an owner, or when the owner is the player or
     *          resolves to no soul. It is also legal when C_RPGInventory's test (AnchorId::LegalToTake) passes: for a
     *          public-enemy owner, and for huntable game while the player has the HuntingPermit ability. Otherwise
     *          the loot window marks it stolen only when the owner names a faction location. Generated carcass loot
     *          gets the same owner, so the verdict holds before and after the first loot. [KCD2
     *          soul:IsLegalToLoot()]
     * @param body_soul The body's soul.
     * @param player_soul The player's soul.
     * @param player_soul_wuid The player's soul WUID.
     * @return The verdict, or std::nullopt when a step cannot be evaluated.
     */
    [[nodiscard]] std::optional<bool>
    body_loot_is_legal(std::uintptr_t body_soul, std::uintptr_t player_soul, Wuid player_soul_wuid) noexcept;

    /** @brief A soul's WUID (+0x20). [KCD2 +0x30] */
    [[nodiscard]] Wuid soul_wuid(std::uintptr_t soul) noexcept;

    /** @brief Resolves a soul WUID through the C_SoulList's table. [KCD2 the RPG module's soul table] */
    [[nodiscard]] std::uintptr_t soul_from_wuid(Wuid wuid) noexcept;

    /** @brief A soul's C_Inventory (the pointer at +0xC08). [KCD2 soul vtable slot 60, then the holder's slot 0] */
    [[nodiscard]] std::uintptr_t soul_inventory(std::uintptr_t soul) noexcept;

    /**
     * @brief Reports whether a dead body still has loot that the game adds on the first loot.
     * @details The soul is dead, its loot was never generated (+0x538), and its soul class names a default inventory
     *          preset. The game generates the loot of a carcass once, when the player first loots it.
     * @return The answer, or std::nullopt when the soul or a field cannot be read. [KCD2 has no such test]
     */
    [[nodiscard]] std::optional<bool> soul_loot_pending(std::uintptr_t soul) noexcept;

    /**
     * @brief player.actor:CanLoot(victim), the game's own loot-action test (C_Actor::CanLoot, called natively).
     * @param looter The player's actor (C_Player).
     * @param victim The victim's entity id.
     * @return The verdict, or std::nullopt when a part could not be evaluated.
     */
    [[nodiscard]] std::optional<bool> actor_can_loot(std::uintptr_t looter, EntityId victim) noexcept;

    // Inventories

    /** @brief The number of items an inventory holds (every item, hidden ones included). */
    [[nodiscard]] std::optional<std::size_t> inventory_item_count(std::uintptr_t inventory) noexcept;

    /**
     * @brief EntityModule.HasPlayerVisibleItems: true when no item the player would see in the transfer screen is
     *        left, the test behind the game's "(empty)" prompt.
     * @details KCD1 has no such test, so this always answers std::nullopt (callers fall back to
     *          inventory_item_count()).
     */
    [[nodiscard]] std::optional<bool> inventory_is_empty_for_player(std::uintptr_t inventory) noexcept;

    /**
     * @brief EntityModule.CanUseInventory: true unless the inventory is read-only and empty.
     * @details The game restocks a read-only inventory before it checks the count. This read leaves the inventory as
     *          it is, so a restock that is due does not count yet.
     */
    [[nodiscard]] std::optional<bool> inventory_is_usable(std::uintptr_t inventory) noexcept;

    /** @brief Resolves an inventory WUID through the inventory manager. */
    [[nodiscard]] std::uintptr_t inventory_from_wuid(Wuid wuid) noexcept;

    /**
     * @brief EntityModule.GetInventoryOwner: the WUID of the soul that owns an inventory.
     * @return The WUID (constants::WUID_INVALID for none), or std::nullopt when the call is unavailable.
     */
    [[nodiscard]] std::optional<Wuid> inventory_owner(std::uintptr_t inventory) noexcept;

    // World items

    /**
     * @brief Copies the world items of the item system whose entity lies within @p reach of @p center.
     * @details Walked like collect_actors_near(): plain reads under SEH for the whole map, validation for the items in
     *          reach.
     * @param out Receives the items (cleared first).
     * @param center The centre.
     * @param reach The distance in metres.
     * @param max_items Safety bound on the walk.
     * @param total Receives the number of items walked, when not null.
     * @return True when the map was walked to its end.
     */
    [[nodiscard]] bool collect_items_near(
        std::vector<ItemView> &out,
        const game_structures::Vec3f &center,
        float reach,
        std::size_t max_items,
        std::size_t *total = nullptr
    );

    /**
     * @brief The size field of the item system's map: every world item of the level, so a change means an item was
     *        dropped, spawned or picked up.
     * @return The count, or std::nullopt when the item system is unavailable.
     */
    [[nodiscard]] std::optional<std::size_t> item_map_size() noexcept;

    /**
     * @enum EntityPresence
     * @brief Where a remembered entity is now.
     */
    enum class EntityPresence : std::uint8_t
    {
        /// The pointer no longer carries the id and class it was remembered with (deleted or reused).
        Gone,
        /// Still the same entity, beyond the reach.
        Far,
        /// Still the same entity, within the reach.
        Near,
    };

    /**
     * @brief Tests, with plain reads under SEH, whether @p entity still carries @p id and class @p klass, and whether
     *        it lies within @p reach of @p center.
     * @details For filtering large remembered entity sets cheaply, and for dropping the entries that are gone; a
     *          pointer that passes is still validated before anything is called on it.
     */
    [[nodiscard]] EntityPresence entity_presence(
        std::uintptr_t entity,
        EntityId id,
        std::uintptr_t klass,
        const game_structures::Vec3f &center,
        float reach
    ) noexcept;

    /**
     * @brief Tests that a remembered world item still belongs to @p entity (the item's entity pointer reads back
     *        unchanged); @p entity must come from a validated lookup of the item's id.
     */
    [[nodiscard]] bool item_still_on(const ItemView &item, std::uintptr_t entity) noexcept;

    /** @brief The world item of an entity (IItemSystem::GetItem), as a C_PickableItem. */
    [[nodiscard]] std::optional<ItemView> item_of(EntityId id) noexcept;

    /**
     * @brief The item-class half of item:CanUse: a player item (class type flag 0x4) that is not in use.
     * @details It leaves out the reach half (a user within 1 m) and the soul half (a gated item), so it holds at any
     *          distance. [KCD2 class IsA 25, reach wh_pl_PickMaxDistance]
     */
    [[nodiscard]] std::optional<bool> item_is_pickable(const ItemView &item) noexcept;

    /** @brief item:IsUsed() (the in-use bit of the C_PickableItem). */
    [[nodiscard]] std::optional<bool> item_in_use(const ItemView &item) noexcept;

    /**
     * @brief The script field npcOnly (PickableItem.lua, from Properties.bOnlyNPC).
     * @return The value, or std::nullopt when the field is absent (nil, which the script reads as false) or unreadable.
     *         [KCD2 the C_Item flag the game mirrors into the field]
     * @note Main thread (it runs the script system).
     */
    [[nodiscard]] std::optional<bool> item_is_npc_only(const ItemView &item) noexcept;

    /**
     * @brief What holds a world item: an inventory when the C_Item carries the WUID of one (+0x68), else nothing.
     * @details A new C_Item starts with constants::WUID_INVALID (0x180453678). An inventory stamps its WUID into the
     *          items it takes (0x180451D08) and writes WUID_INVALID back when it lets one go (0x18044F718). An
     *          inventory with the non-stamping flag at +0xA0 (shop, quest delivery or reward, repair) never stamps.
     *          KCD1 tells no slot, borrowed or attached holder apart. [KCD2 the owner object's class]
     */
    [[nodiscard]] ItemHolder item_holder(const ItemView &item) noexcept;

    /**
     * @brief The raw owner object of a world item: the C_Inventory whose WUID the C_Item keeps at +0x68, or 0.
     *        [KCD2 the owner pointer at +0x98, else +0x90]
     */
    [[nodiscard]] std::uintptr_t item_owner(const ItemView &item) noexcept;

    /** @brief item:CanSteal(user) (C_PickableItem vtable slot 92). [KCD2 slot 91] */
    [[nodiscard]] std::optional<bool> item_can_steal(const ItemView &item, EntityId user) noexcept;

    /** @brief item:IsFromShop(): the shop-goods flag (0x4) of the C_Item flags at +0x48. [KCD2 a shop goods walk] */
    [[nodiscard]] std::optional<bool> item_is_from_shop(const ItemView &item) noexcept;

    // Script-table fields the game keeps only on the entity (read through the engine's IScriptTable)

    /** @brief A boolean field of an entity's script table; std::nullopt when absent or not a boolean. */
    [[nodiscard]] std::optional<bool> script_bool(std::uintptr_t entity, const char *key) noexcept;

    /** @brief A handle field (a WUID) of an entity's script table; std::nullopt when absent or not a handle. */
    [[nodiscard]] std::optional<Wuid> script_handle(std::uintptr_t entity, const char *key) noexcept;

    /**
     * @brief A boolean field of a table inside an entity's script table (Properties.bIsDirectlyReadable).
     * @param entity A CEntity.
     * @param table_key The nested table's key ("Properties").
     * @param key The field's key in that table.
     * @return The value; std::nullopt when either level is absent or of another type.
     * @note Main thread (it runs the script system).
     */
    [[nodiscard]] std::optional<bool>
    script_table_bool(std::uintptr_t entity, const char *table_key, const char *key) noexcept;

} // namespace HenrySenses

#endif // HENRYSENSES_GAME_NATIVES_HPP
