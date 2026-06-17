/**
 * @file game_state.cpp
 * @brief Live game-state detection backing the INI-driven camera policy.
 *
 * Combat and dialogue are read from the active wh::game camera: the camera manager stores a pointer to
 * the currently active camera at manager+0x10, and that object carries a TYPE ID at cam+0x08 that
 * identifies the mode (0 FP, 1 TP, 2 Dialog, 3 Combat, 4 Minigame(dice), 7 Ansel). The classification is
 * cached on the active-camera pointer so the steady state costs a single pointer compare. The minigame
 * umbrella and its child come from the C_PlayerModule active-minigame map (so first-person minigames such
 * as reading are detected, not just the dice camera). Mount and crouch come from the player's stance.
 *
 * KCD1 differences vs KCD2: there is no Aiming state (the missile-weapon aim flag was not reverse-
 * engineered for 1.9.7) and no Cart stance; the minigame container is a std::map (not the KCD2 intrusive
 * list); the active camera is identified by its type id (not RTTI on combat/dialog vtables).
 */

#include "game_state.hpp"
#include "constants.hpp"
#include "global_state.hpp"
#include "offset_heal.hpp"
#include "hooks/ui_menu_hooks.hpp"

#include <DetourModKit.hpp>

#include <array>
#include <cctype>
#include <string>

namespace TPVCamera
{

    namespace
    {

        /**
         * @brief Classifies an active-camera type id into the combat / dialogue state bits.
         * @details Caches the last camera pointer and its classification so the steady state (the active
         *          camera unchanged frame to frame) costs one pointer compare; a camera switch re-reads once.
         *          Render-thread only, so the cache is a plain static. Minigames are NOT read from the camera
         *          (only dice swaps the active camera to the minigame camera; reading and the rest stay
         *          first-person), so they are detected separately in poll_active_minigame.
         * @param camera Runtime pointer of the active camera object.
         * @return The matching GameState bit, or 0 when the active camera is none of the tracked modes.
         */
        // Diagnostic stashes (render thread only): the raw signals the last poll observed, so the game-state
        // change log can report the detail (active-camera type id, minigame-map size) behind the mask.
        int s_dbg_camera_type = -1;
        long long s_dbg_minigame_size = -1;

        [[nodiscard]] uint32_t classify_active_camera(uintptr_t camera) noexcept
        {
            static uintptr_t s_last_camera = 0;
            static uint32_t s_last_bits = 0;
            if (camera == s_last_camera)
            {
                return s_last_bits;
            }

            uint32_t bits = 0;
            const auto type_id = DMK::Memory::seh_read<int>(camera + Constants::OFFSET_CAMERA_TYPE_ID);
            s_dbg_camera_type = type_id ? *type_id : -1;
            if (type_id)
            {
                switch (*type_id)
                {
                case Constants::CAMERA_TYPE_DIALOG:
                    bits = state_bit(GameState::Dialogue);
                    break;
                case Constants::CAMERA_TYPE_COMBAT:
                    bits = state_bit(GameState::Combat);
                    break;
                default:
                    bits = 0; // FP / TP / Minigame(dice) / Ansel: no combat/dialogue bit here
                    break;
                }
            }

            s_last_camera = camera;
            s_last_bits = bits;
            return bits;
        }

        /**
         * @brief Resolves the active camera and classifies it, returning 0 on any failed read.
         * @details Dereferences the global-context slot to the context object first (so the self-heal can scan the
         *          anchored base), then once the world is live heals the context member offsets one-shot, then walks
         *          context -> camera manager (self-healed OFFSET_MANAGER_PTR_STORAGE) -> active camera
         *          (OFFSET_ACTIVE_CAMERA) -> type id, each link SEH-guarded and screened as a plausible user-space
         *          pointer. The manager is the same wh::game::C_CameraManager the game-state walk uses.
         */
        [[nodiscard]] uint32_t poll_active_camera_state() noexcept
        {
            const auto context_slot = g_global_context_ptr_address.load(std::memory_order_relaxed);
            if (!context_slot)
            {
                return 0;
            }
            // Resolve the context object first so the self-heal can run against it. Gating the heal on the world
            // being live (rather than on the manager slot being populated) keeps a camera-manager OFFSET drift
            // recoverable: the heal scans the anchored context base, never navigating through the offset it heals.
            const auto context = DMK::Memory::seh_read<uintptr_t>(reinterpret_cast<uintptr_t>(context_slot));
            if (!context || !DMK::Memory::plausible_userspace_ptr(*context))
            {
                return 0;
            }
            if (game_world_ready().load(std::memory_order_relaxed))
            {
                heal_context_offsets(*context);
            }
            // One guarded walk: context object -> camera manager (self-healed OFFSET_MANAGER_PTR_STORAGE) -> active
            // camera (OFFSET_ACTIVE_CAMERA). seh_read_chain screens every intermediate link with
            // plausible_userspace_ptr under a single fault guard; the terminal camera value it returns is not
            // range-checked by the chain, so it is screened here before use.
            const auto camera = DMK::Memory::seh_read_chain<uintptr_t>(
                *context, {runtime_offsets().context_manager.load(std::memory_order_relaxed),
                           Constants::OFFSET_ACTIVE_CAMERA});
            if (!camera || !DMK::Memory::plausible_userspace_ptr(*camera))
            {
                return 0;
            }
            return classify_active_camera(*camera);
        }

        /**
         * @brief Classifies an active-minigame vtable into its child GameState bit (0 when unrecognized).
         * @details Mirrors classify_active_camera: caches the last vtable so the steady state inside a minigame
         *          is one pointer compare with no RTTI walk. Render-thread only, so the cache is a plain static.
         * @param vtable Runtime vtable pointer of the active wh::playermodule::C_Minigame subclass.
         */
        [[nodiscard]] uint32_t classify_minigame_vtable(uintptr_t vtable) noexcept
        {
            static uintptr_t s_last_vtable = 0;
            static uint32_t s_last_bit = 0;
            if (vtable == s_last_vtable)
            {
                return s_last_bit;
            }

            uint32_t bit = 0;
            for (const MinigameInfo &def : k_minigames)
            {
                if (DMK::Rtti::vtable_is_type(vtable, def.rtti_name))
                {
                    bit = state_bit(def.bit);
                    break;
                }
            }

            s_last_vtable = vtable;
            s_last_bit = bit;
            return bit;
        }

        /**
         * @brief Detects whether the player is in a minigame and which one, via the C_PlayerModule.
         * @details The minigame state is NOT readable from the active camera (only dice swaps the camera; see
         *          classify_active_camera), so it is read from the C_PlayerModule that owns every active minigame.
         *          The chain is reached from the same global context the camera manager hangs off:
         *          context -> C_PlayerModule (OFFSET_MINIGAME_SUBSYSTEM) -> std::map holder (OFFSET_MINIGAME_MAP).
         *          The map's _Mysize at +OFFSET_MINIGAME_MAP_SIZE is 0 when no minigame is active and > 0 while in
         *          one; the RB-tree's first real node (the head sentinel's parent / left walk) holds the
         *          C_Minigame* at +OFFSET_MINIGAME_NODE_VALUE, whose vtable identifies which minigame. Single
         *          player has at most one entry, keyed by the player actor id. Every read is SEH-guarded, so a
         *          failed read reports "no minigame" rather than faulting.
         * @param c_player Live C_Player address (unused on KCD1 single-player; kept for signature parity).
         * @return state_bit(Minigame) | the matching child bit when in a minigame, else 0.
         */
        [[nodiscard]] uint32_t poll_active_minigame(uintptr_t c_player) noexcept
        {
            (void)c_player; // single-player: the only map entry is the player's
            s_dbg_minigame_size = -1; // diagnostic: set to the real _Mysize below once the map resolves
            const auto context_slot = g_global_context_ptr_address.load(std::memory_order_relaxed);
            if (!context_slot)
            {
                return 0;
            }
            // Walk g_global_context -> C_PlayerModule -> std::map holder under one fault guard (each intermediate
            // link screened by plausible_userspace_ptr). The map value the chain returns is screened here.
            const auto map = DMK::Memory::seh_read_chain<uintptr_t>(
                reinterpret_cast<uintptr_t>(context_slot),
                {0, runtime_offsets().context_minigame_subsystem.load(std::memory_order_relaxed),
                 Constants::OFFSET_MINIGAME_MAP});
            if (!map || !DMK::Memory::plausible_userspace_ptr(*map))
            {
                return 0;
            }
            // _Mysize == 0 means no active minigame: the cheap gate before walking the tree.
            const auto size = DMK::Memory::seh_read<uint64_t>(*map + Constants::OFFSET_MINIGAME_MAP_SIZE);
            s_dbg_minigame_size = size ? static_cast<long long>(*size) : -1;
            if (!size || *size == 0)
            {
                return 0;
            }
            // *map -> _Myhead, the std::map sentinel. begin() (the smallest key, and the ONLY entry in
            // single-player) = sentinel._Left @ +0x00. NOTE: the KCD2 port walked a circular intrusive LIST here,
            // but KCD1 keeps a red-black tree (std::map): that list walk oscillates straight back to the sentinel
            // and then reads its garbage value, which is why only the umbrella bit (never a child) ever resolved.
            // Read _Left directly -- _Mysize > 0 here, so it is a real node (an empty tree links _Left to itself).
            const auto sentinel = DMK::Memory::seh_read<uintptr_t>(*map);
            if (!sentinel || !DMK::Memory::plausible_userspace_ptr(*sentinel))
            {
                return state_bit(GameState::Minigame); // size > 0 but tree unreadable: at least flag the umbrella
            }
            const auto node = DMK::Memory::seh_read<uintptr_t>(*sentinel); // sentinel._Left = leftmost real node
            if (!node || !DMK::Memory::plausible_userspace_ptr(*node))
            {
                return state_bit(GameState::Minigame);
            }
            const auto minigame = DMK::Memory::seh_read<uintptr_t>(*node + Constants::OFFSET_MINIGAME_NODE_VALUE);
            if (!minigame || !DMK::Memory::plausible_userspace_ptr(*minigame))
            {
                return state_bit(GameState::Minigame);
            }
            const auto vtable = DMK::Memory::seh_read<uintptr_t>(*minigame);
            if (!vtable || !DMK::Memory::plausible_userspace_ptr(*vtable))
            {
                return state_bit(GameState::Minigame);
            }
            return state_bit(GameState::Minigame) | classify_minigame_vtable(*vtable);
        }

        /**
         * @brief Reads the player's current STANCE enum, validated by RTTI, or 0 on any failure.
         * @details C_ActorModel is a POINTER on C_Player (C_PLAYER_ACTOR_MODEL_OFFSET = 0x908), dereferenced and
         *          its vtable validated against the C_ActorModel RTTI name (cached after the first read, so the
         *          steady state is one pointer compare plus the stance read). A layout drift (a wrong vtable)
         *          yields 0 rather than a garbage read. The 4-byte current-stance enum at
         *          C_ACTOR_MODEL_STANCE_OFFSET = 0x1C8 is the SINGLE source for both crouch and mount on KCD1:
         *          0 = standing, 1 = lying, 2 = sitting, 3 = kneel, 4 = mounted (riding), 5 = crouching/sneaking.
         * @return The stance enum value, or 0 if the actor model / RTTI / read failed.
         */
        [[nodiscard]] uint32_t poll_stance(uintptr_t c_player) noexcept
        {
            const auto actor_model = DMK::Memory::seh_read<uintptr_t>(
                c_player + runtime_offsets().c_player_actor_model.load(std::memory_order_relaxed));
            if (!actor_model || !DMK::Memory::plausible_userspace_ptr(*actor_model))
            {
                return 0u;
            }
            const auto vtable = DMK::Memory::seh_read<uintptr_t>(*actor_model);
            if (!vtable || !DMK::Memory::plausible_userspace_ptr(*vtable))
            {
                return 0u;
            }
            static uintptr_t s_actor_model_vtable = 0;
            if (s_actor_model_vtable == 0)
            {
                if (!DMK::Rtti::vtable_is_type(*vtable, Constants::C_ACTOR_MODEL_RTTI_NAME))
                {
                    return 0u;
                }
                s_actor_model_vtable = *vtable;
            }
            else if (*vtable != s_actor_model_vtable)
            {
                return 0u;
            }
            const auto stance = DMK::Memory::seh_read<uint32_t>(*actor_model + Constants::C_ACTOR_MODEL_STANCE_OFFSET);
            return stance ? *stance : 0u;
        }

        /**
         * @brief Detects whether the player is aiming a ranged weapon (bow/crossbow), or false on any failure.
         * @details C_Player carries a player-side ranged-aim byte at OFFSET_AIMING_FLAG that reads 1 in every
         *          non-aiming state (holstered, weapon lowered, melee/combat stance) and 0 ONLY while aiming a
         *          ranged weapon. It is INVERTED, so aiming == (flag == 0); a failed read is
         *          treated as "not aiming" (fail closed). Player-side, so weapon-agnostic (crossbows, which
         *          share the C_Bow class, are covered) and reachable at a fixed offset with no weapon-handle chain.
         * @return state_bit(Aiming) while aiming a ranged weapon, else 0.
         */
        [[nodiscard]] uint32_t poll_aiming(uintptr_t c_player) noexcept
        {
            const auto flag = DMK::Memory::seh_read<uint8_t>(c_player + Constants::OFFSET_AIMING_FLAG);
            return (flag && *flag == 0) ? state_bit(GameState::Aiming) : 0;
        }

        /// Trims leading and trailing ASCII whitespace from a view (no allocation).
        [[nodiscard]] std::string_view trim_view(std::string_view text) noexcept
        {
            constexpr std::string_view whitespace = " \t\r\n";
            const size_t begin = text.find_first_not_of(whitespace);
            if (begin == std::string_view::npos)
            {
                return {};
            }
            const size_t end = text.find_last_not_of(whitespace);
            return text.substr(begin, end - begin + 1);
        }

        /// ASCII case-insensitive equality of a token against a lowercase literal.
        [[nodiscard]] bool token_equals(std::string_view token, std::string_view lower_literal) noexcept
        {
            if (token.size() != lower_literal.size())
            {
                return false;
            }
            for (size_t i = 0; i < token.size(); ++i)
            {
                if (static_cast<char>(std::tolower(static_cast<unsigned char>(token[i]))) != lower_literal[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// Maps a single trimmed token to its GameState bit, or 0 when unrecognized.
        [[nodiscard]] uint32_t token_to_bit(std::string_view token) noexcept
        {
            if (token_equals(token, "menu"))
            {
                return state_bit(GameState::Menu);
            }
            if (token_equals(token, "overlay"))
            {
                return state_bit(GameState::Overlay);
            }
            if (token_equals(token, "combat"))
            {
                return state_bit(GameState::Combat);
            }
            if (token_equals(token, "mount"))
            {
                return state_bit(GameState::Mount);
            }
            if (token_equals(token, "dialogue"))
            {
                return state_bit(GameState::Dialogue);
            }
            if (token_equals(token, "minigame"))
            {
                return state_bit(GameState::Minigame);
            }
            if (token_equals(token, "aiming"))
            {
                return state_bit(GameState::Aiming);
            }
            // Crouch and Stealth are aliases: KCD1 crouch IS the sneak/stealth stance.
            if (token_equals(token, "crouch") || token_equals(token, "stealth"))
            {
                return state_bit(GameState::Crouch);
            }
            // Remaining E_StanceCategory stances (see poll_stance): lying / sitting / kneel. (No Cart on KCD1.)
            if (token_equals(token, "lying"))
            {
                return state_bit(GameState::Lying);
            }
            if (token_equals(token, "sitting"))
            {
                return state_bit(GameState::Sitting);
            }
            if (token_equals(token, "kneel"))
            {
                return state_bit(GameState::Kneel);
            }
            // Per-minigame child tokens (dice, reading, ...). Each resolves to its child bit; the umbrella
            // "minigame" token above matches ANY minigame. poll_active_minigame sets both bits, so a child token
            // reacts only to that minigame while "minigame" reacts to all of them.
            for (const MinigameInfo &def : k_minigames)
            {
                if (token_equals(token, def.token))
                {
                    return state_bit(def.bit);
                }
            }
            return 0;
        }

    } // namespace

    uint32_t parse_state_mask(std::string_view csv)
    {
        DMK::Logger &logger = DMK::Logger::get_instance();
        uint32_t mask = 0;

        size_t start = 0;
        while (start <= csv.size())
        {
            const size_t comma = csv.find(',', start);
            const size_t end = (comma == std::string_view::npos) ? csv.size() : comma;
            const std::string_view token = trim_view(csv.substr(start, end - start));
            if (!token.empty())
            {
                const uint32_t bit = token_to_bit(token);
                if (bit != 0)
                {
                    mask |= bit;
                }
                else
                {
                    logger.warning("GameState: ignoring unknown state token '{}'", std::string(token));
                }
            }
            if (comma == std::string_view::npos)
            {
                break;
            }
            start = comma + 1;
        }
        return mask;
    }

    uint32_t poll_game_state(uintptr_t c_player) noexcept
    {
        uint32_t mask = 0;

        if (is_game_menu_open())
        {
            mask |= state_bit(GameState::Menu);
        }
        if (overlay_state().active.load(std::memory_order_relaxed))
        {
            mask |= state_bit(GameState::Overlay);
        }

        mask |= poll_active_camera_state();
        // Minigames (the umbrella Minigame bit plus the specific child) come from the C_PlayerModule map, not
        // the camera, so a first-person minigame such as reading is detected. It also works before the player
        // resolves (single-player: the only entry is the player's).
        mask |= poll_active_minigame(c_player);

        uint32_t stance = 0;
        if (c_player != 0)
        {
            // Every body-posture state comes from the player's current STANCE enum (wh::entitymodule::
            // E_StanceCategory at C_ActorModel+0x1C8, read once): standing=0, lying=1, sitting=2, kneel=3,
            // horse(mount)=4, crouch=5. Standing carries no bit (DEFAULT preset). The active camera stays
            // first-person for these, so the camera-state selector cannot see them; the stance can. 1-frame
            // transients during a stance switch are filtered by the GameState debounce.
            stance = poll_stance(c_player);
            switch (stance)
            {
            case Constants::C_ACTOR_MODEL_STANCE_LYING:
                mask |= state_bit(GameState::Lying);
                break;
            case Constants::C_ACTOR_MODEL_STANCE_SITTING:
                mask |= state_bit(GameState::Sitting);
                break;
            case Constants::C_ACTOR_MODEL_STANCE_KNEEL:
                mask |= state_bit(GameState::Kneel);
                break;
            case Constants::C_ACTOR_MODEL_STANCE_MOUNT:
                mask |= state_bit(GameState::Mount);
                break;
            case Constants::C_ACTOR_MODEL_STANCE_CROUCH:
                mask |= state_bit(GameState::Crouch);
                break;
            default:
                break; // standing / undefined: no stance bit
            }

            // Aiming a ranged weapon (bow/crossbow): a player-side flag on C_Player, weapon-agnostic and needing
            // no weapon-handle chain (the KCD2 embedded missile controller does not exist on KCD1).
            mask |= poll_aiming(c_player);
        }

        // TRACE the raw state plus the signals behind it whenever the mask OR the stance changes, so a state that
        // fails to engage can be traced to the underlying signal (active-camera type id, minigame-map _Mysize,
        // stance) instead of guessed. Trace level so it is off by default but available when diagnosing.
        static uint32_t s_dbg_last_mask = 0xFFFFFFFFu;
        static uint32_t s_dbg_last_stance = 0xFFFFFFFFu;
        if (mask != s_dbg_last_mask || stance != s_dbg_last_stance)
        {
            s_dbg_last_mask = mask;
            s_dbg_last_stance = stance;
            DMK::Logger::get_instance().trace(
                "GameState: raw=0x{:X} stance={} camType={} mgMapSize={} menu={} overlay={}", mask, stance,
                s_dbg_camera_type, s_dbg_minigame_size, is_game_menu_open() ? 1 : 0,
                overlay_state().active.load(std::memory_order_relaxed) ? 1 : 0);
        }

        return mask;
    }

    uint32_t debounce_game_state(uint32_t raw_mask, float delta_seconds, float hold_seconds) noexcept
    {
        static uint32_t s_stable_mask = 0;
        static std::array<float, k_game_state_bit_count> s_bit_timer{};

        if (hold_seconds <= 0.0f)
        {
            // Debounce disabled (hot-reloadable): pass through and clear the per-bit dwell so a later
            // re-enable does not flip a bit early off a stale, partially-accumulated timer.
            s_stable_mask = raw_mask;
            s_bit_timer.fill(0.0f);
            return raw_mask;
        }

        for (uint32_t i = 0; i < k_game_state_bit_count; ++i)
        {
            const uint32_t bit = 1u << i;
            const bool raw_on = (raw_mask & bit) != 0;
            const bool stable_on = (s_stable_mask & bit) != 0;
            if (raw_on == stable_on)
            {
                // Bit already matches the stable value: reset its dwell timer so a transient blip that
                // clears before the hold elapses never flips the stable mask.
                s_bit_timer[i] = 0.0f;
            }
            else
            {
                s_bit_timer[i] += delta_seconds;
                if (s_bit_timer[i] >= hold_seconds)
                {
                    s_stable_mask ^= bit;
                    s_bit_timer[i] = 0.0f;
                }
            }
        }
        return s_stable_mask;
    }

} // namespace TPVCamera
