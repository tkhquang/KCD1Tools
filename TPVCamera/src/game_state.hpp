/**
 * @file game_state.hpp
 * @brief Derives the current game state (combat, dialogue, minigame, mount, menu, overlay) from
 *        authoritative engine signals, for the INI-driven camera policy.
 *
 * Every signal is read from a discrete selector UPSTREAM of the camera pose smoother, so a state
 * edge is exact and does not lag like a smoothed value would. Combat and dialogue are read from the
 * active wh::game camera class (via the camera manager's active-camera type id); the minigame umbrella
 * and its child from the C_PlayerModule active-minigame map; mount and crouch from the player's stance.
 *
 * KCD1 differences vs KCD2: there is no Cart stance (it does not exist on KCD1), so that token is absent.
 * Aiming is read from a player-side flag (no embedded missile controller on KCD1, see constants.hpp). All 11
 * KCD1 minigames are C_Minigame and detected via RTTI (dice, reading, alchemy, herb gathering, pickpocketing,
 * lockpicking, hole digging, backgammon, book transcription, building, sharpening). The detection path is the
 * same C_Minigame map KCD2 uses; only the roster differs (KCD1 has, for example, backgammon and building, where
 * KCD2 has others such as blacksmithing and archery).
 */
#ifndef TPVCAMERA_GAME_STATE_HPP
#define TPVCAMERA_GAME_STATE_HPP

#include "constants.hpp"

#include <array>
#include <cstdint>
#include <string_view>

namespace TPVCamera
{

    /**
     * @enum GameState
     * @brief Bit flags for the game states the camera policy can react to.
     * @details Used as a uint32_t bit set (one set bit per active state). Minigames contribute an umbrella
     *          @ref Minigame bit (any minigame on screen) PLUS one mutually-exclusive child bit that
     *          identifies which minigame (see the Minigame* values and parse_state_mask).
     */
    enum class GameState : uint32_t
    {
        /// In-game pause menu open.
        Menu = 1u << 0,
        /// A blocking UI overlay is up (inventory, map, dialog screen, codex).
        Overlay = 1u << 1,
        /// Combat camera active (weapon drawn).
        Combat = 1u << 2,
        /// Player mounted on horseback (E_StanceCategory horse = 4).
        Mount = 1u << 3,
        /// Dialogue camera active.
        Dialogue = 1u << 4,
        /// Any minigame on screen (umbrella; a Minigame* child below identifies which).
        Minigame = 1u << 5,
        /// Player crouching / sneaking (E_StanceCategory crouch = 5).
        Crouch = 1u << 6,
        // Remaining E_StanceCategory values (the stance enum at C_ActorModel+0x1C8).
        // These are MUTUALLY EXCLUSIVE with Mount/Crouch and with each other (one stance field): standing(0)
        // carries no bit (DEFAULT preset handles standing).
        /// Lying down (E_StanceCategory lying = 1): sleeping in bed.
        Lying = 1u << 7,
        /// Sitting (E_StanceCategory sitting = 2): bench / chair.
        Sitting = 1u << 8,
        /// Kneeling (E_StanceCategory kneel = 3).
        Kneel = 1u << 9,
        // Per-minigame children. Each is set together with the umbrella @ref Minigame bit while that minigame
        // is on screen; the player is in at most one at a time. Read from the C_PlayerModule active-minigame
        // map (NOT the camera), so first-person minigames like reading are detected too (see
        // poll_active_minigame). The full C_Minigame subclass set is covered, including lockpicking and
        // hole-digging, which are C_Minigame and resolve a child bit like the rest.
        /// Dice (the one minigame that uses the dedicated minigame camera).
        MinigameDice = 1u << 10,
        /// Reading a book or scroll.
        MinigameReading = 1u << 11,
        /// Brewing at an alchemy bench.
        MinigameAlchemy = 1u << 12,
        /// Picking a herb.
        MinigameHerbGathering = 1u << 13,
        /// Pickpocketing an NPC.
        MinigamePickpocketing = 1u << 14,
        /// Picking a lock.
        MinigameLockpicking = 1u << 15,
        /// Digging at a dig spot (treasure / grave).
        MinigameHoleDigging = 1u << 16,
        /// Playing backgammon.
        MinigameBackgammon = 1u << 17,
        /// Transcribing / scribing in a book.
        MinigameBookTranscription = 1u << 18,
        /// Building (camp / construction).
        MinigameBuilding = 1u << 19,
        /// Sharpening a weapon at a grindstone.
        MinigameSharpening = 1u << 20,
        /// Aiming a ranged weapon (bow/crossbow). Player-side flag (C_Player+0x298), so weapon-agnostic.
        Aiming = 1u << 21,
    };

    /// Number of defined GameState bits; sizes the debounce timer array.
    inline constexpr uint32_t k_game_state_bit_count = 22;

    /// Returns the raw bit value of a GameState flag.
    [[nodiscard]] constexpr uint32_t state_bit(GameState state) noexcept
    {
        return static_cast<uint32_t>(state);
    }

    /**
     * @struct MinigameInfo
     * @brief One row of the minigame registry: the concrete RTTI name used to identify it live, its child
     *        GameState bit, the lowercase INI / bind_state token, and the overlay display label.
     * @details Single source of truth shared by the live detector (poll_active_minigame), the INI and
     *          bind-token parsers (parse_state_mask, parse_bind_mask, bind_mask_to_tokens) and the overlay
     *          bind editor, so the minigame vocabulary cannot drift between them.
     */
    struct MinigameInfo
    {
        /// wh::playermodule::C_* RTTI type-descriptor name (see constants.hpp).
        const char *rtti_name;
        /// Child bit set alongside the umbrella @ref GameState::Minigame.
        GameState bit;
        /// Lowercase INI / bind_state token.
        std::string_view token;
        /// Human-readable label for the overlay bind editor.
        const char *label;
    };

    /// Every KCD1 minigame, ordered by how commonly a user is likely to want it (the overlay lists it in order).
    inline constexpr std::array<MinigameInfo, 11> k_minigames{{
        {Constants::C_MINIGAME_DICE_RTTI_NAME, GameState::MinigameDice, "dice", "Dice"},
        {Constants::C_MINIGAME_READING_RTTI_NAME, GameState::MinigameReading, "reading", "Reading"},
        {Constants::C_MINIGAME_ALCHEMY_RTTI_NAME, GameState::MinigameAlchemy, "alchemy", "Alchemy"},
        {Constants::C_MINIGAME_HERB_GATHERING_RTTI_NAME, GameState::MinigameHerbGathering, "herbgathering",
         "Herb gathering"},
        {Constants::C_MINIGAME_PICKPOCKETING_RTTI_NAME, GameState::MinigamePickpocketing, "pickpocketing",
         "Pickpocketing"},
        {Constants::C_MINIGAME_LOCKPICKING_RTTI_NAME, GameState::MinigameLockpicking, "lockpicking", "Lockpicking"},
        {Constants::C_MINIGAME_HOLE_DIGGING_RTTI_NAME, GameState::MinigameHoleDigging, "holedigging",
         "Hole digging"},
        {Constants::C_MINIGAME_BACKGAMMON_RTTI_NAME, GameState::MinigameBackgammon, "backgammon", "Backgammon"},
        {Constants::C_MINIGAME_BOOK_TRANSCRIPTION_RTTI_NAME, GameState::MinigameBookTranscription,
         "booktranscription", "Book transcription"},
        {Constants::C_MINIGAME_BUILDING_RTTI_NAME, GameState::MinigameBuilding, "building", "Building"},
        {Constants::C_MINIGAME_SHARPENING_RTTI_NAME, GameState::MinigameSharpening, "sharpening", "Sharpening"},
    }};

    /**
     * @brief Parses a comma-separated state-token list into a GameState bit mask.
     * @details Tokens are case-insensitive and surrounding whitespace is ignored. Recognized tokens:
     *          Menu, Overlay, Combat, Mount, Dialogue, Aiming, Crouch (alias Stealth), Lying, Sitting, Kneel;
     *          Minigame (matches ANY minigame); and the per-minigame tokens Dice, Reading, Alchemy,
     *          HerbGathering, Pickpocketing, Lockpicking, HoleDigging, Backgammon, BookTranscription, Building,
     *          Sharpening. An empty list yields 0; an unrecognized token is logged at WARNING level and skipped.
     *          (KCD1 does not recognize Cart; its minigame roster also differs from KCD2's.)
     * @param csv Comma-separated token list (e.g. "Combat,Dialogue,Minigame").
     * @return The OR of the recognized tokens' bits.
     */
    [[nodiscard]] uint32_t parse_state_mask(std::string_view csv);

    /**
     * @brief Reads the current game-state bit mask from the live engine signals.
     * @details Menu and overlay come from the UI signals; combat and dialogue from the active wh::game
     *          camera class (resolved via the global-context to camera-manager chain and classified by its
     *          type id, cached so the steady state is a single pointer compare); the minigame umbrella and
     *          its per-minigame child from the C_PlayerModule active-minigame map (so first-person minigames
     *          such as reading are detected, not just the dice camera); mount and crouch from the player's
     *          C_ActorModel STANCE enum (mounted = 4, crouch = 5). Every engine read is SEH-guarded, so a
     *          failed read omits that bit rather than faulting. Intended to be called once per frame from the
     *          camera detour (the render thread); the camera classification cache is a plain static and is
     *          therefore not safe to call concurrently.
     * @param c_player Live C_Player address used for the stance/minigame-owner reads, or 0 to skip them.
     * @return The raw (un-debounced) GameState bit mask.
     */
    [[nodiscard]] uint32_t poll_game_state(uintptr_t c_player) noexcept;

    /**
     * @brief Applies per-bit hysteresis to a raw state mask so brief flicker does not pop the camera.
     * @details A bit must differ from the stable value for at least @p hold_seconds before it flips,
     *          so a momentary combat or dialogue transition cannot toggle a forced view on and off.
     *          Holds file-scope state and so must be called from a single thread (the render thread).
     * @param raw_mask Raw mask from poll_game_state().
     * @param delta_seconds Seconds elapsed since the previous call.
     * @param hold_seconds Dwell time a bit must hold its new value before it flips; <= 0 disables it.
     * @return The debounced (stable) mask.
     */
    [[nodiscard]] uint32_t debounce_game_state(uint32_t raw_mask, float delta_seconds, float hold_seconds) noexcept;

} // namespace TPVCamera

#endif // TPVCAMERA_GAME_STATE_HPP
