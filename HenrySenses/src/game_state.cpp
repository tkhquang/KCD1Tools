/**
 * @file game_state.cpp
 * @brief Live game-state detection and the HideIn situation lists.
 */

#include "game_state.hpp"
#include "config.hpp"
#include "constants.hpp"
#include "global_state.hpp"
#include "offset_heal.hpp"

#include <DetourModKit.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>
#include <string>
#include <algorithm>

namespace HenrySenses
{
    namespace
    {
        /**
         * @brief Reads the global-context object, publishing it to the self-heal once the world is live.
         * @return The context object address, or 0.
         */
        [[nodiscard]] std::uintptr_t read_context() noexcept
        {
            std::byte *const slot = g_global_context_ptr_address.load(std::memory_order_relaxed);
            if (slot == nullptr)
            {
                return 0;
            }
            const auto context =
                DMK::memory::read<std::uintptr_t>(DMK::Address{reinterpret_cast<std::uintptr_t>(slot)});
            if (!context || !DMK::memory::is_plausible_ptr(DMK::Address{*context}))
            {
                return 0;
            }
            // Gating the heal on the world being live keeps a camera-manager offset drift recoverable without ever
            // scanning a half-built context at the main menu.
            if (game_world_ready().load(std::memory_order_relaxed))
            {
                note_context_base(*context);
            }
            return *context;
        }

        /**
         * @brief Classifies the active wh::game camera into the combat / dialogue bits.
         * @details KCD1 stores the active camera at manager + OFFSET_ACTIVE_CAMERA. Every camera carries a type id at
         *          camera + OFFSET_CAMERA_TYPE_ID, so the type id classifies it without an RTTI compare.
         *          [KCD2 matches the camera's vtable against the combat and dialogue camera classes.]
         * @param context Global-context object.
         * @return The matching bit, or 0.
         */
        [[nodiscard]] std::uint32_t poll_active_camera_state(std::uintptr_t context) noexcept
        {
            // One guarded walk: context -> camera manager (self-healed) -> active camera.
            const std::array<std::ptrdiff_t, 2> camera_chain{
                offset_value(runtime_offsets().context_manager),
                constants::OFFSET_ACTIVE_CAMERA
            };
            const auto camera_slot = DMK::memory::walk(DMK::Address{context}, camera_chain);
            if (!camera_slot)
            {
                return 0;
            }
            const auto camera = DMK::memory::read<std::uintptr_t>(*camera_slot);
            if (!camera || !DMK::memory::is_plausible_ptr(DMK::Address{*camera}))
            {
                return 0;
            }
            const auto type_id =
                DMK::memory::read<std::int32_t>(DMK::Address{*camera + constants::OFFSET_CAMERA_TYPE_ID});
            if (!type_id)
            {
                return 0;
            }
            if (*type_id == constants::CAMERA_TYPE_COMBAT)
            {
                return state_bit(GameState::Combat);
            }
            if (*type_id == constants::CAMERA_TYPE_DIALOG)
            {
                return state_bit(GameState::Dialogue);
            }
            return 0;
        }

        /**
         * @brief Detects a minigame through the C_PlayerModule's active-minigame map.
         * @details Only dice swaps the active camera, so lockpicking, reading and the other first-person minigames
         *          are detected from the module instead: context -> C_PlayerModule -> std::map<actorId, C_Minigame*>.
         *          A non-empty map means a minigame is on screen. Single player keeps one entry at most, the player's.
         *          [KCD2 walks the C_MinigameManager's circular list and checks each owner.]
         * @param context Global-context object.
         * @return state_bit(Minigame) when a minigame is active, else 0.
         */
        [[nodiscard]] std::uint32_t poll_active_minigame(std::uintptr_t context) noexcept
        {
            const std::array<std::ptrdiff_t, 2> map_chain{
                offset_value(runtime_offsets().context_minigame_subsystem),
                constants::OFFSET_MINIGAME_MAP
            };
            const auto map_slot = DMK::memory::walk(DMK::Address{context}, map_chain);
            if (!map_slot)
            {
                return 0;
            }
            const auto map = DMK::memory::read<std::uintptr_t>(*map_slot);
            if (!map || !DMK::memory::is_plausible_ptr(DMK::Address{*map}))
            {
                return 0;
            }
            const auto size =
                DMK::memory::read<std::uint64_t>(DMK::Address{*map + constants::OFFSET_MINIGAME_MAP_SIZE});
            return size && *size != 0 ? state_bit(GameState::Minigame) : 0;
        }
    } // namespace

    std::uint32_t poll_game_state() noexcept
    {
        DMK_PROFILE_FUNCTION();
        std::uint32_t mask = 0;

        if (const std::uintptr_t context = read_context(); context != 0)
        {
            mask |= poll_active_camera_state(context);
            mask |= poll_active_minigame(context);
        }
        return mask;
    }

    StateList parse_state_list(std::string_view list)
    {
        struct Token
        {
            std::string_view name;
            GameState state;
        };
        constexpr std::array<Token, 4> tokens{{
            {"dialogue", GameState::Dialogue},
            {"dialog", GameState::Dialogue},
            {"combat", GameState::Combat},
            {"minigame", GameState::Minigame},
        }};
        StateList parsed;
        std::size_t start = 0;
        while (start <= list.size())
        {
            const std::size_t comma = list.find(',', start);
            const std::size_t end = comma == std::string_view::npos ? list.size() : comma;
            std::string_view token = list.substr(start, end - start);
            while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
            {
                token.remove_prefix(1);
            }
            while (!token.empty() && (token.back() == ' ' || token.back() == '\t' || token.back() == '\r'))
            {
                token.remove_suffix(1);
            }
            if (!token.empty())
            {
                const auto known = std::find_if(
                    tokens.begin(),
                    tokens.end(),
                    [token](const Token &entry)
                    {
                        return entry.name.size() == token.size() &&
                               std::equal(
                                   token.begin(),
                                   token.end(),
                                   entry.name.begin(),
                                   [](char a, char b) { return ascii_lower(a) == b; }
                               );
                    }
                );
                if (known != tokens.end())
                {
                    parsed.mask |= state_bit(known->state);
                }
                else
                {
                    parsed.unknown += (parsed.unknown.empty() ? "" : ", ") + std::string(token);
                }
            }
            if (comma == std::string_view::npos)
            {
                break;
            }
            start = comma + 1;
        }
        return parsed;
    }

    std::string state_list_text(std::uint32_t mask)
    {
        constexpr std::array<std::pair<GameState, std::string_view>, 3> names{{
            {GameState::Dialogue, "Dialogue"},
            {GameState::Combat, "Combat"},
            {GameState::Minigame, "Minigame"},
        }};
        std::string text;
        for (const auto &[state, name] : names)
        {
            if ((mask & state_bit(state)) != 0)
            {
                text += (text.empty() ? "" : ", ") + std::string(name);
            }
        }
        return text.empty() ? std::string{"none"} : text;
    }

    std::uint32_t default_hide_mask() noexcept
    {
        return settings().hide_in.load(std::memory_order_relaxed);
    }

} // namespace HenrySenses
