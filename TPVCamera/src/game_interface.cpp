/**
 * @file game_interface.cpp
 * @brief Resolves the game's global-context pointer (the camera-manager root).
 *
 * KCD1 reaches the global context through a fixed .data slot in the module image
 * (qword_1834FFD10). The slot ADDRESS is resolved at runtime from a getter's RIP-relative
 * load via the Context AOB cascade (aob_resolver.hpp); a total cascade miss fails closed.
 * initialize_game_interface() publishes that slot once; the game-state detection (game_state.cpp)
 * walks context -> camera manager from there.
 */

#include "game_interface.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <cstddef>
#include <cstdint>

using DMK::format::format_address;

namespace TPVCamera
{

    DMK::Result<void> initialize_game_interface()
    {
        DMK::Logger &logger = DMK::log();
        logger.info("GameInterface: Initializing from the static global-context slot...");

        if (module_info().base == 0)
        {
            logger.error("GameInterface: module base not resolved before game-interface init");
            return std::unexpected(DMK::Error{DMK::ErrorCode::InvalidArg, "game_interface/module"});
        }

        // The global-context storage slot is a fixed .data location in the WHGame.dll image (the singleton
        // getters return *qword_1834FFD10). The Context anchor resolves the slot ADDRESS from a getter's
        // RIP-relative load (k_contextCandidates); resolution is runtime-only, so a total cascade miss fails
        // closed here. Publish the slot ADDRESS (not the pointer it holds, which is null until a level
        // loads); game_state.cpp dereferences it fresh each frame and validates the value.
        const std::uintptr_t ctx_slot = anchor_address(AnchorId::Context);
        if (ctx_slot == 0)
        {
            logger.error("GameInterface: Context cascade unresolved (global-context slot)");
            return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "game_interface/anchor"});
        }

        g_global_context_ptr_address.store(reinterpret_cast<std::byte *>(ctx_slot), std::memory_order_relaxed);
        logger.info("GameInterface: Global context pointer storage at {}", format_address(ctx_slot));
        return {};
    }

    void cleanup_game_interface()
    {
        g_global_context_ptr_address.store(nullptr, std::memory_order_relaxed);
    }

} // namespace TPVCamera
