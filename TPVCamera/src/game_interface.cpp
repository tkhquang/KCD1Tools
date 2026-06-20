/**
 * @file game_interface.cpp
 * @brief Resolves the game's global-context pointer (the camera-manager root).
 *
 * KCD1 reaches the global context through a fixed .data slot in the module image
 * (qword_1834FFD10). The slot ADDRESS is resolved patch-resiliently from a getter's RIP-relative
 * load via the Context AOB cascade (aob_resolver.hpp), with module_base +
 * GLOBAL_CONTEXT_STATIC_OFFSET as the fail-closed fallback. initialize_game_interface() publishes
 * that slot once; the game-state detection (game_state.cpp) walks context -> camera manager from there.
 */

#include "game_interface.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <stdexcept>

using DMK::Format::format_address;

namespace TPVCamera
{

    bool initialize_game_interface()
    {
        DMK::Logger &logger = DMK::Logger::get_instance();

        try
        {
            logger.info("GameInterface: Initializing from the static global-context slot...");

            const std::uintptr_t module_base = module_info().base;
            if (module_base == 0)
            {
                throw std::runtime_error("Module base not resolved before game-interface init");
            }

            // The global-context storage slot is a fixed .data location in the WHGame.dll image (the singleton
            // getters return *qword_1834FFD10). The Context anchor resolves the slot ADDRESS from a getter's
            // RIP-relative load (k_contextCandidates); the static RVA is the fail-closed fallback for a total
            // cascade miss. Publish the slot ADDRESS (not the pointer it holds, which is null until a level
            // loads); game_state.cpp dereferences it fresh each frame and validates the value.
            std::uintptr_t ctx_slot = anchor_address(AnchorId::Context);
            if (ctx_slot == 0)
            {
                ctx_slot = module_base + Constants::GLOBAL_CONTEXT_STATIC_OFFSET;
            }

            g_global_context_ptr_address.store(reinterpret_cast<std::byte *>(ctx_slot), std::memory_order_relaxed);

            logger.info("GameInterface: Global context pointer storage at {}", format_address(ctx_slot));

            return true;
        }
        catch (const std::exception &e)
        {
            logger.error("GameInterface: Initialization failed: {}", e.what());
            return false;
        }
    }

    void cleanup_game_interface()
    {
        g_global_context_ptr_address.store(nullptr, std::memory_order_relaxed);
    }

} // namespace TPVCamera
