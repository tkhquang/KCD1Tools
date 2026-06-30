/**
 * @file game_interface.hpp
 * @brief Resolves the game's global-context pointer (the camera-manager root).
 *
 * The global-context -> camera-manager chain is the entry point the game-state
 * detection walks to read the active camera (see game_state.cpp). This unit
 * resolves and caches the context-pointer storage from the module image once.
 */
#ifndef TPVCAMERA_GAME_INTERFACE_HPP
#define TPVCAMERA_GAME_INTERFACE_HPP

namespace TPVCamera
{

    /**
     * @brief Stores the resolved global-context pointer for the game-state camera reads.
     * @details KCD1 reaches the global context through the .data slot resolved at runtime by the Context AOB
     *          cascade; a total cascade miss fails closed. The resolved storage slot is published to
     *          g_global_context_ptr_address for the game-state camera
     *          reads (game_state.cpp); without this call those reads find no state.
     * @return true if the module base is known and the context slot was published, false otherwise.
     * @note Call after the game module base/size is recorded in module_info().
     */
    [[nodiscard]] bool initialize_game_interface();

    /**
     * @brief Clean up game interface resources.
     */
    void cleanup_game_interface();

} // namespace TPVCamera

#endif // TPVCAMERA_GAME_INTERFACE_HPP
