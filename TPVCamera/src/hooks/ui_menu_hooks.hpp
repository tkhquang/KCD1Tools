/**
 * @file hooks/ui_menu_hooks.hpp
 * @brief Header for in-game menu hooks functionality.
 *
 * Provides functions to initialize and manage hooks that directly intercept
 * the game's UI menu open and close functions.
 *
 * KCD1: the KCD2 menu-open/close AOBs get 0 matches on 1.9.7 and the coverage is redundant with the
 * hardware-mouse cursor gate, so this unit is a compile-safe STUB: the installer no-ops and the query
 * always reports "menu closed" (menu/UI suppression comes from the cursor gate in camera_hook instead).
 */
#ifndef TPVCAMERA_UI_MENU_HOOKS_HPP
#define TPVCAMERA_UI_MENU_HOOKS_HPP

namespace TPVCamera
{

    /**
     * @brief Installs the UI menu open/close hooks from the pre-resolved anchors.
     * @return true if both hooks installed, false otherwise. KCD1: always false (stubbed).
     * @note Call after resolve_all_anchors(); the hook targets are read via anchor_address().
     */
    [[nodiscard]] bool initialize_ui_menu_hooks();

    /**
     * @brief Check if the in-game menu is currently open.
     * @return true if the menu is open, false otherwise. KCD1: always false (stubbed).
     */
    [[nodiscard]] bool is_game_menu_open() noexcept;

} // namespace TPVCamera

#endif // TPVCAMERA_UI_MENU_HOOKS_HPP
