/**
 * @file hooks/ui_menu_hooks.hpp
 * @brief Header for in-game menu hooks functionality.
 *
 * Provides functions to initialize and query the hook that intercepts the game's in-game menu
 * open/close toggle. KCD1 funnels both directions through one toggle (see ui_menu_hooks.cpp), so a
 * single hook replaces KCD2's separate MenuOpen / MenuClose pair.
 */
#ifndef TPVCAMERA_UI_MENU_HOOKS_HPP
#define TPVCAMERA_UI_MENU_HOOKS_HPP

#include <DetourModKit/error.hpp>
#include <DetourModKit/hook.hpp>

namespace TPVCamera
{

    /**
     * @brief Installs the in-game menu toggle hook from the pre-resolved MenuOpen anchor.
     * @return An empty Result once the hook is armed, or the typed Error (NoMatch for an unresolved anchor,
     *         otherwise the install / enable code).
     * @note Call after resolve_all_anchors(); the hook target is read via anchor_address(). The hook is pushed
     *       onto @p hooks, which shutdown() retires through the DetourGate.
     */
    [[nodiscard]] DMK::Result<void> initialize_ui_menu_hooks(DMK::hook::HookStack &hooks);

    /**
     * @brief Check if the in-game menu is currently open.
     * @return true if the menu is open, false otherwise.
     */
    [[nodiscard]] bool is_game_menu_open() noexcept;

} // namespace TPVCamera

#endif // TPVCAMERA_UI_MENU_HOOKS_HPP
