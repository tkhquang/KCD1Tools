/**
 * @file hooks/ui_overlay_hooks.hpp
 * @brief Header for UI overlay hooks functionality.
 *
 * Provides a function to initialize hooks that drive overlay_state().active while a blocking apse/UI screen
 * is up. The camera reads overlay_state().active to suppress the third-person offset while an overlay
 * (inventory, codex, map) is up, so the view renders from the untouched engine frame under any UI.
 *
 * KCD1: the KCD2 HideOverlays/ShowOverlays AOBs get 0 matches on 1.9.7, so this drives the same
 * overlay_state().active from the CryEngine action-filter worker instead (apse screens raise "only_ui" /
 * "only_map" / "only_dialog"); see ui_overlay_hooks.cpp. The API and overlay_state() output match KCD2 so the
 * call sites are unchanged between the two builds, and the overlay covers the dialog screen as KCD2 does.
 */
#ifndef TPVCAMERA_UI_OVERLAY_HOOKS_HPP
#define TPVCAMERA_UI_OVERLAY_HOOKS_HPP

namespace TPVCamera
{

    /**
     * @brief Installs the overlay/apse hook that drives overlay_state().active.
     * @return true if the hook installed, false otherwise (overlay detection then disabled).
     * @note KCD1 hooks the action-filter worker at module_base + ACTION_FILTER_WORKER_STATIC_RVA.
     */
    [[nodiscard]] bool initialize_ui_overlay_hooks();

} // namespace TPVCamera

#endif // TPVCAMERA_UI_OVERLAY_HOOKS_HPP
