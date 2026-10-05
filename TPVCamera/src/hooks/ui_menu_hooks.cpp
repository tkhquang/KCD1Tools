/**
 * @file hooks/ui_menu_hooks.cpp
 * @brief KCD1 in-game menu open/close detection via the wh::guimodule menu toggle.
 *
 * KCD2 hooked two separate vtable functions (MenuOpen / MenuClose) whose entry AOBs get 0 matches on KCD1.
 * KCD1 instead funnels every in-game-menu open/close through ONE toggle, sub_1805B84CC(this, char display),
 * the "DisplayIngameMenu" convergence (found via the C_UIMenuEvents registry). This hooks it and latches
 * display into is_game_menu_open(). Resolved at runtime by the MenuOpen AOB cascade (mirrors the other hooks).
 * The API matches KCD2 so the call sites (game_state.cpp, tpv_camera.cpp) are unchanged between the builds.
 */

#include "ui_menu_hooks.hpp"
#include "aob_resolver.hpp"
#include "detour_gate.hpp"

#include <DetourModKit.hpp>

#include <atomic>

namespace TPVCamera
{

    // wh::guimodule in-game menu toggle: void(this, char display). display = 1 opens the menu, 0 closes it.
    using MenuToggleFunc = void(__fastcall *)(void *this_ptr, char display);

    static std::atomic<MenuToggleFunc> s_menu_toggle_original{nullptr};
    static std::atomic<bool> s_is_menu_open(false);

    /**
     * @brief Menu-toggle detour: latch the requested open/close state, then call the original exactly once.
     * @details No SEH frame and no C++ try: the detour only logs (no-throw) and stores a mod-owned atomic, so
     *          it performs no foreign-memory dereference and cannot throw. The original is invoked outside any
     *          guard so the engine function runs exactly once. The toggle itself no-ops on an unchanged state,
     *          but `display` is the requested state either way, so the latch always tracks the menu.
     */
    static void __fastcall menu_toggle_detour(void *this_ptr, char display) noexcept
    {
        const DetourGate::Pass pass;
        const bool open = display != 0;
        (void)DMK::log().log_noexcept(DMK::LogLevel::Debug,
                                      open ? "UIMenuHook: in-game menu opening" : "UIMenuHook: in-game menu closing");
        s_is_menu_open.store(open, std::memory_order_relaxed);

        if (const MenuToggleFunc original = s_menu_toggle_original.load(std::memory_order_acquire))
        {
            original(this_ptr, display);
        }
    }

    DMK::Result<void> initialize_ui_menu_hooks(DMK::hook::HookStack &hooks)
    {
        // MenuOpen is the menu open/close toggle runtime AOB cascade (k_menuToggleCandidates, plus its call-site
        // rung); a total cascade miss fails closed. The default hook::Options prologue policy is Fail: refuse
        // the install when the resolved entry leads with a breakpoint byte. A sibling mod's E9 jump hook decodes
        // as a relocatable branch rather than a refusal, so layering still works.
        const uintptr_t toggle_addr = anchor_address(AnchorId::MenuOpen);
        if (toggle_addr == 0)
        {
            DMK::log().error("UIMenuHook: MenuOpen cascade unresolved (menu toggle)");
            return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "ui_menu_hooks/anchor"});
        }

        // Every failure below propagates the library's own Error rather than a stringified exception, so the
        // caller keeps the typed ErrorCode. TargetAlreadyHookedByThisKit means drop our own handle, while
        // TargetAlreadyHookedByAnotherModule means a sibling mod owns the target.
        DMK_TRY(installed, DMK::hook::inline_at(
                               DMK::hook::InlineRequest{.name = "MenuToggle", .target = DMK::Address{toggle_addr}},
                               &menu_toggle_detour));
        DMK_TRY_VOID(DetourGate::arm(hooks, std::move(installed), s_menu_toggle_original));

        DMK::log().info("UIMenuHook: hooked in-game menu toggle at {} (menu detection enabled)",
                        DMK::format::format_address(toggle_addr));
        return {};
    }

    bool is_game_menu_open() noexcept
    {
        return s_is_menu_open.load(std::memory_order_relaxed);
    }

} // namespace TPVCamera
