/**
 * @file hooks/interaction_hook.cpp
 * @brief Camera-space interaction: redirect the player look-ray onto the render camera + crosshair (KCD1).
 *
 * @details KCD1's C_PlayerInteractor selects its "press to use" target each tick (vtable slot 5 sub_1803E5054
 *          -> the selection sub_1803E51EC). The selection builds its look ray AND evaluates candidates from the
 *          FRAMEWORK VIEW pose v10 (*(framework+56)+44), which the mod never offsets. In third person the
 *          eye-anchored view diverges from the screen-centre crosshair, so the use-target misses what the
 *          crosshair points at.
 *
 *          A ray-only redirect (rewriting just the ray-query builder sub_1803E5B1C) is UNSAFE on KCD1: the
 *          selection reads v10 downstream IN ADDITION to the ray it builds, so redirecting only the ray leaves a
 *          camera-ray + eye-view mismatch that crashes the candidate evaluation (KCD2 avoided this by rewriting
 *          an interactor-OWNED origin/dir field shared by the whole selection - KCD1 has no such field). So this
 *          instead wraps the WHOLE selection: it transiently overwrites the framework view pose v10 (position +
 *          orientation) with the render camera + crosshair, runs the original selection (its ray AND its
 *          projection are now both camera-consistent), then restores v10. The look direction is computed inside
 *          the selection from v10's orientation, so the quaternion is built with the engine's own
 *          Quat::SetRotationVDir convention (CryEngine Cry_Quat.h) to guarantee it matches.
 *
 *          Gated on cursor-hidden (the main menu renders a camera with a RESOLVED player, so c_player / aim-pose
 *          validity do NOT distinguish it - only the OS cursor does), InteractFromCamera, and a valid published
 *          aim pose. Every v10 access is a DetourModKit guarded read/write; v10 is restored on every path.
 *          Resolved at runtime via AOB cascades.
 */

#include "interaction_hook.hpp"
#include "aob_resolver.hpp"
#include "config.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <span>

namespace TPVCamera
{
    namespace
    {

        // sub_1803E51EC(interactor /*rcx*/, out /*rdx*/, flag /*r8*/, out2 /*r9*/, mode /*stack: 1 primary,
        // 2 secondary*/): the per-tick interactor target selection. We wrap it to make the whole selection use
        // the render camera + crosshair, then restore the engine view.
        using SelectionFunc = uintptr_t(__fastcall *)(uintptr_t interactor, uintptr_t out, uintptr_t flag,
                                                      uintptr_t out2, int mode);
        std::atomic<SelectionFunc> s_selection_original{nullptr};

        // diagnostics (game thread only; atomic for the trace line)
        std::atomic<unsigned long long> s_redirects{0};
        const char *s_last_reason = "none";
        std::chrono::steady_clock::time_point s_last_log{};

        /**
         * @brief Resolves the live game-framework base (== global context) at runtime. 0 if not live.
         * @details The interaction redirect needs the framework's view subsystem (framework +
         *          FRAMEWORK_VIEW_OFFSET). The framework is the value held in the global-context .data slot (the
         *          engine's framework getter does nothing but load that slot), so it is read from the slot the
         *          Context quorum resolves: *(ctx_slot) equals the getter's return. A failed Interaction gate
         *          returns 0, and resolve_view_pose then leaves the native selection in place.
         */
        uintptr_t resolve_framework() noexcept
        {
            const uintptr_t ctx_slot = gated_anchor_address(Feature::Interaction, AnchorId::Context);
            if (ctx_slot == 0)
            {
                return 0;
            }
            const auto framework = DMK::memory::read<uintptr_t>(DMK::Address{ctx_slot});
            return (framework && DMK::memory::is_plausible_ptr(DMK::Address{*framework})) ? *framework : 0;
        }

        /**
         * @brief Resolves the framework view pose v10 (Vec3 position floats 0..2, CryEngine Quat floats 3..6).
         * @return Address of the pose, or 0 if any link is unresolved. Uses DMK::memory::read (internally
         *         guarded) so this frame holds no SEH itself.
         */
        uintptr_t resolve_view_pose() noexcept
        {
            const uintptr_t framework = resolve_framework();
            if (framework == 0 || !DMK::memory::is_plausible_ptr(DMK::Address{framework}))
            {
                return 0;
            }
            const auto view = DMK::memory::read<uintptr_t>(DMK::Address{framework + Constants::FRAMEWORK_VIEW_OFFSET});
            if (!view || !DMK::memory::is_plausible_ptr(DMK::Address{*view}))
            {
                return 0;
            }
            const auto flag = DMK::memory::read<uint8_t>(DMK::Address{*view + Constants::VIEW_POSE_ALT_FLAG_OFFSET});
            if (!flag)
            {
                return 0;
            }
            const uintptr_t pose =
                *view + Constants::VIEW_POSE_OFFSET + (*flag != 0 ? Constants::VIEW_POSE_ALT_DELTA : 0);
            return DMK::memory::is_plausible_ptr(DMK::Address{pose}) ? pose : 0;
        }

        /**
         * @brief Builds the look quaternion for a forward direction, matching CryEngine Quat::SetRotationVDir
         *        (Cry_Quat.h) exactly, so the engine's forward derived from v10 equals the crosshair forward.
         * @param fx,fy,fz Unit forward direction (the crosshair).
         * @param out_q Filled with the quaternion in v10 memory order: v.x, v.y, v.z, w.
         */
        void quat_from_vdir(float fx, float fy, float fz, float out_q[4]) noexcept
        {
            const double k = 0.70710676908493042; // sqrt(1/2): the default up-vector half-rotation
            double w = k;
            double vx = static_cast<double>(fz) * k;
            double vy = 0.0;
            double vz = 0.0;
            const double l = std::sqrt(static_cast<double>(fx) * fx + static_cast<double>(fy) * fy);
            if (l > 0.00001)
            {
                const double hvx = fx / l;
                const double hvy = fy / l + 1.0;
                const double hvz = l + 1.0;
                const double r = std::sqrt(hvx * hvx + hvy * hvy);
                const double s = std::sqrt(hvz * hvz + static_cast<double>(fz) * fz);
                double hacos0 = 0.0;
                double hasin0 = -1.0;
                if (r > 0.00001)
                {
                    hacos0 = hvy / r; // yaw
                    hasin0 = -hvx / r;
                }
                const double hacos1 = hvz / s; // pitch
                const double hasin1 = static_cast<double>(fz) / s;
                w = hacos0 * hacos1;
                vx = hacos0 * hasin1;
                vy = hasin0 * hasin1;
                vz = hasin0 * hacos1;
            }
            out_q[0] = static_cast<float>(vx);
            out_q[1] = static_cast<float>(vy);
            out_q[2] = static_cast<float>(vz);
            out_q[3] = static_cast<float>(w);
        }

        /**
         * @brief Snapshots v10 (7 floats), then overwrites its position (0..2) with the camera origin SLID forward
         *        to the eye's projection along the crosshair, and its quaternion (3..6) with the crosshair
         *        orientation. false when the read or the write faults (v10 is then unchanged).
         * @details The render camera sits FollowDistance BEHIND the player, but the interactor's range cap is
         *          measured from the view position, so writing the raw camera origin culls every nearby usable as
         *          too far. saved[0..2] is the engine's current view position (the eye), so we slide the camera
         *          origin forward along the crosshair to the eye's projection onto that ray: the hit line is
         *          unchanged but the range now measures from ~eye. Mirrors the KCD2 redirect's origin slide.
         *
         *          Both halves are DetourModKit guarded accesses: read_into copies the snapshot under the fault
         *          guard, and write_in_place stores the 28-byte pose as one span without ever changing page
         *          protection, so this frame needs no SEH of its own. The pose is a heap member of the view
         *          object, so the store cannot straddle a writability seam.
         */
        [[nodiscard]] bool save_and_overwrite_pose(uintptr_t pose, const float cam[3], const float dir[3],
                                                   const float quat[4], std::array<float, 7> &saved) noexcept
        {
            if (!DMK::memory::read_into(DMK::Address{pose}, std::as_writable_bytes(std::span{saved})))
            {
                return false;
            }
            const float proj =
                (saved[0] - cam[0]) * dir[0] + (saved[1] - cam[1]) * dir[1] + (saved[2] - cam[2]) * dir[2];
            const float adv = proj > 0.0f ? proj : 0.0f; // never slide backward past the camera
            const std::array<float, 7> redirected{
                cam[0] + dir[0] * adv, cam[1] + dir[1] * adv, cam[2] + dir[2] * adv, quat[0], quat[1], quat[2], quat[3],
            };
            return DMK::memory::write_in_place(DMK::Address{pose}, redirected).has_value();
        }

        /** @brief Restores the snapshot taken by save_and_overwrite_pose (guarded; a fault leaves v10 as is). */
        void restore_pose(uintptr_t pose, const std::array<float, 7> &saved) noexcept
        {
            (void)DMK::memory::write_in_place(DMK::Address{pose}, saved);
        }

        /** @brief Rate-limited (2 s) trace line; only while InteractFromCamera is on (caller checks that). */
        void maybe_log_status(float px, float py, float pz, float dx, float dy, float dz) noexcept
        {
            const auto now = std::chrono::steady_clock::now();
            if (now - s_last_log < std::chrono::seconds(2))
            {
                return;
            }
            s_last_log = now;
            (void)DMK::log().try_log(
                DMK::LogLevel::Trace,
                "InteractionHook[run]: redirects={} lastReason={} | cam=({}, {}, {}) crosshair=({}, {}, {})",
                s_redirects.load(std::memory_order_relaxed), s_last_reason, px, py, pz, dx, dy, dz);
        }

        /**
         * @brief Selection detour: wrap sub_1803E51EC, overwriting v10 with the camera+crosshair pose for the
         *        duration of the call so the ray AND the candidate projection are both camera-consistent.
         */
        uintptr_t __fastcall selection_detour(uintptr_t interactor, uintptr_t out, uintptr_t flag, uintptr_t out2,
                                              int mode) noexcept
        {
            const DetourScope in_flight;
            const SelectionFunc original = s_selection_original.load(std::memory_order_acquire);
            if (original == nullptr)
            {
                return 0;
            }

            // Stay inert outside active gameplay. interaction_aim_pose().is_valid() is true ONLY while the TPV
            // offset is actually applied; every UI/menu state (main menu, in-game menu, inventory, map, dialogue)
            // raises an Overlay action filter that suppresses the offset (SuppressTPVState=Overlay), which
            // invalidates the pose - so this single check excludes all of them, no separate cursor gate needed.
            if (!settings().interact_from_camera.load(std::memory_order_relaxed) || !interaction_aim_pose().is_valid())
            {
                return original(interactor, out, flag, out2, mode);
            }

            float px, py, pz, dx, dy, dz;
            if (!interaction_aim_pose().load(px, py, pz, dx, dy, dz))
            {
                s_last_reason = "aim pose unreadable";
                return original(interactor, out, flag, out2, mode);
            }
            const float fl = std::sqrt(dx * dx + dy * dy + dz * dz);
            if (fl < 1e-4f)
            {
                s_last_reason = "degenerate crosshair dir";
                return original(interactor, out, flag, out2, mode);
            }
            dx /= fl;
            dy /= fl;
            dz /= fl;

            const uintptr_t pose = resolve_view_pose();
            if (pose == 0)
            {
                s_last_reason = "view pose unresolved";
                return original(interactor, out, flag, out2, mode);
            }

            float quat[4];
            quat_from_vdir(dx, dy, dz, quat);
            const float pos[3] = {px, py, pz};
            const float dir[3] = {dx, dy, dz};
            std::array<float, 7> saved{};
            if (!save_and_overwrite_pose(pose, pos, dir, quat, saved))
            {
                s_last_reason = "view overwrite faulted (unchanged)";
                return original(interactor, out, flag, out2, mode);
            }

            s_redirects.fetch_add(1, std::memory_order_relaxed);
            s_last_reason = "view redirected to camera+crosshair";
            maybe_log_status(px, py, pz, dx, dy, dz);

            // Run the full selection against the camera-consistent view, then ALWAYS restore the engine view.
            const uintptr_t result = original(interactor, out, flag, out2, mode);
            restore_pose(pose, saved);
            return result;
        }

    } // namespace

    DMK::Result<void> initialize_interaction_hook(HookSet &hooks)
    {
        // InteractorLookRay is a runtime AOB cascade (k_interactorLookRayCandidates), read through the Interaction
        // gate. The default hook::Options prologue policy is Fail (refuse a breakpoint first byte). A sibling mod's
        // E9 jump-hook does not trip it, so layering still works.
        const uintptr_t hook_addr = gated_anchor_address(Feature::Interaction, AnchorId::InteractorLookRay);
        if (hook_addr == 0)
        {
            DMK::log().error("InteractionHook: InteractorLookRay cascade unresolved (interaction selection)");
            return std::unexpected(DMK::Error{DMK::ErrorCode::NoMatch, "interaction_hook/anchor"});
        }

        DMK_TRY(installed, DMK::hook::inline_at(DMK::hook::InlineRequest{.name = "InteractionSelection",
                                                                         .target = DMK::Address{hook_addr}},
                                                &selection_detour));
        // Publish the trampoline and store the handle BEFORE enable() arms the patch, so the set owns a hook whose arm
        // fails with the patch live.
        s_selection_original.store(installed.original<SelectionFunc>(), std::memory_order_release);
        DMK_TRY_VOID(hooks.push(std::move(installed)).enable());

        DMK::log().info("InteractionHook: hooked interactor selection at {} (view-consistent camera-space "
                        "interaction enabled)",
                        DMK::format::format_address(hook_addr));
        return {};
    }

} // namespace TPVCamera
