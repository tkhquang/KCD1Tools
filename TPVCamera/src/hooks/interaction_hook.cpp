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
 *          an interactor-OWNED origin/dir field shared by the whole selection -- KCD1 has no such field). So this
 *          instead wraps the WHOLE selection: it transiently overwrites the framework view pose v10 (position +
 *          orientation) with the render camera + crosshair, runs the original selection (its ray AND its
 *          projection are now both camera-consistent), then restores v10. The look direction is computed inside
 *          the selection from v10's orientation, so the quaternion is built with the engine's own
 *          Quat::SetRotationVDir convention (CryEngine Cry_Quat.h) to guarantee it matches.
 *
 *          Gated on cursor-hidden (the main menu renders a camera with a RESOLVED player, so c_player / aim-pose
 *          validity do NOT distinguish it -- only the OS cursor does), InteractFromCamera, and a valid published
 *          aim pose. SEH-guarded throughout; v10 is restored on every path. Resolved via static RVAs.
 */

#include "interaction_hook.hpp"
#include "aob_resolver.hpp"
#include "config.hpp"
#include "constants.hpp"
#include "global_state.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <stdexcept>
#include <string>

namespace TPVCamera
{
    namespace
    {

        // sub_1803E51EC(interactor /*rcx*/, out /*rdx*/, flag /*r8*/, out2 /*r9*/, mode /*stack: 1 primary,
        // 2 secondary*/): the per-tick interactor target selection. We wrap it to make the whole selection use
        // the render camera + crosshair, then restore the engine view.
        using SelectionFunc = uintptr_t(__fastcall *)(uintptr_t interactor, uintptr_t out, uintptr_t flag,
                                                      uintptr_t out2, int mode);
        SelectionFunc s_selection_original = nullptr;

        // sub_180430AA4: returns the CCryAction/game framework singleton (lazily inits + caches). v10 (the
        // selection's look-ray view pose) is reached through it.
        using FrameworkGetterFunc = uintptr_t(__fastcall *)();
        FrameworkGetterFunc s_framework_getter = nullptr;

        // --- diagnostics (game thread only; atomic for the trace line) ---
        std::atomic<unsigned long long> s_redirects{0};
        const char *s_last_reason = "none";
        std::chrono::steady_clock::time_point s_last_log{};

        /** @brief SEH-guarded call to the framework getter (an engine call, not a guarded read). 0 on fault. */
        uintptr_t call_framework_getter() noexcept
        {
            if (s_framework_getter == nullptr)
            {
                return 0;
            }
            __try
            {
                return s_framework_getter();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
        }

        /**
         * @brief Resolves the framework view pose v10 (Vec3 position floats 0..2, CryEngine Quat floats 3..6).
         * @return Address of the pose, or 0 if any link is unresolved. Uses DMK::Memory::seh_read (internally
         *         guarded) so this frame holds no SEH itself.
         */
        uintptr_t resolve_view_pose() noexcept
        {
            const uintptr_t framework = call_framework_getter();
            if (framework == 0 || !DMK::Memory::plausible_userspace_ptr(framework))
            {
                return 0;
            }
            const auto view = DMK::Memory::seh_read<uintptr_t>(framework + Constants::FRAMEWORK_VIEW_OFFSET);
            if (!view || !DMK::Memory::plausible_userspace_ptr(*view))
            {
                return 0;
            }
            const auto flag = DMK::Memory::seh_read<uint8_t>(*view + Constants::VIEW_POSE_ALT_FLAG_OFFSET);
            if (!flag)
            {
                return 0;
            }
            const uintptr_t pose =
                *view + Constants::VIEW_POSE_OFFSET + (*flag != 0 ? Constants::VIEW_POSE_ALT_DELTA : 0);
            return DMK::Memory::plausible_userspace_ptr(pose) ? pose : 0;
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
                    hacos0 = hvy / r;  // yaw
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
         * @brief SEH-guarded: snapshot v10 (7 floats), then overwrite its position (0..2) with the camera origin
         *        SLID forward to the eye's projection along the crosshair, and its quaternion (3..6) with the
         *        crosshair orientation. false on fault.
         * @details The render camera sits FollowDistance BEHIND the player, but the interactor's range cap is
         *          measured from the view position, so writing the raw camera origin culls every nearby usable as
         *          too far. saved[0..2] is the engine's current view position (the eye), so we slide the camera
         *          origin forward along the crosshair to the eye's projection onto that ray: the hit line is
         *          unchanged but the range now measures from ~eye. Mirrors the KCD2 redirect's origin slide.
         */
        bool save_and_overwrite_pose(uintptr_t pose, const float cam[3], const float dir[3], const float quat[4],
                                     float saved[7]) noexcept
        {
            bool ok = false;
            __try
            {
                float *v = reinterpret_cast<float *>(pose);
                for (int i = 0; i < 7; ++i)
                {
                    saved[i] = v[i];
                }
                const float proj =
                    (saved[0] - cam[0]) * dir[0] + (saved[1] - cam[1]) * dir[1] + (saved[2] - cam[2]) * dir[2];
                const float adv = proj > 0.0f ? proj : 0.0f; // never slide backward past the camera
                v[0] = cam[0] + dir[0] * adv;
                v[1] = cam[1] + dir[1] * adv;
                v[2] = cam[2] + dir[2] * adv;
                v[3] = quat[0];
                v[4] = quat[1];
                v[5] = quat[2];
                v[6] = quat[3];
                ok = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                ok = false;
            }
            return ok;
        }

        /** @brief SEH-guarded: restore the snapshot taken by save_and_overwrite_pose. */
        void restore_pose(uintptr_t pose, const float saved[7]) noexcept
        {
            __try
            {
                float *v = reinterpret_cast<float *>(pose);
                for (int i = 0; i < 7; ++i)
                {
                    v[i] = saved[i];
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
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
            DMK::Logger::get_instance().trace(
                "InteractionHook[run]: redirects={} lastReason={} | cam=({}, {}, {}) crosshair=({}, {}, {})",
                s_redirects.load(std::memory_order_relaxed), s_last_reason, px, py, pz, dx, dy, dz);
        }

        /**
         * @brief Selection detour: wrap sub_1803E51EC, overwriting v10 with the camera+crosshair pose for the
         *        duration of the call so the ray AND the candidate projection are both camera-consistent.
         */
        uintptr_t __fastcall selection_detour(uintptr_t interactor, uintptr_t out, uintptr_t flag, uintptr_t out2,
                                              int mode)
        {
            // Stay inert outside active gameplay. interaction_aim_pose().is_valid() is true ONLY while the TPV
            // offset is actually applied; every UI/menu state (main menu, in-game menu, inventory, map, dialogue)
            // raises an Overlay action filter that suppresses the offset (SuppressTPVState=Overlay), which
            // invalidates the pose -- so this single check excludes all of them, no separate cursor gate needed.
            if (!settings().interact_from_camera.load(std::memory_order_relaxed) ||
                !interaction_aim_pose().is_valid())
            {
                return s_selection_original(interactor, out, flag, out2, mode);
            }

            float px, py, pz, dx, dy, dz;
            if (!interaction_aim_pose().load(px, py, pz, dx, dy, dz))
            {
                s_last_reason = "aim pose unreadable";
                return s_selection_original(interactor, out, flag, out2, mode);
            }
            const float fl = std::sqrt(dx * dx + dy * dy + dz * dz);
            if (fl < 1e-4f)
            {
                s_last_reason = "degenerate crosshair dir";
                return s_selection_original(interactor, out, flag, out2, mode);
            }
            dx /= fl;
            dy /= fl;
            dz /= fl;

            const uintptr_t pose = resolve_view_pose();
            if (pose == 0)
            {
                s_last_reason = "view pose unresolved";
                return s_selection_original(interactor, out, flag, out2, mode);
            }

            float quat[4];
            quat_from_vdir(dx, dy, dz, quat);
            const float pos[3] = {px, py, pz};
            const float dir[3] = {dx, dy, dz};
            float saved[7];
            if (!save_and_overwrite_pose(pose, pos, dir, quat, saved))
            {
                s_last_reason = "view overwrite faulted (unchanged)";
                return s_selection_original(interactor, out, flag, out2, mode);
            }

            s_redirects.fetch_add(1, std::memory_order_relaxed);
            s_last_reason = "view redirected to camera+crosshair";
            maybe_log_status(px, py, pz, dx, dy, dz);

            // Run the full selection against the camera-consistent view, then ALWAYS restore the engine view.
            const uintptr_t result = s_selection_original(interactor, out, flag, out2, mode);
            restore_pose(pose, saved);
            return result;
        }

    } // namespace

    bool initialize_interaction_hook()
    {
        DMK::Logger &logger = DMK::Logger::get_instance();

        // Fail closed if the resolved entry leads with a call/breakpoint byte; a sibling mod's E9 jump-hook does
        // not trip this gate, so layering still works.
        const DMK::HookConfig hook_config{.prologue_policy = DMK::InlineProloguePolicy::Fail};

        try
        {
            const uintptr_t module_base = module_info().base;
            if (module_base == 0)
            {
                throw std::runtime_error("module base unknown");
            }

            s_framework_getter =
                reinterpret_cast<FrameworkGetterFunc>(module_base + Constants::FRAMEWORK_GETTER_STATIC_RVA);

            // InteractorLookRay carries an AOB cascade (k_interactorLookRayCandidates); the static RVA is the
            // fail-closed fallback for a total cascade miss.
            uintptr_t hook_addr = anchor_address(AnchorId::InteractorLookRay);
            if (hook_addr == 0)
            {
                hook_addr = module_base + Constants::INTERACTOR_LOOKRAY_STATIC_RVA; // sub_1803E51EC
            }

            auto result = DMK::HookManager::get_instance().create_inline_hook(
                "InteractionSelection", hook_addr, reinterpret_cast<void *>(selection_detour),
                reinterpret_cast<void **>(&s_selection_original), hook_config);
            if (!result.has_value())
            {
                throw std::runtime_error("Failed to create interaction selection hook: " +
                                         std::string(DMK::Hook::error_to_string(result.error())));
            }

            logger.info("InteractionHook: hooked interactor selection at {} (view-consistent camera-space "
                        "interaction enabled)",
                        DMK::Format::format_address(hook_addr));
            return true;
        }
        catch (const std::exception &e)
        {
            logger.error("InteractionHook: Initialization failed: {}", e.what());
            return false;
        }
    }

} // namespace TPVCamera
