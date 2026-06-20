/**
 * @file physics_raycast.cpp
 * @brief Implementation of the IPhysicalWorld::RayWorldIntersection wrapper.
 */

#include "physics_raycast.hpp"
#include "constants.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <cmath>
#include <cstring>

namespace TPVCamera
{

    // IPhysicalWorld::RayWorldIntersection. KCD1 vtable slot 35 (RWI_VTABLE_OFFSET) is the SRWIParams form
    // (see constants.hpp). Signature (decompiled sub_18041B7F0):
    //   int __fastcall(world /*rcx*/, SRWIParams* pp /*rdx*/, void* pLockContacts /*r8, may be null*/,
    //                  int iCaller /*r9d*/)
    // NOTE iCaller is the FOURTH arg (r9), with a third pLockContacts arg (r8) between it and the params.
    // The params block (org/dir EMBEDDED Vec3, objtypes/flags, hits ptr, nMaxHits) is built per ray; the
    // function pointer is resolved fresh from the live world vtable, not cached.
    using RayWorldIntersectionFn = int(__fastcall *)(void *physical_world, void *spwi_params, void *lock_contacts,
                                                     int i_caller);

    // Address of the IPhysicalWorld* global (read fresh per ray, not cached: it is null until a
    // level loads and is replaced across level transitions). Derived from the g_env base.
    static uintptr_t s_physical_world_global_addr = 0;

    // Mapped range of the scanned game module (WHGame.dll), captured once at init. A freshly read world vtable /
    // RWI function pointer is confirmed to live inside the game image with a branch-only contains() test (no
    // syscall): a stale or reallocated world pointer yields a vtable slot that does not point into the image, and
    // calling through it must be rejected before the indirect call.
    static DMK::Memory::ModuleRange s_game_module{};

    bool initialize_physics_raycast(uintptr_t module_base, size_t module_size, uintptr_t g_env)
    {
        DMK::Logger &logger = DMK::Logger::get_instance();

        if (g_env == 0)
        {
            logger.warning("PhysicsRaycast: g_env not resolved; collision/aim raycast unavailable");
            return false;
        }

        // p_physical_world is a member of the g_env struct (see PHYSICAL_WORLD_OFFSET); deriving its
        // slot from the patch-resiliently resolved g_env base avoids a second hardcoded address.
        s_physical_world_global_addr = g_env + Constants::PHYSICAL_WORLD_OFFSET;
        s_game_module = {module_base, module_base + module_size};

        logger.info("PhysicsRaycast: RayWorldIntersection via world vtable slot {}, p_physical_world slot at {}",
                    DMK::Format::format_address(static_cast<uintptr_t>(Constants::RWI_VTABLE_OFFSET)),
                    DMK::Format::format_address(s_physical_world_global_addr));
        return true;
    }

    /**
     * @brief SEH-isolated engine call. Held apart from the C++ caller so the structured
     *        handler shares no frame with object unwinding; a fault becomes "no hit".
     */
    static int ray_world_intersection_guarded(RayWorldIntersectionFn fn, void *physical_world, void *spwi_params)
    {
        __try
        {
            // iCaller is the 4th arg (r9); the 3rd (r8 = pLockContacts) is null for the default lock path.
            return fn(physical_world, spwi_params, nullptr, Constants::RWI_EXTERNAL_CALLER);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0;
        }
    }

    std::optional<RayHit> ray_world_intersection(const Vector3 &origin, const Vector3 &direction, int objtypes,
                                                 unsigned int flags, const uintptr_t *skip_ents, int n_skip_ents)
    {
        if (s_physical_world_global_addr == 0)
        {
            return std::nullopt;
        }

        // Resolve the physical world fresh; bail cleanly while it is null (no level / loading).
        const auto world_value = DMK::Memory::seh_read<uintptr_t>(s_physical_world_global_addr);
        if (!world_value || *world_value == 0 || !DMK::Memory::plausible_userspace_ptr(*world_value))
        {
            return std::nullopt;
        }
        const uintptr_t world = *world_value;

        // RayWorldIntersection is resolved from the LIVE world vtable (slot RWI_VTABLE_OFFSET), not a static
        // address: KCD1 has no AOB-resolvable inline helper, and the vtable slot is the patch-stable anchor. Each
        // step is screened (in-image, plausible pointer) so a stale world cannot reach the indirect call.
        const auto vtable = DMK::Memory::seh_read<uintptr_t>(world);
        if (!vtable || !DMK::Memory::plausible_userspace_ptr(*vtable) || !DMK::Memory::contains(s_game_module, *vtable))
        {
            return std::nullopt;
        }
        const auto fn_slot = DMK::Memory::seh_read<uintptr_t>(*vtable + Constants::RWI_VTABLE_OFFSET);
        if (!fn_slot || !DMK::Memory::plausible_userspace_ptr(*fn_slot) ||
            !DMK::Memory::contains(s_game_module, *fn_slot))
        {
            return std::nullopt;
        }
        const auto fn = reinterpret_cast<RayWorldIntersectionFn>(*fn_slot);

        alignas(16) std::byte hit_buffer[Constants::RAY_HIT_SIZE];
        std::memset(hit_buffer, 0, sizeof(hit_buffer));

        // Build the SRWIParams block (KCD1 vtable-slot-35 ABI). org/dir are EMBEDDED Vec3 values; hits points at
        // the local ray_hit buffer; nMaxHits = 1. skip_ents is intentionally unused: the camera ray filters by
        // objtypes (ent_static | ent_terrain), so the player capsule (ent_living) and worn rigids are already
        // excluded, and the SRWIParams skip-ents fields were not reversed for this fork.
        (void)skip_ents;
        (void)n_skip_ents;
        alignas(16) std::byte params[Constants::SRWI_PARAMS_SIZE];
        std::memset(params, 0, sizeof(params));
        *reinterpret_cast<Vector3 *>(params + Constants::SRWI_ORG_OFFSET) = origin;
        *reinterpret_cast<Vector3 *>(params + Constants::SRWI_DIR_OFFSET) = direction;
        *reinterpret_cast<int *>(params + Constants::SRWI_OBJTYPES_OFFSET) = objtypes;
        *reinterpret_cast<unsigned int *>(params + Constants::SRWI_FLAGS_OFFSET) = flags;
        *reinterpret_cast<void **>(params + Constants::SRWI_HITS_OFFSET) = hit_buffer;
        *reinterpret_cast<int *>(params + Constants::SRWI_NMAXHITS_OFFSET) = 1;

        const int hit_count = ray_world_intersection_guarded(fn, reinterpret_cast<void *>(world), params);
        if (hit_count < 1)
        {
            return std::nullopt;
        }

        RayHit hit{};
        hit.m_distance = *reinterpret_cast<const float *>(hit_buffer + Constants::RAY_HIT_OFFSET_DISTANCE);
        hit.m_point = *reinterpret_cast<const Vector3 *>(hit_buffer + Constants::RAY_HIT_OFFSET_POINT);
        hit.m_normal = *reinterpret_cast<const Vector3 *>(hit_buffer + Constants::RAY_HIT_OFFSET_NORMAL);
        hit.m_collider = *reinterpret_cast<const uintptr_t *>(hit_buffer + Constants::RAY_HIT_OFFSET_COLLIDER);
        hit.m_terrain = *reinterpret_cast<const int *>(hit_buffer + Constants::RAY_HIT_OFFSET_TERRAIN);

        // Reject the engine's "no hit" sentinel (a very large dist) and bad values.
        if (!std::isfinite(hit.m_distance) || hit.m_distance < 0.0f || hit.m_distance >= 1.0e9f)
        {
            return std::nullopt;
        }
        return hit;
    }

    std::optional<RayHit> ray_fan_sweep(const Vector3 &origin, const Vector3 &sweep, float radius, int objtypes,
                                        unsigned int flags, const uintptr_t *skip_ents, int n_skip_ents)
    {
        const float len = sweep.magnitude();
        if (len < 1e-4f)
        {
            return std::nullopt;
        }
        const Vector3 dir = sweep / len;

        // Two axes perpendicular to the sweep. Pick a seed not parallel to dir, then Gram-Schmidt.
        const Vector3 seed = (std::fabs(dir.z) < 0.9f) ? Vector3{0.0f, 0.0f, 1.0f} : Vector3{1.0f, 0.0f, 0.0f};
        Vector3 right = dir.cross(seed);
        const float rlen = right.magnitude();
        if (rlen < 1e-4f)
        {
            // Degenerate: fall back to the single centre ray.
            return ray_world_intersection(origin, sweep, objtypes, flags, skip_ents, n_skip_ents);
        }
        right = right / rlen;
        const Vector3 up = right.cross(dir); // already unit (right and dir are orthonormal)

        // Centre + four parallel rays offset by the radius => a square tube approximating the swept sphere.
        const Vector3 offsets[5] = {Vector3{0.0f, 0.0f, 0.0f}, right * radius, right * (-radius), up * radius,
                                    up * (-radius)};

        std::optional<RayHit> best;
        for (const Vector3 &off : offsets)
        {
            const auto h = ray_world_intersection(origin + off, sweep, objtypes, flags, skip_ents, n_skip_ents);
            if (h.has_value() && (!best.has_value() || h->m_distance < best->m_distance))
            {
                best = h;
            }
        }
        return best;
    }

    // IPhysicalWorld::PrimitiveWorldIntersection (KCD1 vtable slot 57). The float return is the distance to the
    // first contact for a sweep (> 0 == hit); resolved fresh from the live world vtable, not cached.
    using PrimitiveWorldIntersectionFn = float(__fastcall *)(void *physical_world, void *pp, void *p_lock_contacts,
                                                             const char *name_tag);

    /**
     * @brief SEH-isolated PWI engine call, held apart from the C++ caller so a fault becomes "no hit".
     */
    static float primitive_world_intersection_guarded(PrimitiveWorldIntersectionFn fn, void *world, void *pp)
    {
        __try
        {
            return fn(world, pp, nullptr, "TPVCameraSweep");
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return 0.0f;
        }
    }

    /**
     * @brief Releases the SPWIParams WriteLockCond (InterlockedAdd(prw, -iActive)) under an SEH frame.
     * @details The engine repoints prw and sets iActive only when it took the real global world lock; otherwise
     *          prw stays the self-pointer and iActive is 0 (a no-op). prw is read back from the engine-written
     *          params and screened, but a stale-but-plausible prw would fault on the atomic store, so the store
     *          runs under __try. POD-only body so the SEH frame shares no C++ unwinding.
     */
    static void release_spwi_write_lock_guarded(std::byte *params) noexcept
    {
        __try
        {
            auto *prw = *reinterpret_cast<volatile long **>(params + Constants::SPWI_OFF_LOCK_PRW);
            const long active = *reinterpret_cast<volatile long *>(params + Constants::SPWI_OFF_LOCK_IACTIVE);
            if (prw && DMK::Memory::plausible_userspace_ptr(reinterpret_cast<uintptr_t>(prw)) && active != 0)
            {
                _InterlockedExchangeAdd(prw, -active);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    std::optional<RayHit> sphere_world_sweep(const Vector3 &origin, float radius, const Vector3 &sweep, int objtypes,
                                             const uintptr_t *p_skip_ents, int n_skip_ents)
    {
        // One-time resolution diagnostics so the log can tell "PWI unavailable" (call path broken) apart from
        // "PWI ran but missed". First failure reason and first success each logged once.
        static bool s_logged_ok = false;
        static bool s_logged_fail = false;
        auto log_fail_once = [](const char *reason)
        {
            if (!s_logged_fail)
            {
                s_logged_fail = true;
                DMK::Logger::get_instance().debug("Sphere sweep unavailable: {}", reason);
            }
        };

        if (s_physical_world_global_addr == 0)
        {
            log_fail_once("physics raycast not initialized");
            return std::nullopt;
        }

        // Resolve the physical world fresh; bail cleanly while it is null (no level / loading).
        const auto world_value = DMK::Memory::seh_read<uintptr_t>(s_physical_world_global_addr);
        if (!world_value || *world_value == 0 || !DMK::Memory::plausible_userspace_ptr(*world_value))
        {
            log_fail_once("physical world null (no level / loading)");
            return std::nullopt;
        }
        const uintptr_t world = *world_value;

        // PWI is resolved from the LIVE world vtable (slot PHYS_WORLD_VTABLE_PWI_OFFSET), screened in-image like
        // RWI. The slot wraps the impl with the world lock, so calling it from the render thread is safe.
        const auto vtable = DMK::Memory::seh_read<uintptr_t>(world);
        if (!vtable || !DMK::Memory::plausible_userspace_ptr(*vtable) || !DMK::Memory::contains(s_game_module, *vtable))
        {
            log_fail_once("world vtable unreadable or outside the game image");
            return std::nullopt;
        }
        const auto fn_slot = DMK::Memory::seh_read<uintptr_t>(*vtable + Constants::PHYS_WORLD_VTABLE_PWI_OFFSET);
        if (!fn_slot || !DMK::Memory::plausible_userspace_ptr(*fn_slot) ||
            !DMK::Memory::contains(s_game_module, *fn_slot))
        {
            log_fail_once("PWI vtable slot unresolved or outside the game image");
            return std::nullopt;
        }
        const auto fn = reinterpret_cast<PrimitiveWorldIntersectionFn>(*fn_slot);
        if (!s_logged_ok)
        {
            s_logged_ok = true;
            DMK::Logger::get_instance().debug("Sphere sweep: PWI RESOLVED (world={}, fn={})",
                                              DMK::Format::format_address(world),
                                              DMK::Format::format_address(reinterpret_cast<uintptr_t>(fn)));
        }

        // primitives::sphere { Vec3 center; float r; } in WORLD space (CryEngine PWI primitives are world).
        alignas(16) std::byte sphere[Constants::PRIMITIVE_SPHERE_SIZE];
        std::memset(sphere, 0, sizeof(sphere));
        *reinterpret_cast<Vector3 *>(sphere + 0x0) = origin;
        *reinterpret_cast<float *>(sphere + Constants::PRIMITIVE_SPHERE_RADIUS_OFFSET) = radius;

        // geom_contact*; the engine writes through ppcontact, but we read only the float return (distance), so
        // we never dereference the contact (no shared-data lifetime concern).
        void *contact = nullptr;

        alignas(16) std::byte params[Constants::SPWI_PARAMS_SIZE];
        std::memset(params, 0, sizeof(params));
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_ITYPE) = Constants::PRIMITIVE_TYPE_SPHERE;
        *reinterpret_cast<const void **>(params + Constants::SPWI_OFF_PPRIM) = sphere;
        *reinterpret_cast<Vector3 *>(params + Constants::SPWI_OFF_SWEEPDIR) = sweep;
        // Flags @ +0x98: the impl tests &0x800 (rwi_queue) and feeds this to the broadphase filter. 0x101 is the
        // KCD2-tuned full-range value (registers both close AND far contacts); do NOT set 0x800 (keeps it
        // synchronous). entTypes @ +0x9C is DEAD in this fork (zero impl reads) -> the write is a defensive no-op;
        // actors are excluded by p_skip_ents + the fan-authority gate in camera_hook.
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_FLAGS) = Constants::SPWI_FLAGS_FULL_RANGE;
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_ENTTYPES) = objtypes;
        *reinterpret_cast<void **>(params + Constants::SPWI_OFF_PPCONTACT) = &contact;
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_GEOMFLAGSALL) = 0;
        // Broad colltype mask so the sphere stops on any solid surface (mirrors the RWI colltype intent).
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_GEOMFLAGSANY) = Constants::SPWI_GEOMFLAGS_ANY_SOLID;
        // Skip the player's own physics entities so the sweep reports a clean WORLD distance instead of slamming
        // into the body at point-blank. nSkipEnts is impl-clamped to <= 4; pSkipEnts is read as pSkipEnts[i].
        const bool have_skip = p_skip_ents != nullptr && n_skip_ents > 0;
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_NSKIPENTS) = have_skip ? n_skip_ents : 0;
        *reinterpret_cast<const void **>(params + Constants::SPWI_OFF_PSKIPENTS) = have_skip ? p_skip_ents : nullptr;
        // WriteLockCond: prw self-pointer == thread-safe mode (no global lock held), matching the engine ctor.
        *reinterpret_cast<int *>(params + Constants::SPWI_OFF_LOCK_IACTIVE) = 0;
        *reinterpret_cast<void **>(params + Constants::SPWI_OFF_LOCK_PRW) = params + Constants::SPWI_OFF_LOCK_IACTIVE;

        const float distance = primitive_world_intersection_guarded(fn, reinterpret_cast<void *>(world), params);

        // Release the WriteLockCond exactly as the engine's own caller does (InterlockedAdd(prw, -iActive)),
        // reading both back AFTER the call. If the engine took a real lock it repointed prw + set iActive, so
        // this frees it (no physics-thread stall); in thread-safe self-pointer mode iActive is 0 (no-op). Runs
        // even after a faulted call, under its own SEH frame so a stale prw cannot crash.
        release_spwi_write_lock_guarded(params);

        if (!std::isfinite(distance) || distance <= 0.0f)
        {
            return std::nullopt;
        }

        // Only the distance is used by the camera; approximate the point/normal along the sweep so the RayHit is
        // fully populated for any caller that inspects them.
        RayHit hit{};
        hit.m_distance = distance;
        const float len = sweep.magnitude();
        const Vector3 dir = (len > 1e-6f) ? sweep / len : Vector3{0.0f, 0.0f, 0.0f};
        hit.m_point = origin + dir * distance;
        hit.m_normal = dir * -1.0f;
        return hit;
    }

    int resolve_player_physics_skip(const Vector3 &origin, const Vector3 &sweep, float radius, int objtypes_all,
                                    int objtypes_world, unsigned int flags, uintptr_t *out_skip, int max_out)
    {
        if (out_skip == nullptr || max_out <= 0)
        {
            return 0;
        }
        const float len = sweep.magnitude();
        if (len < 1e-4f)
        {
            return 0;
        }
        const Vector3 dir = sweep / len;
        const Vector3 seed = (std::fabs(dir.z) < 0.9f) ? Vector3{0.0f, 0.0f, 1.0f} : Vector3{1.0f, 0.0f, 0.0f};
        Vector3 right = dir.cross(seed);
        const float rlen = right.magnitude();
        Vector3 up{0.0f, 0.0f, 0.0f};
        if (rlen >= 1e-4f)
        {
            right = right / rlen;
            up = right.cross(dir);
        }
        else
        {
            right = Vector3{0.0f, 0.0f, 0.0f};
        }
        // REVERSE probe: cast from the camera end back toward the pivot. The pivot is inside the body, so a
        // forward ray exits through a back-face and misses the body; a reverse ray hits it from outside. Same
        // square-tube fan offsets as the sweep so coverage matches the sphere's footprint.
        const Vector3 camera = origin + sweep;
        const Vector3 back = sweep * -1.0f; // camera -> pivot, length = |sweep|
        const Vector3 offsets[5] = {Vector3{0.0f, 0.0f, 0.0f}, right * radius, right * (-radius), up * radius,
                                    up * (-radius)};
        int n = 0;
        for (const Vector3 &off : offsets)
        {
            const Vector3 o = camera + off;
            const auto h_all = ray_world_intersection(o, back, objtypes_all, flags);
            if (!h_all.has_value() || h_all->m_collider == 0)
            {
                continue;
            }
            // A non-world entity (player body, worn gear, NPC) is invisible to the world-only mask: collect it
            // only when the all-types hit is nearer than the world hit (or the world ray misses). World geometry
            // appears in BOTH casts at the same range, so it is never collected -- we must not skip the world.
            const auto h_world = ray_world_intersection(o, back, objtypes_world, flags);
            const bool is_non_world = !h_world.has_value() || h_all->m_distance < h_world->m_distance - 0.02f;
            if (!is_non_world)
            {
                continue;
            }
            bool seen = false;
            for (int i = 0; i < n; ++i)
            {
                if (out_skip[i] == h_all->m_collider)
                {
                    seen = true;
                    break;
                }
            }
            if (!seen && n < max_out)
            {
                out_skip[n++] = h_all->m_collider;
            }
        }
        return n;
    }

} // namespace TPVCamera
