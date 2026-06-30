/**
 * @file constants.hpp
 * @brief Central definitions for constants used throughout the mod.
 *
 * Includes version info, filenames, memory offsets, RTTI type names, and engine
 * flag values. Code/data locations are resolved purely at runtime by the
 * multi-candidate AOB cascades in aob_resolver.hpp so they survive game updates;
 * this file keeps no hard-coded image addresses.
 *
 * This is the KCD1 1.9.7 retarget of the KCD2 TPVCamera mod: the structure,
 * constant NAMES and comments mirror the KCD2 source so the two builds stay
 * maintainable in lockstep; only the KCD1-specific binary values differ.
 */
#ifndef TPVCAMERA_CONSTANTS_HPP
#define TPVCAMERA_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "version.hpp"

/**
 * @namespace Constants
 * @brief Encapsulates global constants and config defaults.
 */
namespace Constants
{
    // Mod name derived from version.hpp; used for the INI/log file names and the
    // per-process instance mutex. The version string and repository URL are read
    // directly from TPVCamera::Version where they are needed.
    constexpr const char *MOD_NAME = TPVCamera::Version::MOD_NAME;

    // File extensions
    constexpr const char *INI_FILE_EXTENSION = ".ini";
    constexpr const char *PRESETS_FILE_SUFFIX = "_presets.json";

    /** @brief Gets the INI config filename (e.g., "KCD1_TPVCamera.ini"). */
    [[nodiscard]] inline std::string get_config_filename()
    {
        return std::string(MOD_NAME) + INI_FILE_EXTENSION;
    }

    /** @brief Gets the camera-presets JSON filename (e.g., "KCD1_TPVCamera_presets.json"). */
    [[nodiscard]] inline std::string get_presets_filename()
    {
        return std::string(MOD_NAME) + PRESETS_FILE_SUFFIX;
    }

    /** @brief Log file name passed to DMK::Bootstrap (string-view-safe literal). */
    constexpr const char *LOG_FILE_NAME = "KCD1_TPVCamera.log";
    /** @brief Per-PID instance-mutex prefix so duplicate ASI loads bail cleanly. */
    constexpr const char *INSTANCE_MUTEX_PREFIX = "KCD1_TPVCamera_";

    // --- Default Configuration Values ---
    /** @brief Default logging level ("INFO"). */
    constexpr const char *DEFAULT_LOG_LEVEL = "INFO";

    // All AOB signatures are defined as multi-candidate cascades in aob_resolver.hpp
    // (k_contextCandidates, k_frustumCandidates, ...). The global-context cascade
    // resolves the storage slot whose +0x38 reaches the camera-manager root the
    // game-state detection walks (see OFFSET_MANAGER_PTR_STORAGE); the frustum-builder
    // cascade resolves CCamera::UpdateFrustumPlanes, the matrix-offset hook target that
    // every gameplay camera funnels through (gated to the game view by the embedding
    // CView vtable, camera - SVIEWPARAMS_VIEWMATRIX_OFFSET).

    // RTTI type-descriptor name of the CView class. The frustum-builder detour confirms a
    // camera belongs to a game view by matching the embedding object's vtable against this
    // name (via DMK::Rtti), then caches that vtable address for a fast per-camera qword
    // compare. Anchoring on the ASLR-invariant RTTI name rather than a hardcoded vtable
    // address keeps the game-view gate working across game patches.
    constexpr const char *CVIEW_RTTI_NAME = ".?AVCView@@";

    // Player look/aim orientation chain. Used to LEVEL the aim pitch while free-look orbit is active
    // so the character's head and the eye look forward (not just the camera).
    //
    // KCD1 uses a CCryAction singleton (NOT gEnv->pGame->GetIGameFramework). Chain:
    //   CCryAction  = *(g_pGameFramework slot)  (resolved at runtime by the AnchorId::CryActionFramework AOB
    //                 cascade; RTTI "CCryAction") -- see camera_hook resolve_cry_action()
    //   CActionGame = *(CCryAction + CCRYACTION_ACTIONGAME_OFFSET)   [KCD2 used +0x88]
    //   C_Player    = *(CActionGame + CACTIONGAME_LOCAL_ACTOR_OFFSET), validated by its RTTI type name [KCD2 +0xA40]
    //   -> look controller (C_Player + C_PLAYER_LOOK_CONTROLLER_OFFSET)   [KCD2 +0x238]
    //   -> scalar look PITCH (controller + LOOK_CONTROLLER_PITCH_OFFSET, radians, 0 = level), with a
    //      synchronized copy at LOOK_CONTROLLER_PITCH2_OFFSET; the camera reads the DERIVED quat at +0x24.
    // KCD1 pitch primary is +0x48 with a synced copy at +0x08 (KCD2 had pitch +0x8/+0x48). To LEVEL the
    // aim write BOTH pitch copies; the cameras read the derived quat lc+0x24, not the scalar.

    // g_env (SSystemGlobalEnvironment) base is resolved at runtime by the AnchorId::Genv AOB cascade;
    // pPhysicalWorld/p3DEngine/pHardwareMouse are members reached via the GENV_* offsets below.
    // RTTI type-descriptor name of C_Player, used to validate the resolved actor (replaces a
    // hardcoded vtable address so the check survives patches).
    constexpr const char *C_PLAYER_RTTI_NAME = ".?AVC_Player@entitymodule@wh@@";
    // RTTI type-descriptor name of CCryAction, used to validate the resolved framework object.
    constexpr const char *CCRYACTION_RTTI_NAME = ".?AVCCryAction@@";
    constexpr ptrdiff_t CCRYACTION_ACTIONGAME_OFFSET = 0x78; // [KCD2 +0x88]
    // RTTI type-descriptor name of CActionGame, the self-heal anchor for CCRYACTION_ACTIONGAME_OFFSET.
    constexpr const char *CACTIONGAME_RTTI_NAME = ".?AVCActionGame@@";
    constexpr ptrdiff_t CACTIONGAME_LOCAL_ACTOR_OFFSET = 0xA00;  // [KCD2 +0xA40]
    constexpr ptrdiff_t C_PLAYER_LOOK_CONTROLLER_OFFSET = 0x4C0; // [KCD2 +0x238]; ptr, lazy-init, +0 = C_Player back-ptr
    constexpr ptrdiff_t LOOK_CONTROLLER_PITCH_OFFSET = 0x48;     // scalar look pitch (radians, 0 = level) [KCD2 +0x8]
    constexpr ptrdiff_t LOOK_CONTROLLER_PITCH2_OFFSET = 0x08;    // synchronized pitch copy [KCD2 +0x48]
    // Look quaternion the camera/aim reads (DERIVED from pitch+yaw each frame).
    constexpr ptrdiff_t LOOK_CONTROLLER_QUAT_OFFSET = 0x24; // unit quat XYZW
    // GetLookQuaternion = C_Player IActor vtable slot 56 (+0x1C0); GetLookPitch = slot 58 (+0x1D0).
    constexpr ptrdiff_t C_PLAYER_GET_LOOK_QUAT_VTABLE_OFFSET = 0x1C0;
    constexpr ptrdiff_t C_PLAYER_GET_LOOK_PITCH_VTABLE_OFFSET = 0x1D0;

    // --- Player BODY-turn: force the entity world yaw (camera-relative body facing) ----------------
    // The look controller above is aim-only, so a separate primitive turns the BODY. The engine's
    // CAnimatedCharacter override-rotation is exactly two writes: an active byte and a world quat. The
    // animated-character update copies that quat into the entity rotation for the frame, REPLACING the
    // animation-derived facing, then clears the active byte (consume-once), so it is re-asserted every
    // frame while held. We replicate it with direct member writes (same effect, no cross-thread call),
    // gated by validating the resolved CAnimatedCharacter vtable.
    // Resolution from C_Player (validated by its RTTI type name):
    //   C_AnimatedHuman    = *(C_Player + C_PLAYER_ANIMATED_HUMAN_OFFSET)   [wh::animationmodule::C_AnimatedHuman]
    //   CAnimatedCharacter = *(C_AnimatedHuman + ANIMATED_HUMAN_ANIMCHAR_OFFSET), validated by its RTTI type name
    //   then write animchar+ANIMCHAR_OVERRIDE_ROT_ACTIVE_OFFSET = 1 and the world quat (XYZW) at
    //   animchar+ANIMCHAR_OVERRIDE_ROT_QUAT_OFFSET.
    constexpr ptrdiff_t C_PLAYER_ENTITY_OFFSET = 0x38; // C_Player -> CEntity (resolve fresh each frame)
    // RTTI type-descriptor name of CEntity, the self-heal anchor for the entity pointer.
    constexpr const char *C_ENTITY_RTTI_NAME = ".?AVCEntity@@";
    constexpr ptrdiff_t C_PLAYER_ANIMATED_HUMAN_OFFSET = 0x2F8; // [KCD2 +0x268]
    // RTTI type-descriptor name of C_AnimatedHuman, the self-heal anchor for the animated-human pointer.
    constexpr const char *C_ANIMATED_HUMAN_RTTI_NAME = ".?AVC_AnimatedHuman@animationmodule@wh@@";
    constexpr ptrdiff_t ANIMATED_HUMAN_ANIMCHAR_OFFSET = 0x20;
    // RTTI type-descriptor name of CAnimatedCharacter, used to validate the resolved animchar.
    constexpr const char *ANIMATED_CHARACTER_RTTI_NAME = ".?AVCAnimatedCharacter@@";
    constexpr ptrdiff_t ANIMCHAR_OVERRIDE_ROT_ACTIVE_OFFSET = 0x1D8; // BYTE, set to 1 each frame (consume-once)
    constexpr ptrdiff_t ANIMCHAR_OVERRIDE_ROT_QUAT_OFFSET = 0x1DC;   // world Quat XYZW (16 bytes)
    // Component offsets within a 16-byte quaternion (4 contiguous floats, X Y Z W). Used to write the
    // override-rotation quat above field by field; a quat is always this packed-float layout, so these are
    // sizeof(float) strides, not an engine-version struct map.
    constexpr ptrdiff_t QUAT_X_OFFSET = 0x0;
    constexpr ptrdiff_t QUAT_Y_OFFSET = 0x4;
    constexpr ptrdiff_t QUAT_Z_OFFSET = 0x8;
    constexpr ptrdiff_t QUAT_W_OFFSET = 0xC;

    // Keyboard turn-and-run: the player's input object (the action-dispatcher's `self`) is a
    // wh::entitymodule::C_PlayerInput; its body-relative MOVE INPUT is two floats (x = strafe, +right; y =
    // forward). Writing (x=0, y=+1) each frame forces pure-forward movement, which OVERRIDES the held digital
    // move keys and -- being a field write, not an xi_* action -- does NOT flip the HUD device glyphs. The pointer
    // is cached from the hook (player_onaction_player_input); the consumer validates this RTTI name before
    // writing. KCD2 pins the look yaw directly instead, so this field write is a KCD1-only mechanism.
    constexpr const char *C_PLAYERINPUT_RTTI_NAME = ".?AVC_PlayerInput@entitymodule@wh@@";
    constexpr ptrdiff_t C_PLAYERINPUT_PLAYER_BACKREF_OFFSET = 0x10; // C_PlayerInput -> C_Player (owning player)
    constexpr ptrdiff_t C_PLAYERINPUT_MOVE_X_OFFSET = 0x58;         // body-relative move input x (strafe; +right)
    constexpr ptrdiff_t C_PLAYERINPUT_MOVE_Y_OFFSET = 0x5C;         // body-relative move input y (forward)

    // The head-visibility setter (k_headVisibilityCandidates) has signature
    // void __fastcall(this /*rcx*/, bool hide_head /*dl*/, char flags /*r8b*/). The
    // first-person rig hides the player head; forcing hide_head to false keeps it
    // visible while the third-person offset is rendering so the player is not headless
    // from behind. KCD1 setter = sub_18106201C.

    // Global action dispatcher: the KCD2 AOB keys on a profiler/action string stripped from KCD1, but the
    // dispatcher itself was located via the surviving "OnAction" Lua string -> the player OnAction bridge
    // sub_181077628. The player_onaction_hook hooks it for orbit move-detection, resolved at runtime by the
    // AnchorId::ActionDispatch cascade (k_actionDispatchCandidates).

    // --- Physics world raycast (camera collision + aim convergence) ---
    // IPhysicalWorld::RayWorldIntersection inline helper (k_rayWorldIntersectionCandidates). Casts a
    // world ray and fills a ray_hit; returns the hit count. Signature (Microsoft x64):
    //   int(this /*rcx = p_physical_world*/, const Vec3* org /*rdx*/, const Vec3* dir /*r8*/,
    //       int objtypes /*r9d*/, uint flags, ray_hit* hits, int n_max_hits, void* p_skip_ents,
    //       int n_skip_ents, void* p_foreign_data, int i_foreign_data, const char* p_name_tag)
    // dir is NOT normalized -- its length is the maximum ray length, and ray_hit.dist is the
    // world-space distance to the hit.

    // p_physical_world (IPhysicalWorld*) is a member of the g_env struct: its slot address is
    // g_env + PHYSICAL_WORLD_OFFSET. It is derived from the static g_env base, so no separate static
    // address is hardcoded. The slot is dereferenced fresh on each ray: it is null until a level's
    // physical world exists, and can change on reload.
    constexpr ptrdiff_t PHYSICAL_WORLD_OFFSET = 0x30;

    // Hardware-mouse cursor reference counter: the universal "a UI wants the OS cursor" signal.
    // Menus, inventory/map, corpse-and-container loot, trade and dialogue all route through the
    // hardware mouse counter; it reads > 0 whenever a UI is up and 0 in plain gameplay (including
    // combat and bow aiming). The hardware mouse (IHardwareMouse*) is a g_env member at
    // g_env + GENV_HARDWARE_MOUSE_OFFSET, and its counter (int) sits at p_hardware_mouse +
    // HARDWARE_MOUSE_CURSOR_COUNT_OFFSET. Derived from the static g_env base and screened on each
    // read; the orbit-freeze gate no-ops if either link cannot be resolved.
    constexpr ptrdiff_t GENV_HARDWARE_MOUSE_OFFSET = 0x108; // [KCD2 +0x118]
    constexpr ptrdiff_t HARDWARE_MOUSE_CURSOR_COUNT_OFFSET = 0x30;

    // ray_hit field offsets (CryEngine physinterface.h). The engine writes a full ray_hit through the
    // SRWIParams hits pointer; size the buffer generously (0x60, matching the fork layout) so a
    // slightly larger fork ray_hit can never overflow the stack buffer.
    constexpr size_t RAY_HIT_SIZE = 0x60;
    constexpr ptrdiff_t RAY_HIT_OFFSET_DISTANCE = 0x00; // float, world distance along dir
    constexpr ptrdiff_t RAY_HIT_OFFSET_COLLIDER = 0x08; // IPhysicalEntity* pCollider (the entity hit)
    constexpr ptrdiff_t RAY_HIT_OFFSET_POINT = 0x24;    // Vec3 world hit position
    constexpr ptrdiff_t RAY_HIT_OFFSET_NORMAL = 0x30;   // Vec3 surface normal
    constexpr ptrdiff_t RAY_HIT_OFFSET_TERRAIN = 0x3C;  // int bTerrain (non-zero == global terrain heightmap hit)

    // CPhysicalEntity / CPhysicalPlaceholder world AABB (m_BBox): min @ +0x08, max @ +0x14, each a Vec3.
    constexpr ptrdiff_t PHYS_ENTITY_BBOX_MIN_OFFSET = 0x08;
    constexpr ptrdiff_t PHYS_ENTITY_BBOX_MAX_OFFSET = 0x14;

    // CPhysicalEntity foreign data: m_pForeignData @ +0x20 (the IRenderNode the physics entity belongs to),
    // m_iForeignData @ +0x28 (the PHYS_FOREIGN_ID; 1 == PHYS_FOREIGN_ID_STATIC = a static brush/render node).
    constexpr ptrdiff_t PHYS_ENTITY_FOREIGN_DATA_OFFSET = 0x20;
    constexpr ptrdiff_t PHYS_ENTITY_FOREIGN_TYPE_OFFSET = 0x28;
    constexpr int PHYS_FOREIGN_ID_STATIC = 1;

    // entity_query_flags subset (physinterface.h): ent_static=1, ent_sleeping_rigid=2, ent_rigid=4,
    // ent_living=8, ent_independent=0x10, ent_terrain=0x100. Camera collision blocks on the SOLID WORLD
    // ONLY -- ent_static | ent_terrain -- which is buildings/walls/level geometry/static props/vegetation
    // plus the ground. It deliberately EXCLUDES movable rigids, living capsules and independents.
    constexpr int RWI_OBJTYPES_CAMERA = 0x101; // ent_static | ent_terrain (solid world only)
    // ent_all: every entity type (static|rigid|living|independent|terrain|...). Used ONLY to find the
    // player's own physics entities to SKIP on the sphere sweep (the widest query so no actor body is missed),
    // never as a camera-collision surface filter.
    constexpr int RWI_OBJTYPES_ALL = 0x11F;
    // rwi_stop_at_pierceable (0x0F) | rwi_colltype_any (0x400) | geom_colltype_ray (0x00020000) |
    // geom_colltype_player (0x80000000) == 0x8002040F. The high word adds an explicit geometry collide-type
    // request so static collision-PROXY meshes (fabric roofs) flagged geom_colltype_player but NOT
    // geom_colltype_ray are still reported, instead of the camera sliding through the cloth.
    constexpr unsigned int RWI_STOP_AT_PIERCEABLE = 0x0000000F; // stop at the first solid (non-pierceable) hit
    constexpr unsigned int RWI_COLLTYPE_ANY = 0x00000400;       // report a hit whatever the surface collision class
    constexpr unsigned int GEOM_COLLTYPE_RAY = 0x00020000;      // request geometry flagged as ray-collidable
    constexpr unsigned int GEOM_COLLTYPE_PLAYER = 0x80000000;   // also request player-collidable proxies (fabric roofs)
    constexpr unsigned int RWI_FLAGS_STOP_AT_SOLID =
        RWI_STOP_AT_PIERCEABLE | RWI_COLLTYPE_ANY | GEOM_COLLTYPE_RAY | GEOM_COLLTYPE_PLAYER; // 0x8002040F

    // IPhysicalWorld::RayWorldIntersection is reached through the LIVE physical-world vtable, NOT an AOB on an
    // inline helper (KCD2 used an AOB; the KCD1 RayWorldIntersection anchor is empty by design). It is vtable
    // SLOT 35 == byte offset 0x118. The slot is resolved fresh per ray from
    // the live world vtable and screened before the indirect call. [KCD2 resolved a flat helper by AOB.]
    constexpr ptrdiff_t RWI_VTABLE_OFFSET = 0x118; // IPhysicalWorld vtable slot 35

    // KCD1 vtable slot 35 is the CryEngine 3.6+ SRWIParams form, NOT the old flat-arg form:
    //   int RayWorldIntersection(this /*rcx = world*/, SRWIParams* pp /*rdx*/, void* pLockContacts /*r8 = null*/,
    //                            int iCaller /*r9d*/)   <- in sub_18041B7F0; iCaller is the 4th arg
    // The caller builds a zeroed SRWIParams (org/dir are EMBEDDED Vec3 values, not pointers), points its hits
    // field at a ray_hit buffer, sets nMaxHits = 1, and passes iCaller = RWI_EXTERNAL_CALLER (the external
    // physics-thread index; the synchronous path spin-locks on it). The field offsets below are KCD1 1.9.7
    // specific. KCD2 instead resolved a flat 12-arg INLINE helper by AOB -- a DIFFERENT entry; the
    // vtable slot must NOT be called with that flat signature (args land in the wrong registers).
    constexpr int RWI_EXTERNAL_CALLER = 4;           // SRWIParams iCaller (MAX_PHYS_THREADS external slot)
    constexpr size_t SRWI_PARAMS_SIZE = 0x80;        // zeroed params block
    constexpr ptrdiff_t SRWI_ORG_OFFSET = 0x18;      // Vec3 org (embedded)
    constexpr ptrdiff_t SRWI_DIR_OFFSET = 0x24;      // Vec3 dir (embedded; length = max ray length)
    constexpr ptrdiff_t SRWI_OBJTYPES_OFFSET = 0x30; // int entity_query_flags
    constexpr ptrdiff_t SRWI_FLAGS_OFFSET = 0x34;    // unsigned int rwi_flags
    constexpr ptrdiff_t SRWI_HITS_OFFSET = 0x38;     // ray_hit* hits
    constexpr ptrdiff_t SRWI_NMAXHITS_OFFSET = 0x40; // int nMaxHits

    // --- Swept-sphere camera collision: IPhysicalWorld::PrimitiveWorldIntersection (PWI / SPWIParams) ---
    // PORTED FROM KCD2: the Warhorse fork shares this physics layout, so KCD1's offsets are IDENTICAL to
    // KCD2's. On KCD1 (impl sub_18038878C): PWI = CPhysicalWorld vtable slot 57; the impl reads
    // the SPWIParams fields at the offsets below; pLockContacts (r8) defaults to pp+0xD8 when null. Signature:
    //   float(this /*rcx=world*/, SPWIParams* pp /*rdx*/, WriteLockCond* pLockContacts /*r8=0->pp+0xD8*/,
    //         const char* pNameTag /*r9*/)  -> xmm0 = distance to first contact (> 0 == hit; sweep).
    constexpr ptrdiff_t PHYS_WORLD_VTABLE_PWI_OFFSET = 0x1C8; // CPhysicalWorld vtable slot 57

    // primitives::sphere { Vec3 center; float r; } -- 16 bytes, type id 4. center is WORLD space.
    constexpr int PRIMITIVE_TYPE_SPHERE = 4;
    constexpr size_t PRIMITIVE_SPHERE_SIZE = 0x10;
    // primitives::sphere is { Vec3 center; float r; }: center at +0, radius float at +0xC (a fixed POD layout,
    // not an engine-version struct map).
    constexpr ptrdiff_t PRIMITIVE_SPHERE_RADIUS_OFFSET = 0xC;

    // Fork SPWIParams field offsets (KCD1, from sub_18038878C; identical to the KCD2 fork).
    // Heavily reorganized vs the generic CryEngine header. The OUTPUT/lock fields (engine writes through them)
    // are the memory-safety-critical ones.
    constexpr size_t SPWI_PARAMS_SIZE = 0x100;        // impl reads through ~0xE0; pad to 0x100
    constexpr ptrdiff_t SPWI_OFF_ITYPE = 0x18;        // int primitive type (4 = sphere)
    constexpr ptrdiff_t SPWI_OFF_PPRIM = 0x20;        // const primitives::primitive*
    constexpr ptrdiff_t SPWI_OFF_SWEEPDIR = 0x8C;     // Vec3 sweep vector (|dir| > 0 -> sweep)
    constexpr ptrdiff_t SPWI_OFF_FLAGS = 0x98;        // int rwi-style flags: impl tests &0x800 = queue and feeds
                                                      // the broadphase filter -- set 0x101, NEVER 0x800
    constexpr ptrdiff_t SPWI_OFF_ENTTYPES = 0x9C;     // entity_query_flags per header order; DEAD in this fork
    constexpr ptrdiff_t SPWI_OFF_PPCONTACT = 0xA0;    // geom_contact** OUT (engine writes *ppcontact)
    constexpr ptrdiff_t SPWI_OFF_GEOMFLAGSALL = 0xA8; // int (parts must have ALL these geom flags)
    constexpr ptrdiff_t SPWI_OFF_GEOMFLAGSANY = 0xAC; // int colltype mask (0x0FFF = any solid surface)
    constexpr ptrdiff_t SPWI_OFF_NSKIPENTS = 0xB8;    // int (impl clamps to <= 4)
    constexpr ptrdiff_t SPWI_OFF_PSKIPENTS = 0xC0;    // IPhysicalEntity** (impl indexes pSkipEnts[i])
    constexpr ptrdiff_t SPWI_OFF_LOCK_IACTIVE = 0xD8; // int  WriteLockCond.iActive
    constexpr ptrdiff_t SPWI_OFF_LOCK_PRW = 0xE0;     // int* WriteLockCond.prw (self-ptr = thread-safe, no lock)

    // SPWI field VALUES (written INTO the fields above; the offsets are the field positions, these are the
    // contents). Kept named alongside the offsets so a tuning change is one edit, not a hunt through the impl.
    // Flags value for SPWI_OFF_FLAGS: the impl tests &0x800 (rwi_queue); 0x101 is the KCD2-tuned full-range
    // value that registers both close and far contacts. Must NOT include 0x800 (that would queue, not run sync).
    constexpr int SPWI_FLAGS_FULL_RANGE = 0x101;
    // Colltype mask for SPWI_OFF_GEOMFLAGSANY: stop the sphere on ANY solid surface (mirrors the RWI intent).
    constexpr int SPWI_GEOMFLAGS_ANY_SOLID = 0x0FFF;

    // --- Render-node camera occlusion (collide with render-only roofs RWI cannot see) ---
    // Some roofs (tent / awning canopy cloth) are CBrush render meshes with NO ray-collidable physics, so
    // the physics camera collision glides straight through them and the cloth buries the camera when a
    // look-down raises it overhead. The renderer DOES see them: I3DEngine::GetObjectsInBox is an octree
    // query that returns the render nodes overlapping a box, independent of physics collision type. The
    // camera clamps below an overhead brush so a steep look-down does not lift it into the canopy.
    //
    // p3DEngine (I3DEngine*) is a g_env member at g_env + GENV_3DENGINE_OFFSET; the query function is
    // reached through the live C3DEngine vtable slot. Both are screened on each use.
    constexpr ptrdiff_t GENV_3DENGINE_OFFSET = 0x08;
    // I3DEngine::GetObjectsInBox = C3DEngine vtable SLOT 233 (+233*8). [KCD2 used slot 243.]
    //   uint32 GetObjectsInBox(this /*rcx*/, const AABB* bbox /*rdx; 6 floats min.xyz,max.xyz*/,
    //   IRenderNode** p_out /*r8*/). p_out == null returns the count only; otherwise it memcpys the FULL
    //   list with NO size cap, so the count is read first and the buffer sized to fit it.
    constexpr ptrdiff_t C3DENGINE_VTABLE_GETOBJECTSINBOX_OFFSET = 233 * 8;
    // IRenderNode vtable: GetBBox = slot 5 (+0x28) [KCD2 slot 4/+0x20]; GetRenderNodeType = slot 7 (+0x38),
    // returns EERType (eERType_Brush == 1) [same as KCD2].
    constexpr ptrdiff_t RENDERNODE_VTABLE_GETBBOX_OFFSET = 0x28;
    constexpr ptrdiff_t RENDERNODE_VTABLE_GETTYPE_OFFSET = 0x38;
    constexpr int EERTYPE_BRUSH = 1;
    // IRenderNode::m_dwRndFlags (carries ERF_HIDDEN). UNRESOLVED for KCD1 + currently UNUSED: 0x34 is NOT
    // m_dwRndFlags -- it is a render-state dword whose bit 8 (0x100) is SET on many VISIBLE brushes, so the KCD2
    // ERF_HIDDEN visibility gate is omitted in render_occlusion.cpp until the real offset is reversed (see the
    // TODO there). Kept for documentation / the eventual restore. [KCD2 m_dwRndFlags +0x28, ERF_HIDDEN BIT(8)]
    constexpr ptrdiff_t RENDERNODE_RNDFLAGS_OFFSET = 0x34; // WRONG/unresolved -- not currently referenced
    constexpr unsigned int ERF_HIDDEN = 0x100;             // ERenderNodeFlags BIT(8)
    // A render node whose largest world-AABB dimension exceeds this (meters) is treated as world / terrain
    // and never used as an overhead roof clamp, so only compact props (tents, awnings, lean-tos) qualify.
    constexpr float RENDER_OCCLUSION_MAX_BRUSH_SIZE = 50.0f;
    // Safety cap on the per-query node count; also sizes the stack list buffer for the count-then-fill query.
    constexpr int RENDER_OCCLUSION_MAX_NODES = 1024;

    // CBrush layout (KCD1): Matrix34 @ +0x48 [KCD2 +0x50]; IStatObj* @ +0x98 [same];
    // cached world AABB min @ +0xAC, max @ +0xB8 (read directly; what GetBBox returns).
    constexpr ptrdiff_t CBRUSH_MATRIX_OFFSET = 0x48;   // Matrix34 world transform [KCD2 +0x50]
    constexpr ptrdiff_t CBRUSH_STATOBJ_OFFSET = 0x98;  // IStatObj*
    constexpr ptrdiff_t CBRUSH_AABB_MIN_OFFSET = 0xAC; // cached world AABB min Vec3
    constexpr ptrdiff_t CBRUSH_AABB_MAX_OFFSET = 0xB8; // cached world AABB max Vec3
    // IStatObj::m_szFileName, a CryString whose value IS the char* to the .cgf path chars (dereferenced once).
    // On KCD1: statobj+0xA8 -> "objects/buildings/.../*_roof.cgf" (KCD2 was +0xA0; reads null here).
    // (statobj+0xB8 is a DIFFERENT attr string -- "lastpose = undefined" -- so do not confuse the two.)
    // Used for trace-logging WHAT a render-occlusion clamp latched onto (identify false positives by name).
    constexpr ptrdiff_t STATOBJ_CGF_NAME_OFFSET = 0xA8; // char* to .cgf path on the IStatObj [KCD2 +0xA0]

    // --- Render-mesh cloth ray-march (ports KCD2's overhead cloth clamp 1:1; only the values differ) ---
    // IStatObj -> IRenderMesh (CRenderMesh): statobj+0x48 RTTI == "CRenderMesh" [KCD2 +0x58].
    constexpr ptrdiff_t STATOBJ_RENDERMESH_OFFSET = 0x48; // IRenderMesh* (CRenderMesh) [KCD2 +0x58]
    // CRenderMesh vertex count: GetPosPtr (slot 43) allocates 12 * *(rmesh+0x6C) and fills that
    // many float3 positions, so +0x6C IS m_nVerts (== IRenderMesh::GetVerticesCount) [KCD2 +0x7C].
    constexpr ptrdiff_t RENDERMESH_NVERTS_OFFSET = 0x6C;
    // IRenderMesh::GetPosPtr vtable slot 43 (same index as KCD2): returns the engine-decoded
    // float3 CPU position cache and sets *stride = 12; the FSL_READ flag takes the decode/build path.
    constexpr ptrdiff_t RENDERMESH_VTABLE_GETPOSPTR_OFFSET = 43 * 8;
    constexpr unsigned int IRENDERMESH_FSL_READ = 0x01; // FSL_READ (engine enum, fork-stable) [same as KCD2]
    constexpr int RENDER_OCCLUSION_VERT_MAX = 200000;   // sanity cap on a mesh's vertex count [same as KCD2]
    // Tube radius (m) around the pivot->camera sightline within which a cloth vertex counts as occluding; also
    // the camera's standoff below the canopy. MIN_COLUMN_VERTS cloth vertices must lie on the tube to clamp (so a
    // thin beam / rope does not). REQUERY_DIST throttles the re-query of the (static) cloth. [all same as KCD2]
    constexpr float RENDER_OCCLUSION_COLUMN_RADIUS = 0.3f;
    constexpr int RENDER_OCCLUSION_MIN_COLUMN_VERTS = 3;
    constexpr float RENDER_OCCLUSION_REQUERY_DIST = 0.40f;

    // --- Camera-space interaction (door/usable look-at ray redirect) ---
    // RESOLVED for KCD1 via the interactor SELECTION-WRAP (interaction_hook.cpp + the INTERACTOR_LOOKRAY /
    // FRAMEWORK_VIEW constants below): the per-tick selection is wrapped and its framework-view pose is
    // transiently overwritten with the render camera + crosshair (origin slid to the eye projection). The KCD2
    // look-ray-builder rewrite did NOT port (KCD1 reads the shared view downstream); the on-screen reticle gate
    // for InteractiveScene usables (shrines/beds/doors) is still not ported (its KCD1 analog is unresolved).

    // KCD2 hooked the in-game menu (MenuOpen/MenuClose) and UI overlays (HideOverlays/ShowOverlays) via AOBs
    // that get 0 matches on KCD1. KCD1 reaches the same game-states through different convergences, each
    // resolved at runtime by its own AOB cascade: the menu via the wh::guimodule toggle (AnchorId::MenuOpen)
    // and the overlay/apse UI (inventory, codex, map) via the CryEngine action-filter worker
    // (AnchorId::OverlayHide). Dialogue is detected separately via the active-camera RTTI (the dialogue camera
    // swaps to wh::game::C_CameraDialog, type_id 2 -- see CAMERA_TYPE_DIALOG).

    // Generic input-event dispatcher (k_inputDispatchCandidates resolves it at runtime): KCD1 hook point is
    // CBaseInput::PostInputEvent (sub_1803E60B8; CBaseInput vtable slot 12). Every input event (movement and
    // look, FPV and TPV) funnels through here. The free-look hooks it to capture the mouse-look delta and
    // freeze look input while orbiting.

    // Global action dispatcher (the C++ source of Lua Player:OnAction), sub_1801FF740 on the dev build,
    // resolved at runtime by k_actionDispatchCandidates. Found via the surviving "OnAction" Lua string;
    // signature is IDENTICAL to KCD2's sub_1808EBEE4 (clean, non-variadic): _QWORD*(this /*rcx*/, const char**
    // name /*rdx*/, uint activation /*r8d: 1=press, 2=release, 4=hold*/, float value /*xmm3*/). It runs the
    // action-map press/release/hold state machine and forwards to Lua OnAction; every player action (movement:
    // moveforward/xi_movey, value ~1 held / 0 released) flows through it. The orbit move-detection hooks it and
    // latches |value|. (The earlier leaf sub_181077628 was the per-entity Lua bridge, which player movement does
    // NOT reach.)

    // In-game menu open/close toggle sub_1805B84CC, the wh::guimodule menu show/hide convergence:
    // void(this /*rcx*/, char display /*dl: 1=open, 0=close*/). It acts only on a state CHANGE (*(this+0x41) is
    // the current menu-open byte) and is the single point ALL menu open/close paths funnel through (Flash
    // "DisplayIngameMenu" handler sub_1805B849C, input, etc -- 5+ callers). Found via the C_UIMenuEvents
    // registry (sub_1811425C8). KCD2 hooked separate vtable MenuOpen/MenuClose; KCD1 has this one toggle
    // instead, resolved at runtime by k_menuToggleCandidates (wired to AnchorId::MenuOpen; MenuClose stays
    // empty).

    // Action-map filter enable/disable worker sub_1804FCC0C: the single convergence both
    // CActionMapManager::EnableFilter (vtable slot 28 = sub_1804FC414) and DisableFilter (slot 29 =
    // sub_1804FCBF0) funnel through: void*(this /*rcx*/, const char* name /*rdx*/, char enable /*r8b: !=0
    // enable, 0 disable*/, uint a4, char a5). A null/empty name is the engine "all filters" branch. Every
    // blocking apse/UI screen enables a NAMED filter here and in plain gameplay NO filter is enabled, so this is
    // KCD1's reliable overlay signal (the KCD2 HideOverlays/ShowOverlays AOBs get 0 matches). Found via the
    // CActionMapManager vtable (??_7CActionMapManager@@6B@). Resolved at runtime by
    // k_actionFilterWorkerCandidates; ui_overlay_hooks.cpp hooks it to drive overlay_state().active.

    // Action-filter names that signal a blocking apse/UI screen: the inventory and codex (and
    // the in-game menu overlay) raise "only_ui", the world map raises "only_map", dialogue raises "only_dialog",
    // and the MAIN MENU / frontend (no level gameplay) raises "only_menu". All drive the Overlay game-state, so
    // the default SuppressTPVState="Overlay" hides the TPV offset in every one of them (incl. the main menu,
    // which renders a background camera with a RESOLVED player -- only_menu is the reliable signal that
    // distinguishes it from gameplay, where NO filter is enabled). Dialogue ALSO sets the separate Dialogue bit
    // via active-camera RTTI in game_state.cpp, used by the edge-triggered Forced* state policies.
    constexpr const char *ACTION_FILTER_ONLY_UI = "only_ui";         // inventory / codex / in-game menu overlay
    constexpr const char *ACTION_FILTER_ONLY_MAP = "only_map";       // world map
    constexpr const char *ACTION_FILTER_ONLY_DIALOG = "only_dialog"; // dialogue
    constexpr const char *ACTION_FILTER_ONLY_MENU = "only_menu";     // main menu / frontend (no level gameplay)

    // Camera-space interaction (look-ray redirect). The C_PlayerInteractor per-tick target selection
    // (vtable slot 5 sub_1803E5054 -> sub_1803E51EC) builds its "what am I looking at / press to use" ray and
    // evaluates candidates from the FRAMEWORK VIEW (eye). In third person the eye-anchored ray diverges from the
    // screen-centre crosshair, so the use-target misses what the crosshair points at. interaction_hook.cpp wraps
    // the selection sub_1803E51EC (resolved at runtime by k_interactorLookRayCandidates, AnchorId::
    // InteractorLookRay) and transiently substitutes the render camera + crosshair pose. KCD1 reads the shared
    // view downstream, so no separate ray-builder rewrite is needed (the KCD2 sub_180530584 analog did not
    // port). Found live via a write-watch on the selected-target id at interactor+0x84.

    // View-consistent interaction redirect (the safe KCD1 approach). The selection sub_1803E51EC builds its
    // look ray AND evaluates candidates from the framework view pose v10, so a ray-only redirect leaves a
    // camera-ray + eye-view mismatch that crashes. Instead the hook wraps sub_1803E51EC and transiently
    // overwrites v10 with the render camera + crosshair, then restores it. v10 is resolved as:
    //   framework = *(global-context slot)  (the AnchorId::Context cascade; the engine getter sub_180430AA4
    //               just loads that slot -- see interaction_hook resolve_framework());
    //   view = *(framework + FRAMEWORK_VIEW_OFFSET);
    //   v10 = view + VIEW_POSE_OFFSET (+ VIEW_POSE_ALT_DELTA when *(view + VIEW_POSE_ALT_FLAG_OFFSET) != 0).
    // v10 layout = Vec3 position (floats 0..2) then a CryEngine Quat (v.x, v.y, v.z, w = floats 3..6).
    constexpr uintptr_t FRAMEWORK_VIEW_OFFSET = 56;            // framework -> gameplay view subsystem
    constexpr uintptr_t VIEW_POSE_OFFSET = 44;                 // view subsystem -> look-ray pose (Vec3 + Quat)
    constexpr uintptr_t VIEW_POSE_ALT_DELTA = 0xD4;            // added to the pose offset when the alt-flag is set
    constexpr uintptr_t VIEW_POSE_ALT_FLAG_OFFSET = 24;        // byte selecting the alternate pose slot

    // Look-axis event ids (SInputEvent.keyId / EKeyId, KCD-renumbered) matched on the analog look channel
    // together with MOUSE_INPUT_TYPE_ID below (which is actually EInputState::eIS_Changed, NOT a device
    // type -- so the same gate catches mouse AND gamepad analog axes; see INPUT_EVENT_TYPE_OFFSET).
    constexpr int INPUT_LOOK_YAW_EVENT_ID = 0x10A;   // mouse horizontal look (maxis_x); value = delta
    constexpr int INPUT_LOOK_PITCH_EVENT_ID = 0x10B; // mouse vertical look (maxis_y); value = delta
    // Gamepad RIGHT-STICK axes (xi_thumbrx / xi_thumbry). Same eIS_Changed channel, but value at +0x18 is
    // the analog DEFLECTION (-1..1), not a delta -- the orbit hook latches it and the render hook integrates
    // it by rate (GamepadOrbitSpeed X/Y deg/s). [KCD2 was 0x21A/0x21B.]
    constexpr int INPUT_PAD_LOOK_YAW_EVENT_ID = 0x216;   // right-stick X (horizontal)
    constexpr int INPUT_PAD_LOOK_PITCH_EVENT_ID = 0x217; // right-stick Y (vertical)
    // Left-stick + the WASD movement keys give movement INTENT in the absence of an action dispatcher.
    constexpr int INPUT_PAD_MOVE_X_EVENT_ID = 0x210; // left-stick X (xi_thumblx)
    constexpr int INPUT_PAD_MOVE_Y_EVENT_ID = 0x211; // left-stick Y (xi_thumbly)

    // --- Memory Offsets ---
    // Global-context -> camera-manager pointer. The manager is the root the game-state detection
    // walks to read the active camera (see OFFSET_ACTIVE_CAMERA below and game_state.cpp). The global-context
    // slot itself is resolved at runtime by the AnchorId::Context cascade (game_interface.cpp).
    constexpr ptrdiff_t OFFSET_MANAGER_PTR_STORAGE = 0x38;        // Global context to camera manager
    // RTTI type-descriptor name of the camera manager, the self-heal anchor for OFFSET_MANAGER_PTR_STORAGE.
    constexpr const char *C_CAMERA_MANAGER_RTTI_NAME = ".?AVC_CameraManager@game@wh@@";

    // --- Game-state detection (see game_state.cpp) ---
    // Active-camera pointer on the wh::game::C_CameraManager. KCD1 stores the active camera at manager+0x10
    // and each camera carries a TYPE ID at cam+0x08 (0=FP 1=TP 2=Dialog 3=Combat 4=Minigame(dice) 7=Ansel),
    // so the active camera is identified by its type id (faster than RTTI). The game selects this camera
    // BEFORE the pose smoother runs, so a state read from it does not lag.
    constexpr ptrdiff_t OFFSET_ACTIVE_CAMERA = 0x10;  // [KCD2 used +0x30 + RTTI]
    constexpr ptrdiff_t OFFSET_CAMERA_TYPE_ID = 0x08; // int type id at cam+0x08
    constexpr int CAMERA_TYPE_FIRST_PERSON = 0;
    constexpr int CAMERA_TYPE_THIRD_PERSON = 1;
    constexpr int CAMERA_TYPE_DIALOG = 2;
    constexpr int CAMERA_TYPE_COMBAT = 3;
    constexpr int CAMERA_TYPE_MINIGAME = 4; // dice/tabletop only
    constexpr int CAMERA_TYPE_ANSEL = 7;
    // RTTI type-descriptor names kept for cross-reference / fallback identification.
    constexpr const char *C_CAMERA_COMBAT_RTTI_NAME = ".?AVC_CameraCombatDelegate@game@wh@@";
    constexpr const char *C_CAMERA_DIALOG_RTTI_NAME = ".?AVC_CameraDialog@game@wh@@";

    // --- Minigame detection (see game_state.cpp poll_active_minigame) ---
    // Every minigame (dice, reading, pickpocketing, alchemy, herb gathering) derives from
    // wh::playermodule::C_Minigame and is owned by the C_PlayerModule. The module keeps the active
    // minigames in a std::map<actorId, C_Minigame*>; a non-empty map means a minigame is on screen.
    // The chain is reached from the SAME global context the camera manager hangs off:
    //   subsystem = *(context + OFFSET_MINIGAME_SUBSYSTEM)    // C_PlayerModule (RTTI-confirmed)
    //   map       = *(subsystem + OFFSET_MINIGAME_MAP)        // ptr to std::map node tree (getter sub_1806FD770)
    //   in_minigame = *(uint64*)(map + OFFSET_MINIGAME_MAP_SIZE) > 0
    // Each tree node holds the key (actorId) at OFFSET_MINIGAME_NODE_KEY and the C_Minigame* value at
    // OFFSET_MINIGAME_NODE_VALUE; the concrete minigame's RTTI then identifies WHICH minigame (dice -> C_Dice,
    // reading -> C_Reading, and so on for all 11 in this one map -- so the per-minigame child bit is reliable).
    // On KCD1 lockpicking and hole-digging are C_Minigame too, so they resolve a child bit like the rest.
    constexpr ptrdiff_t OFFSET_MINIGAME_SUBSYSTEM = 0xE8; // global context -> C_PlayerModule [KCD2 +0x128]
    // RTTI type-descriptor name of the minigame subsystem, the self-heal anchor for OFFSET_MINIGAME_SUBSYSTEM.
    constexpr const char *C_PLAYER_MODULE_RTTI_NAME = ".?AVC_PlayerModule@playermodule@wh@@";
    // Map pointer = C_PlayerModule vtable slot 9 getter sub_1806FD770, which returns *(this + 0x98). The old 0x90
    // read a wrong adjacent heap pointer, giving a garbage _Mysize that left the Minigame umbrella stuck ON with
    // no child bit ever resolving; 0x98 is the correct offset.
    constexpr ptrdiff_t OFFSET_MINIGAME_MAP = 0x98;        // C_PlayerModule -> std::map<actorId,C_Minigame*> ptr
    constexpr ptrdiff_t OFFSET_MINIGAME_MAP_SIZE = 0x08;   // map -> _Mysize (0 == no minigame)
    constexpr ptrdiff_t OFFSET_MINIGAME_NODE_KEY = 0x20;   // tree node -> key (actorId dword)
    constexpr ptrdiff_t OFFSET_MINIGAME_NODE_VALUE = 0x28; // tree node -> C_Minigame* value

    // RTTI type-descriptor names of the concrete KCD1 minigames, matched against the active minigame's vtable.
    constexpr const char *C_MINIGAME_DICE_RTTI_NAME = ".?AVC_Dice@playermodule@wh@@";
    constexpr const char *C_MINIGAME_READING_RTTI_NAME = ".?AVC_Reading@playermodule@wh@@";
    constexpr const char *C_MINIGAME_PICKPOCKETING_RTTI_NAME = ".?AVC_Pickpocketing@playermodule@wh@@";
    constexpr const char *C_MINIGAME_ALCHEMY_RTTI_NAME = ".?AVC_Alchemy@playermodule@wh@@";
    constexpr const char *C_MINIGAME_HERB_GATHERING_RTTI_NAME = ".?AVC_HerbGathering@playermodule@wh@@";
    // The full C_Minigame subclass set (RTTI-enumerated). LockPicking and HoleDigging ARE C_Minigame on KCD1, as
    // are Backgammon/BookTranscription/Building/Sharpening, so all are detected through the one active-minigame map
    // like dice/reading/etc. (KCD2 detects lockpicking the same way; the rosters differ, not the mechanism.)
    constexpr const char *C_MINIGAME_LOCKPICKING_RTTI_NAME = ".?AVC_LockPicking@playermodule@wh@@";
    constexpr const char *C_MINIGAME_HOLE_DIGGING_RTTI_NAME = ".?AVC_HoleDigging@playermodule@wh@@";
    constexpr const char *C_MINIGAME_BACKGAMMON_RTTI_NAME = ".?AVC_Backgammon@playermodule@wh@@";
    constexpr const char *C_MINIGAME_BOOK_TRANSCRIPTION_RTTI_NAME = ".?AVC_BookTranscription@playermodule@wh@@";
    constexpr const char *C_MINIGAME_BUILDING_RTTI_NAME = ".?AVC_Building@playermodule@wh@@";
    constexpr const char *C_MINIGAME_SHARPENING_RTTI_NAME = ".?AVC_Sharpening@playermodule@wh@@";

    // Aiming a missile weapon (bow/crossbow). KCD1 has no embedded missile
    // controller (the KCD2 c_player+0xD70 path does not exist) and the weapon runtime is behind a handle table
    // (no pointer chain to it), but C_Player itself carries a player-side ranged-aim flag at +0x298: it reads 1
    // in EVERY non-aiming state (holstered, weapon lowered, melee/combat stance) and 0 ONLY while aiming a
    // ranged weapon -- INVERTED, so aiming == (*(byte)(c_player+0x298) == 0). Being on C_Player (RTTI
    // wh::entitymodule::C_Player) it is weapon-agnostic (covers crossbows, which share the C_Bow class) and a
    // fixed offset (no chain). +0x299 mirrors it. A failed read must report "not aiming" (fail closed).
    constexpr ptrdiff_t OFFSET_AIMING_FLAG = 0x298; // C_Player -> ranged-aim byte (0 == aiming, inverted)

    // Crouch/sneak AND mount BOTH come from the player's STANCE enum. C_ActorModel is a POINTER on
    // C_Player, dereferenced then validated by its RTTI. The 4-byte CURRENT STANCE enum lives at +0x1C8.
    // KCD1 enum (shifted -1 vs KCD2, NO cart): 0 stand, 1 lying, 2 sitting, 3 kneel, 4 horse/mount, 5 crouch.
    constexpr ptrdiff_t C_PLAYER_ACTOR_MODEL_OFFSET = 0x908; // [KCD2 +0x990]
    constexpr ptrdiff_t C_ACTOR_MODEL_STANCE_OFFSET = 0x1C8; // [KCD2 +0x80]
    constexpr unsigned int C_ACTOR_MODEL_STANCE_LYING = 1u;   // lying down (sleeping in bed)
    constexpr unsigned int C_ACTOR_MODEL_STANCE_SITTING = 2u; // sitting (bench / chair)
    constexpr unsigned int C_ACTOR_MODEL_STANCE_KNEEL = 3u;   // kneeling
    constexpr unsigned int C_ACTOR_MODEL_STANCE_MOUNT = 4u;   // horse (mounted)
    constexpr unsigned int C_ACTOR_MODEL_STANCE_CROUCH = 5u;  // crouch / sneak / stealth
    constexpr const char *C_ACTOR_MODEL_RTTI_NAME = ".?AVC_ActorModel@entitymodule@wh@@";

    // CEntity world transform member (relative to the CEntity* base): Matrix34, translation in column 3.
    constexpr ptrdiff_t OFFSET_ENTITY_WORLD_MATRIX_MEMBER = 0x58;

    // Fields inside the CView object that the third-person camera reads.
    constexpr ptrdiff_t SVIEWPARAMS_POSITION_OFFSET = 0x14;   // Vec3 camera world eye position
    constexpr ptrdiff_t SVIEWPARAMS_ROTATION_OFFSET = 0x20;   // Quat (x,y,z,w) eye orientation
    constexpr ptrdiff_t SVIEWPARAMS_VIEWMATRIX_OFFSET = 0xE8; // embedded render CCamera (3x4 matrix at +0)

    // Render CCamera internals that SetFrustum writes right before the frustum builder runs, read and
    // rewritten by the per-preset FOV override. The projection FOV scalar (radians) is at +0x30; the
    // cull-frustum edge vectors at +0x50/+0x58/+0x60/+0x68/+0x70 are all proportional to 1/tan(fov/2)
    // (with +0x60 the tan term itself), so rescaling them keeps culling matched to the overridden FOV.
    constexpr ptrdiff_t CCAMERA_PROJECTION_FOV_OFFSET = 0x30; // float, projection FOV (radians)
    constexpr ptrdiff_t CCAMERA_CULL_EDGE_0_OFFSET = 0x50;    // float, cull edge (proportional to 1/tan)
    constexpr ptrdiff_t CCAMERA_CULL_EDGE_1_OFFSET = 0x58;
    constexpr ptrdiff_t CCAMERA_CULL_TAN_OFFSET = 0x60; // float, tan(fov/2) term (rescaled by the inverse ratio)
    constexpr ptrdiff_t CCAMERA_CULL_EDGE_3_OFFSET = 0x68;
    constexpr ptrdiff_t CCAMERA_CULL_EDGE_4_OFFSET = 0x70;

    // Hide-head flag mirrored on the player entity (relative to the entity passed to the
    // head-visibility setter); read to re-assert the head while the offset is active.
    constexpr ptrdiff_t OFFSET_ENTITY_HIDE_HEAD_FLAG = 0x9C4; // [KCD2 +0xA38]

    // --- Input Event Offsets ---
    // SInputEvent layout (CryEngine IInput.h: deviceType@+0x00, state@+0x04, keyName@+0x08, keyId@+0x10,
    // modifiers@+0x14, value@+0x18, pSymbol@+0x20). TYPE_OFFSET is the STATE field, not the device type.
    constexpr ptrdiff_t INPUT_EVENT_TYPE_OFFSET = 0x04;  // SInputEvent.state (EInputState)
    constexpr ptrdiff_t INPUT_EVENT_ID_OFFSET = 0x10;    // SInputEvent.keyId (EKeyId)
    constexpr ptrdiff_t INPUT_EVENT_VALUE_OFFSET = 0x18; // SInputEvent.value (mouse: delta; pad: deflection)
    // EInputState::eIS_Changed (1 << 3). Every analog axis move -- mouse OR gamepad stick -- posts with this
    // state, so it is the device-AGNOSTIC gate for the look channel. Name kept for compatibility; it is the
    // input STATE, not a mouse/device type (the keyId distinguishes the axis and the device).
    constexpr int MOUSE_INPUT_TYPE_ID = 8;

    /** @brief Name of the target game module. */
    constexpr const char *MODULE_NAME = "WHGame.dll";
} // namespace Constants
#endif // TPVCAMERA_CONSTANTS_HPP
