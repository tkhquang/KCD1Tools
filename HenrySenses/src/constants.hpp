/**
 * @file constants.hpp
 * @brief Central definitions for constants used throughout the mod.
 *
 * This is the KCD1 retarget of the KCD2 Henry's Senses mod. The structure, constant NAMES and comments mirror the
 * KCD2 source, so the two builds stay in lockstep. Only the KCD1-specific binary values differ, and a value that
 * differs carries the KCD2 one in brackets.
 */
#ifndef HENRYSENSES_CONSTANTS_HPP
#define HENRYSENSES_CONSTANTS_HPP

#include "version.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace HenrySenses::constants
{
    // Mod name derived from version.hpp. It is the stem of the INI and log file names and the instance mutex.
    inline constexpr const char *MOD_NAME = HenrySenses::version::MOD_NAME;

    // File extensions.
    inline constexpr const char *INI_FILE_EXTENSION = ".ini";

    /** @brief Gets the INI config filename ("KCD1_HenrySenses.ini"). */
    [[nodiscard]] inline std::string get_config_filename()
    {
        return std::string(MOD_NAME) + INI_FILE_EXTENSION;
    }

    /** @brief Log file name passed to the DetourModKit Session through ModInfo. */
    inline constexpr const char *LOG_FILE_NAME = "KCD1_HenrySenses.log";
    /** @brief Per-PID instance-mutex prefix so duplicate ASI loads bail cleanly. */
    inline constexpr const char *INSTANCE_MUTEX_PREFIX = "KCD1_HenrySenses_";
    /** @brief Default logging level. */
    inline constexpr const char *DEFAULT_LOG_LEVEL = "INFO";

    /// Name of the game module every anchor and offset lives in.
    inline constexpr const char *MODULE_NAME = "WHGame.dll";

    // The signature file beside the ASI: optional repairs of the built-in signatures, merged over them by label.
    inline constexpr const char *SIGNATURE_FILE_SUFFIX = ".signatures.ini";
    // The [Settings] ExportSignatures output: every built-in signature with its captured baselines.
    inline constexpr const char *SIGNATURE_EXPORT_SUFFIX = ".signatures.captured.ini";
    // The signature-contract epoch a signature file must declare. Bump it only when an in-code change makes older
    // signature files incompatible (a renamed label, a dropped signature); a file for another epoch is ignored.
    inline constexpr std::uint32_t SIGNATURE_REVISION = 1;

    // SSystemGlobalEnvironment (gEnv) members. gEnv is an inline struct inside WHGame.dll (AnchorId::Genv), so each
    // interface pointer is read fresh at gEnv + offset: several are null until the engine has created them.
    inline constexpr std::ptrdiff_t GENV_3DENGINE_OFFSET = 0x08;
    // The IParticleManager secondary base of CParticleManager (the object's primary base is 8 bytes before it).
    inline constexpr std::ptrdiff_t GENV_PARTICLE_MANAGER_OFFSET = 0x68;
    inline constexpr std::ptrdiff_t GENV_SYSTEM_OFFSET = 0xC0; // CSystem

    // Local player chain: the CCryAction slot (AnchorId::CryActionFramework) -> CActionGame -> C_Player (validated by
    // RTTI) -> CEntity*. [KCD2 reaches CCryAction through gEnv -> pGame -> IGame::GetIGameFramework.]
    inline constexpr std::ptrdiff_t CCRYACTION_ACTIONGAME_OFFSET = 0x78;    // [KCD2 0x88]
    inline constexpr std::ptrdiff_t CACTIONGAME_LOCAL_ACTOR_OFFSET = 0xA00; // [KCD2 0xA40]
    inline constexpr std::ptrdiff_t C_PLAYER_ENTITY_OFFSET = 0x38;
    // C_ActorModel pointer. The self-heal pairs it with the entity pointer, so a shifted entity offset heals only when
    // both slots agree, never onto an unrelated CEntity neighbour. [KCD2 pairs C_HitDeathReactions at 0x240, which
    // KCD1 C_Player does not have.]
    inline constexpr std::ptrdiff_t C_PLAYER_ACTOR_MODEL_OFFSET = 0x908;

    // CEntity members.
    inline constexpr std::ptrdiff_t ENTITY_WORLD_MATRIX_OFFSET = 0x58; // Matrix34, translation in column 3
    inline constexpr std::ptrdiff_t ENTITY_NAME_OFFSET = 0xE8;         // const char * [KCD2 0xE0]
    // CEntity::GetProxy(this, type) -> IEntityProxy*, vtable slot 67. [KCD2 slot 74]
    inline constexpr std::ptrdiff_t ENTITY_VTABLE_GET_PROXY_OFFSET = 67 * 8;
    // The proxy map key of the render proxy (EEntityProxy::ENTITY_PROXY_RENDER).
    inline constexpr std::uint32_t ENTITY_PROXY_RENDER = 0;
    // Proxy map key of the script proxy, whose vtable slot 17 returns the entity's IScriptTable. [KCD2 slot 18]
    inline constexpr std::uint32_t ENTITY_PROXY_SCRIPT = 2;
    inline constexpr std::ptrdiff_t SCRIPT_PROXY_VTABLE_GET_TABLE_OFFSET = 17 * 8;
    // IScriptTable::GetValueAny(this, key, ScriptAnyValue *value, bool ignoreMeta), vtable slot 8. The value's type
    // (int at +0) asks for a conversion and reports what was read; the payload is at +8.
    inline constexpr std::ptrdiff_t SCRIPT_TABLE_VTABLE_GET_VALUE_ANY_OFFSET = 8 * 8;
    inline constexpr std::int32_t SCRIPT_ANY_BOOLEAN = 2;
    // ANY_THANDLE: a light userdata such as a WUID; the handle is the 64-bit payload.
    inline constexpr std::int32_t SCRIPT_ANY_HANDLE = 3;
    // KCD1 writes at most 0x18 bytes of a value (a vector), so the KCD2 size stays a safe buffer.
    inline constexpr std::size_t SCRIPT_ANY_VALUE_SIZE = 0x20;
    // ScriptAnyValue type of a table. Reading one into an empty value creates an IScriptTable holding one reference,
    // which IScriptTable::Release (vtable slot 4) drops.
    inline constexpr std::int32_t SCRIPT_ANY_TABLE = 6;
    inline constexpr std::ptrdiff_t SCRIPT_TABLE_VTABLE_RELEASE_OFFSET = 4 * 8;
    // CEntity::GetWorldBounds(this, AABB *), vtable slot 33. [KCD2 slot 34]
    inline constexpr std::ptrdiff_t ENTITY_VTABLE_GET_WORLD_BOUNDS_OFFSET = 33 * 8;
    inline constexpr std::ptrdiff_t ENTITY_ID_OFFSET = 0x0C;
    inline constexpr std::ptrdiff_t ENTITY_CLASS_OFFSET = 0x20;      // IEntityClass *
    inline constexpr std::ptrdiff_t ENTITY_CLASS_NAME_OFFSET = 0x10; // IEntityClass -> const char *
    inline constexpr std::ptrdiff_t ENTITY_FLAGS_OFFSET = 0x08;      // uint32 internal flags
    inline constexpr std::uint32_t ENTITY_FLAG_HIDDEN = 0x10;        // entity:Hide() [KCD2 0x20]
    inline constexpr std::uint32_t ENTITY_INVISIBLE_FLAG = 0x40000;  // entity:Invisible() [KCD2 0x10]
    inline constexpr std::uint32_t ENTITY_ACTIVE_FLAG = 0x01;        // entity:Activate()
    // CEntity entity links (ScriptBind GetLink, 0x181D4A84C): singly linked list at +0xD0 of { const char *name;
    // EntityId target; ...; next at +0x18 }.
    inline constexpr std::ptrdiff_t ENTITY_LINKS_OFFSET = 0xD0;
    inline constexpr std::ptrdiff_t ENTITY_LINK_NAME_OFFSET = 0x00;
    inline constexpr std::ptrdiff_t ENTITY_LINK_TARGET_OFFSET = 0x08;
    inline constexpr std::ptrdiff_t ENTITY_LINK_NEXT_OFFSET = 0x18;

    // IEntitySystem (gEnv + GENV_ENTITY_SYSTEM_OFFSET).
    inline constexpr std::ptrdiff_t GENV_ENTITY_SYSTEM_OFFSET = 0xA0;
    // IEntitySystem::GetEntity(EntityId), vtable slot 12. [KCD2 slot 14]
    inline constexpr std::ptrdiff_t ENTITY_SYSTEM_VTABLE_GET_ENTITY_OFFSET = 12 * 8;
    // IEntitySystem::GetEntityIterator(), vtable slot 20. [KCD2 slot 22]
    inline constexpr std::ptrdiff_t ENTITY_SYSTEM_VTABLE_GET_ITERATOR_OFFSET = 20 * 8;
    // IEntityIt vtable slots.
    inline constexpr std::ptrdiff_t ENTITY_IT_VTABLE_ADD_REF_OFFSET = 1 * 8;
    inline constexpr std::ptrdiff_t ENTITY_IT_VTABLE_RELEASE_OFFSET = 2 * 8;
    inline constexpr std::ptrdiff_t ENTITY_IT_VTABLE_IS_END_OFFSET = 3 * 8;
    inline constexpr std::ptrdiff_t ENTITY_IT_VTABLE_NEXT_OFFSET = 4 * 8;
    // CEntitySystem's salt buffer: 24-byte slots {salt u16, next u32, CEntity *}, an EntityId is slot | salt << 17.
    // [KCD2 buffer +0x200, salt << 18, 0x3FFFC last slot, head +0x6001C0, counters +0x6001C8]
    inline constexpr std::ptrdiff_t ENTITY_SYSTEM_SALT_BUFFER_OFFSET = 0x238;
    inline constexpr std::size_t SALT_SLOT_STRIDE = 24;
    inline constexpr std::ptrdiff_t SALT_SLOT_SALT_OFFSET = 0;
    inline constexpr std::ptrdiff_t SALT_SLOT_NEXT_OFFSET = 8;
    inline constexpr std::ptrdiff_t SALT_SLOT_ENTITY_OFFSET = 16;
    inline constexpr std::uint32_t SALT_ID_SALT_SHIFT = 17;
    inline constexpr std::uint32_t SALT_ID_SLOT_MASK = 0x1FFFF;
    inline constexpr std::uint32_t SALT_LAST_SLOT = 0x1FFFC;
    // The used-list head (uint32 slot) and, after it, three insert counters and one delete counter (uint64 each).
    inline constexpr std::ptrdiff_t ENTITY_SYSTEM_SALT_HEAD_OFFSET = 0x3001F8;
    inline constexpr std::ptrdiff_t ENTITY_SYSTEM_SALT_COUNTERS_OFFSET = 0x300200;
    inline constexpr std::size_t SALT_INSERT_COUNTERS = 3;

    // CRenderProxy, the entity render proxy: its primary base is the IRenderNode, and GetProxy(ENTITY_PROXY_RENDER)
    // returns its IEntityRenderProxy base at this offset. [KCD2 0x50]
    inline constexpr std::ptrdiff_t RENDER_PROXY_SECONDARY_OFFSET = 0x48;
    inline constexpr std::ptrdiff_t RENDER_PROXY_SLOTS_BEGIN_OFFSET = 0x88; // CEntityObject ** vector begin
    inline constexpr std::ptrdiff_t RENDER_PROXY_SLOTS_END_OFFSET = 0x90;   // CEntityObject ** vector end
    // The HUD silhouette word (0xRRGGBBAA, 0 = none) of an entity render proxy, m_nHUDSilhouettesParams. The proxy
    // copies it into SRendParams + 0x98 on every render, and CHudSilhouettes draws every object that carries one.
    // [KCD2 IRenderNode + 0x3C on any render node. KCD1 render nodes other than CRenderProxy carry no word.]
    inline constexpr std::ptrdiff_t RENDER_PROXY_HUD_SILHOUETTE_OFFSET = 0xF4;
    // The proxy's custom material (CEntity::SetMaterial), used for every slot without its own, and its flags: any 0x18
    // bit (hidden, invalid bounds) skips the whole render. [CRenderProxy::Render job entry 0x18032538C]
    inline constexpr std::ptrdiff_t RENDER_PROXY_CUSTOM_MATERIAL_OFFSET = 0xB8;
    inline constexpr std::ptrdiff_t RENDER_PROXY_FLAGS_OFFSET = 0xEC;
    inline constexpr std::uint32_t RENDER_PROXY_FLAGS_SKIP_RENDER = 0x18;
    // CEntityObject, one entity slot: the world Matrix34 it draws with, its own material and its u16 flags. Only an
    // ENTITY_SLOT_RENDER slot draws, and a RENDER_NEAREST slot draws in camera space. [CEntityObject::Render
    // 0x180325670]
    inline constexpr std::ptrdiff_t ENTITY_SLOT_WORLD_TM_OFFSET = 0x08;
    inline constexpr std::ptrdiff_t ENTITY_SLOT_MATERIAL_OFFSET = 0xA0;
    inline constexpr std::ptrdiff_t ENTITY_SLOT_FLAGS_OFFSET = 0xAC;
    inline constexpr std::uint16_t ENTITY_SLOT_RENDER = 0x1;
    inline constexpr std::uint16_t ENTITY_SLOT_RENDER_NEAREST = 0x2;
    inline constexpr std::ptrdiff_t ENTITY_SLOT_STAT_OBJ_OFFSET = 0x78;  // CEntityObject -> IStatObj *
    inline constexpr std::ptrdiff_t ENTITY_SLOT_CHARACTER_OFFSET = 0x80; // CEntityObject -> ICharacterInstance *
    inline constexpr std::ptrdiff_t STAT_OBJ_FILE_PATH_OFFSET = 0xA8;    // CStatObj -> const char * [KCD2 0xA0]
    inline constexpr std::ptrdiff_t CHAR_INSTANCE_FILE_PATH_OFFSET =
        0x28C0; // CCharInstance -> const char * [KCD2 0xA38]
    // CEntitySlot child render node (IRenderNode *): the slot's particle emitter, light or geometry-cache node. The
    // slot's GetParticleEmitter (0x1804D1DCC) returns it when its GetRenderNodeType is 8.
    inline constexpr std::ptrdiff_t ENTITY_SLOT_CHILD_RENDER_NODE_OFFSET = 0x90;

    // IParticleManager::FindEffect(this, name, source, bLoadResources) -> IParticleEffect *, vtable slot 6 of the
    // IParticleManager base. It loads the effect's library (Libs/Particles/<library>.xml) on first use and returns
    // null for an unknown or disabled effect.
    inline constexpr std::ptrdiff_t PARTICLE_MANAGER_VTABLE_FIND_EFFECT_OFFSET = 6 * 8;
    // CParticleManager's primary base, 8 bytes before the IParticleManager base gEnv holds.
    inline constexpr std::ptrdiff_t PARTICLE_MANAGER_PRIMARY_DELTA = 8;
    // The live emitter list of CParticleManager (from its primary base): tail, head, then the u32 count at +0x10.
    // Each CParticleEmitter links itself: previous at +0x208, next at +0x210. Level unloads destroy the listed
    // emitters, so a free emitter is touched only after it is found here again. [KCD2 keeps the head first]
    inline constexpr std::ptrdiff_t PARTICLE_MANAGER_EMITTERS_OFFSET = 0x88;  // [KCD2 0x1B8]
    inline constexpr std::ptrdiff_t PARTICLE_EMITTER_LIST_HEAD_OFFSET = 0x08; // [KCD2 0x00]
    inline constexpr std::ptrdiff_t PARTICLE_EMITTER_LIST_COUNT_OFFSET = 0x10;
    inline constexpr std::ptrdiff_t PARTICLE_EMITTER_NEXT_OFFSET = 0x210; // [KCD2 0x250]
    // CParticleEmitter location (QuatTS: quaternion x, y, z, w, position, uniform scale).
    inline constexpr std::ptrdiff_t PARTICLE_EMITTER_LOCATION_OFFSET = 0x78; // [KCD2 0x70]
    // IParticleEmitter::Kill, vtable slot 68: a command thunk that runs the Kill body (AnchorId::EmitterKill) at once
    // or queues it for the emitter's thread. [KCD2 slot 76 holds Kill itself]
    inline constexpr std::ptrdiff_t PARTICLE_EMITTER_VTABLE_KILL_OFFSET = 68 * 8;

    // IParticleManager::LoadLibrary(this, name, XmlNodeRef &library, bLoadResources) -> bool, vtable slot 9 (MSVC
    // puts the overload after LoadLibrary(name, file, bLoadResources), slot 8). Each <Particles> child becomes the
    // effect "<name>.<its Name>" through LoadEffect (slot 7). A level unload clears the loaded libraries and effects.
    // [KCD2 slot 10]
    inline constexpr std::ptrdiff_t PARTICLE_MANAGER_VTABLE_LOAD_LIBRARY_OFFSET = 9 * 8;

    // CSystem's CXmlUtils (CSystem::GetXmlUtils, vtable slot 113, returns it). CXmlUtils::LoadXmlFromBuffer(this,
    // XmlNodeRef *out, buffer, size, bReuseStrings), vtable slot 2. Its text parser builds CXmlNode trees.
    inline constexpr std::ptrdiff_t SYSTEM_XML_UTILS_OFFSET = 0x8B0; // [KCD2 0xA20]
    inline constexpr std::ptrdiff_t XML_UTILS_VTABLE_LOAD_FROM_BUFFER_OFFSET = 2 * 8;
    // CXmlUtils::LoadXmlFromFile(this, XmlNodeRef *out, file, bReuseStrings), vtable slot 1 (mask materials).
    inline constexpr std::ptrdiff_t XML_UTILS_VTABLE_LOAD_FROM_FILE_OFFSET = 1 * 8;
    // IXmlNode reference count: AddRef vtable slot 3, Release slot 4 (what XmlNodeRef's copy and destructor call).
    inline constexpr std::ptrdiff_t XML_NODE_VTABLE_RELEASE_OFFSET = 4 * 8;
    // CXmlNode getAttr(key) (the value, or ""), getChildCount, getChild(XmlNodeRef *out, i), findChild(XmlNodeRef
    // *out, tag) and the string setAttr(key, value): vtable slots 29, 38, 39, 40 and 67 (mask materials).
    inline constexpr std::ptrdiff_t XML_NODE_VTABLE_GET_ATTR_OFFSET = 29 * 8;
    inline constexpr std::ptrdiff_t XML_NODE_VTABLE_GET_CHILD_COUNT_OFFSET = 38 * 8;
    inline constexpr std::ptrdiff_t XML_NODE_VTABLE_GET_CHILD_OFFSET = 39 * 8;
    inline constexpr std::ptrdiff_t XML_NODE_VTABLE_FIND_CHILD_OFFSET = 40 * 8;
    inline constexpr std::ptrdiff_t XML_NODE_VTABLE_SET_ATTR_OFFSET = 67 * 8;

    // The optional particle library beside the ASI ("KCD1_HenrySenses.particles.xml"), registered under this library
    // name, so its effects are "HenrySenses.<Particles Name>".
    inline constexpr const char *PARTICLE_LIBRARY_FILE_SUFFIX = ".particles.xml";
    inline constexpr const char *PARTICLE_LIBRARY_NAME = "HenrySenses";

    // IRenderNode members. [KCD2 flags are a uint64 at +0x28]
    inline constexpr std::ptrdiff_t RENDERNODE_RNDFLAGS_OFFSET = 0x34;    // uint32 render flags (ERF_*)
    inline constexpr std::ptrdiff_t RENDERNODE_OCTREE_NODE_OFFSET = 0x20; // the octree node, 0 when unregistered
    // float m_fWSMaxViewDist: the node is not drawn past this camera distance, whether it sits in the octree or in the
    // always-visible list (that list skips only the occlusion test). RegisterEntity (0x180374B20) sets it from
    // GetMaxViewDist (vtable slot 48) on its full path. [KCD2 +0x48, slot 45]
    inline constexpr std::ptrdiff_t RENDERNODE_MAX_VIEW_DIST_OFFSET = 0x30;
    // u8 m_ucViewDistRatio. GetMaxViewDist of CRenderProxy and CBrush is max(e_ViewDistMin, size * e_ViewDistRatio *
    // ratio / 100), except that 255 counts as 10000 %: a small item is then drawn out to hundreds of metres.
    // (CRenderProxy 0x1804D5D90, CBrush 0x1804D51A4) [KCD2 +0x4D]
    inline constexpr std::ptrdiff_t RENDERNODE_VIEW_DIST_RATIO_OFFSET = 0x40;
    inline constexpr std::uint8_t VIEW_DIST_RATIO_FAR = 255;
    inline constexpr std::uint32_t ERF_RENDER_ALWAYS = 0x10;
    // IRenderNode::Hide (vtable slot 22) toggles this bit of the uint32 flags. [KCD2 uint64 bit]
    inline constexpr std::uint32_t ERF_HIDDEN = 0x100;
    // Set on the render nodes that hold herbs: the merged-mesh cells and the CVegetation mushrooms. The game's herb
    // index registers only a node that carries it (0x180473E88). A picked mushroom keeps it and gains ERF_HIDDEN until
    // it respawns. [KCD2 uint64 bit]
    inline constexpr std::uint32_t ERF_PICKABLE = 0x8000;
    // IRenderNode virtual slots (CBrush vtable 0x1823A2428): 4 GetBBox(this, AABB *out), 7 GetRenderNodeType, 10
    // GetName (a brush's statobj path, an entity proxy's entity name). [KCD2 GetName is slot 9]
    inline constexpr std::ptrdiff_t RENDERNODE_VTABLE_GET_BBOX_OFFSET = 0x20;
    inline constexpr std::ptrdiff_t RENDERNODE_VTABLE_GET_TYPE_OFFSET = 0x38;
    inline constexpr std::ptrdiff_t RENDERNODE_VTABLE_GET_NAME_OFFSET = 0x50; // [KCD2 0x48]
    // GetRenderNodeType values: CBrush 1, CVegetation 2, CRenderProxy 0x13, CMergedMeshRenderNode 0x17. [KCD2 also
    // CMovableBrush 0x11, which KCD1 does not have]
    inline constexpr std::uint32_t RENDERNODE_TYPE_BRUSH = 1;
    inline constexpr std::uint32_t RENDERNODE_TYPE_VEGETATION = 2;
    inline constexpr std::uint32_t RENDERNODE_TYPE_MERGED_MESH = 0x17;
    // CBrush world Matrix34 m_Matrix: the constructor stores identity there, and GetPos (vtable slot 18) reads its
    // translation at +0x54 / +0x64 / +0x74. [KCD2 +0x50. KCD1 has no COwnedBrush or CMovableBrush]
    inline constexpr std::ptrdiff_t BRUSH_MATRIX_OFFSET = 0x48;
    // CBrush material override (IMaterial *, otherwise the model's own) and model (CStatObj *). [CBrush::Render
    // 0x332198]
    inline constexpr std::ptrdiff_t BRUSH_MATERIAL_OFFSET = 0x88;
    inline constexpr std::ptrdiff_t BRUSH_STAT_OBJ_OFFSET = 0x98;

    // I3DEngine (gEnv + GENV_3DENGINE_OFFSET) registration slots. RegisterEntity takes (node, nSID, nSIDSafe).
    // [KCD2 slots 38 and 46]
    inline constexpr std::ptrdiff_t ENGINE_3D_VTABLE_REGISTER_ENTITY_OFFSET = 34 * 8;
    inline constexpr std::ptrdiff_t ENGINE_3D_VTABLE_UNREGISTER_ENTITY_DIRECT_OFFSET = 37 * 8;
    // I3DEngine::SetPostEffectParam(name, float, bool force), vtable slot 161. On the main thread it applies at once,
    // and from any other thread it queues the call. [KCD2 0x560]
    inline constexpr std::ptrdiff_t ENGINE_3D_VTABLE_SET_POST_EFFECT_PARAM_OFFSET = 161 * 8;
    // I3DEngine::GetObjectsInBox(engine, const AABB* box /*6 floats*/, IRenderNode** out) -> uint32 count; a null out
    // returns the count only, otherwise the whole list is copied with no size cap.
    // C3DEngine vtable slots (vtable 0x1827160A8): GetObjectsByTypeInBox(engine, EERType, const AABB*, IRenderNode**
    // out) sits right before GetObjectsInBox. While slot 233 holds the GetObjectsInBox anchor, slot 232 is the typed
    // query. It walks only the octree object list of the type and keeps the nodes of that type. It takes no flag mask,
    // so the mod applies a mask to its result, and ENGINE3D_QUERY_ANY_RNDFLAGS keeps every node. [KCD2 slots 242 and
    // 243, and its typed query takes a uint64 rndFlagsMask fifth argument]
    inline constexpr std::ptrdiff_t ENGINE3D_VTABLE_GET_OBJECTS_BY_TYPE_IN_BOX_OFFSET = 232 * 8;
    inline constexpr std::ptrdiff_t ENGINE3D_VTABLE_GET_OBJECTS_IN_BOX_OFFSET = 233 * 8;
    inline constexpr std::uint64_t ENGINE3D_QUERY_ANY_RNDFLAGS = ~0ull;

    // Herbs. A pickable herb is not an entity. It is an instance of a merged-mesh vegetation group whose model the
    // game's herb table names, and such groups are grass-like patches batched per cell. The PickableArea entity is only
    // a proxy the interaction probe activates on the herb it looks at.
    // CObjManager vegetation group table (AnchorId::ObjManager holds the CObjManager pointer). CObjManager + 0 points
    // to the per-segment PodArray<StatInstGroup> array, and segment 0 holds the level's groups as {StatInstGroup *,
    // int count}. A group is 0x190 bytes with its CStatObj * at +0. [KCD2 std::vector at CObjManager + 0x10 / + 0x18
    // of 0x1A0-byte groups]
    inline constexpr std::ptrdiff_t OBJMAN_VEG_SEGMENTS_OFFSET = 0x00;
    inline constexpr std::ptrdiff_t VEG_SEGMENT_GROUPS_BEGIN_OFFSET = 0x00;
    inline constexpr std::ptrdiff_t VEG_SEGMENT_GROUPS_COUNT_OFFSET = 0x08; // int32
    inline constexpr std::size_t VEG_GROUP_STRIDE = 0x190;                  // [KCD2 0x1A0]
    // Vegetation group entry: CStatObj * at +0.
    inline constexpr std::ptrdiff_t VEG_GROUP_STAT_OBJ_OFFSET = 0x00;
    // CStatObj model path (char *, IStatObj::GetFilePath at vtable slot 45). The herb identity hashes it, and the log
    // names each herb group with it. [KCD2 0xA0]
    inline constexpr std::ptrdiff_t STATOBJ_PATH_OFFSET = 0xA8;
    // Herb identity. KCD1 has no per-group pickable flag. [KCD2 StatInstGroup bPickable, ERF_PICKABLE at group +0x199]
    // The game names a herb by its model: the herb-type lookup (AnchorId::HerbType, 0x1806BDEE0) maps the model-path
    // hash (0x1802D3114) to a herb type byte. The hash is the CRC-32 of the path with A-Z lowercased. A hash the table
    // lacks gets a default record of type 0. Type 0 and type 0xFF both mean no herb, as the game's wrapper
    // (0x1806BDEC4) reads them. The merged-mesh pick loop (0x181734078) and the mushroom index (0x18047432C) identify
    // herbs this way.
    inline constexpr std::uint8_t HERB_TYPE_NONE = 0x00;
    inline constexpr std::uint8_t HERB_TYPE_INVALID = 0xFF;
    // Longest model path the herb identity hashes. A longer path counts as no herb.
    inline constexpr std::size_t HERB_MODEL_PATH_MAX = 512;
    // CMergedMeshRenderNode (primary base IRenderNode, IMergedMeshRenderNode at +0x48). Instance positions are 16-bit
    // fractions of the cell: world = internalAABB.min + u16 / 65535 * (internalAABB.max.x - internalAABB.min.x),
    // rotated about m_pos by m_zRotation (0x180324A38). A KCD1 cell is e_MergedMeshesExtent wide, 16 m by default.
    inline constexpr std::ptrdiff_t MERGED_MESH_AABB_MIN_OFFSET = 0x84; // [KCD2 0x8C]
    inline constexpr std::ptrdiff_t MERGED_MESH_AABB_MAX_OFFSET = 0x90; // [KCD2 0x98]
    // m_visibleAABB, what GetBBox (vtable slot 19, behind the slot 4 wrapper) and FillBBox (slot 5,
    // 0x1804D6A70) return, and what the octree's box test compares.
    inline constexpr std::ptrdiff_t MERGED_MESH_VISIBLE_AABB_MIN_OFFSET = 0x9C; // [KCD2 0xA4]
    inline constexpr std::ptrdiff_t MERGED_MESH_VISIBLE_AABB_MAX_OFFSET = 0xA8; // [KCD2 0xB0]
    inline constexpr std::ptrdiff_t MERGED_MESH_POS_OFFSET = 0xB4;              // [KCD2 0xBC]
    inline constexpr std::ptrdiff_t MERGED_MESH_ZROTATION_OFFSET = 0xCC;        // [KCD2 0xD4]
    inline constexpr std::ptrdiff_t MERGED_MESH_GROUPS_OFFSET = 0xE0;           // SMMRMGroupHeader * [KCD2 0xF0]
    inline constexpr std::ptrdiff_t MERGED_MESH_GROUP_COUNT_OFFSET = 0xE8;      // u32 [KCD2 0xF8]
    // u32 m_State. The game picks herbs only from a cell in STREAMED_IN, and the pick iterator (0x181734078) bails
    // otherwise. In any other state the engine builds or streams the cell, and its instances can be missing.
    inline constexpr std::ptrdiff_t MERGED_MESH_STATE_OFFSET = 0x60; // [KCD2 0x6C]
    inline constexpr std::uint32_t MERGED_MESH_STATE_STREAMED_IN = 5;
    // SMMRMGroupHeader, 0x70 bytes: instance array, geometry, vegetation group index, instance count. [KCD2 0x80 bytes,
    // instance count at +0x54]
    inline constexpr std::size_t MERGED_MESH_GROUP_STRIDE = 0x70;
    inline constexpr std::ptrdiff_t MERGED_MESH_GROUP_INSTANCES_OFFSET = 0x00;
    inline constexpr std::ptrdiff_t MERGED_MESH_GROUP_VEG_INDEX_OFFSET = 0x4C;
    inline constexpr std::ptrdiff_t MERGED_MESH_GROUP_SAMPLE_COUNT_OFFSET = 0x50;
    // The group's SMMRMGeometry *, which decides the group's model (0x181734410). With bit 0 of its flag byte set, the
    // geometry's own CStatObj is the model. Otherwise the vegetation group's CStatObj is. The game skips a group
    // without geometry.
    inline constexpr std::ptrdiff_t MERGED_MESH_GROUP_GEOMETRY_OFFSET = 0x18;
    inline constexpr std::ptrdiff_t MERGED_MESH_GEOMETRY_STAT_OBJ_OFFSET = 0xC0;
    inline constexpr std::ptrdiff_t MERGED_MESH_GEOMETRY_FLAGS_OFFSET = 0x528;
    inline constexpr std::uint8_t MERGED_MESH_GEOMETRY_FLAG_OWN_STAT_OBJ = 0x01;
    // SMMRMInstance, 16 bytes: u16 x, y, z at 0/2/4 and the scale byte at 12. A pick zeroes the scale (0x181742D50)
    // and a respawn restores it from byte 14 (the original scale). So scale 0 means picked.
    inline constexpr std::size_t MERGED_MESH_INSTANCE_SIZE = 16;
    inline constexpr std::size_t MERGED_MESH_INSTANCE_SCALE_OFFSET = 12;
    // int8 quaternion x, y, z, w (0x1805A5020: each / 128, then normalized). The scale byte is / 64
    // (VEGETATION_CONV_FACTOR).
    inline constexpr std::size_t MERGED_MESH_INSTANCE_QUAT_OFFSET = 6;
    inline constexpr float VEGETATION_CONV_FACTOR = 64.0f;
    // CMergedMeshesManager (AnchorId::MergedMeshesManager holds the pointer): the engine's own index of every
    // merged-mesh cell, m_Nodes[32][32][2] of 24-byte std::vector<CMergedMeshRenderNode *> ({begin, end, capacity}) at
    // +0x08. FindNode (vtable slot 3, 0x18173D9B4) files a cell under ((int)(|z| / e) & 1) + 2 * (32 * ((int)(|x| / e)
    // & 31) + ((int)(|y| / e) & 31)), with e the e_MergedMeshesExtent cvar. So the buckets wrap every 32 cells and hold
    // the cells of the whole streamed area. [KCD2 FindNode slot 6 with a fixed 16 m cell, and the manager found by RTTI
    // next to the CObjManager slot]
    inline constexpr std::ptrdiff_t MERGED_MESHES_MANAGER_BUCKETS_OFFSET = 0x08;
    inline constexpr std::size_t MERGED_MESHES_MANAGER_BUCKET_STRIDE = 24;
    inline constexpr std::uint32_t MERGED_MESHES_HASH_DIM_XY = 32;
    inline constexpr std::uint32_t MERGED_MESHES_HASH_DIM_Z = 2;
    // The e_MergedMeshesExtent default. A changed cvar files the cells elsewhere, and the cross-check against the
    // octree then keeps the octree query.
    inline constexpr float MERGED_MESHES_HASH_CELL_SIZE = 16.0f;
    // CVegetation (a vegetation instance the engine does not merge: the pickable mushrooms). Vec3 m_vPos at +0x48
    // (GetPos, vtable slot 18), the vegetation group index (int) at +0x68 (vtable slot 45). Vtable slot 23 is
    // GetEntityStatObj(this, u32 part, u32 sub_part, Matrix34 *out, bool visible_only) (0x1803FBF28). It writes the
    // instance's world matrix and returns the group's CStatObj. [KCD2 m_vPos +0x50, group +0x78, slot 22 without
    // sub_part]
    inline constexpr std::ptrdiff_t VEGETATION_POSITION_OFFSET = 0x48;
    inline constexpr std::ptrdiff_t VEGETATION_GROUP_INDEX_OFFSET = 0x68;
    inline constexpr std::ptrdiff_t VEGETATION_VTABLE_GET_ENTITY_STAT_OBJ_OFFSET = 23 * 8;
    // Plants of one species closer than this to a cluster's first plant are one pick, so they share one marker.
    inline constexpr float HERB_CLUSTER_RADIUS = 1.0f;
    // Height of the marker box above the plants' base, meters.
    inline constexpr float HERB_MARKER_HEIGHT = 0.5f;
    // Horizontal padding of the marker box around the cluster's plants, meters.
    inline constexpr float HERB_MARKER_PADDING = 0.2f;
    // Corruption guards on one herb query: octree nodes returned for the box, groups per cell, samples per group, cells
    // per manager bucket, pickable vegetation nodes. Each sits far above any real count, since a real count past one
    // would drop herbs inside the radius (a cell cannot hold more groups than the level's ~600).
    inline constexpr std::uint32_t HERB_MAX_OCTREE_NODES = 65536;
    inline constexpr std::uint32_t HERB_MAX_GROUPS_PER_CELL = 1024;
    inline constexpr std::uint32_t HERB_MAX_SAMPLES_PER_GROUP = 65536;
    inline constexpr std::uint32_t HERB_MAX_CELLS_PER_BUCKET = 1024;
    inline constexpr std::uint32_t HERB_MAX_VEGETATION_NODES = 65536;

    // Global context (AnchorId::Context) members used by the dialogue / combat / minigame gates.
    inline constexpr std::ptrdiff_t OFFSET_MANAGER_PTR_STORAGE = 0x38; // context -> wh::game::C_CameraManager
    inline constexpr std::ptrdiff_t OFFSET_ACTIVE_CAMERA = 0x10;       // camera manager -> active camera [KCD2 0x30]
    inline constexpr std::ptrdiff_t OFFSET_CAMERA_TYPE_ID = 0x08;      // camera -> int type id
    inline constexpr std::int32_t CAMERA_TYPE_DIALOG = 2;              // type id of the dialogue camera
    inline constexpr std::int32_t CAMERA_TYPE_COMBAT = 3;              // type id of the combat camera
    inline constexpr std::ptrdiff_t OFFSET_MINIGAME_SUBSYSTEM = 0xE8;  // context -> C_PlayerModule [KCD2 0x128]
    inline constexpr std::ptrdiff_t OFFSET_MINIGAME_MAP = 0x98; // C_PlayerModule -> std::map<actorId, C_Minigame *>
    inline constexpr std::ptrdiff_t OFFSET_MINIGAME_MAP_SIZE = 0x08; // map -> _Mysize (0 = no minigame)

    // Gameplay natives (engine/game_natives.hpp). The global context is a module registry.
    inline constexpr std::ptrdiff_t CONTEXT_ENTITY_MODULE_OFFSET = 0xB0; // wh::entitymodule::C_EntityModule [KCD2 0xE0]
    // wh::rpgmodule::C_SoulList, which the C_RPGModule constructor stores in the context. [KCD2 reaches the souls
    // through C_RPGModule at +0x130]
    inline constexpr std::ptrdiff_t CONTEXT_SOUL_LIST_OFFSET = 0x158;
    // CCryAction: the actor system (IGameFramework::GetIActorSystem returns it) and the item system, whose
    // IItemSystem interface sits at +8 (IGameFramework::GetIItemSystem). [KCD2 0x518 and 0x520]
    inline constexpr std::ptrdiff_t CRYACTION_ACTOR_SYSTEM_OFFSET = 0x508;
    inline constexpr std::ptrdiff_t CRYACTION_ITEM_SYSTEM_OFFSET = 0x510;
    inline constexpr std::ptrdiff_t ITEM_SYSTEM_INTERFACE_OFFSET = 0x08;
    // CActorSystem: EntityId -> IActor* hash map. Its list sentinel is at +0x40; a list node is { next, prev,
    // EntityId key at +0x10, IActor * at +0x18 }. IActorSystem::GetActor(this, id) is vtable slot 3.
    inline constexpr std::ptrdiff_t ACTOR_SYSTEM_LIST_HEAD_OFFSET = 0x40;
    inline constexpr std::ptrdiff_t ACTOR_NODE_KEY_OFFSET = 0x10;
    inline constexpr std::ptrdiff_t ACTOR_NODE_VALUE_OFFSET = 0x18;
    inline constexpr std::ptrdiff_t ACTOR_SYSTEM_VTABLE_GET_ACTOR_OFFSET = 3 * 8;
    // IItemSystem (interface): std::map<EntityId, IItem *> head node at +0x70; a tree node is { left, parent, right,
    // colour u8 at +0x18, is-nil u8 at +0x19, EntityId key at +0x20, IItem * at +0x28 }. GetItem(this, id) is
    // vtable slot 21.
    inline constexpr std::ptrdiff_t ITEM_MAP_HEAD_OFFSET = 0x70;
    // The map's element count follows its head (MSVC _Tree_val { _Myhead, _Mysize }). AddItem (slot 19) adds one in
    // the emplace sub_1802BE37C, and RemoveItem (slot 20) takes one off in the erase sub_18068DACC. [KCD2
    // sub_180707460 and sub_1808E037C]
    inline constexpr std::ptrdiff_t ITEM_MAP_SIZE_OFFSET = ITEM_MAP_HEAD_OFFSET + 0x08;
    inline constexpr std::ptrdiff_t ITEM_NODE_IS_NIL_OFFSET = 0x19;
    inline constexpr std::ptrdiff_t ITEM_NODE_KEY_OFFSET = 0x20;
    inline constexpr std::ptrdiff_t ITEM_NODE_VALUE_OFFSET = 0x28;
    inline constexpr std::ptrdiff_t ITEM_SYSTEM_VTABLE_GET_ITEM_OFFSET = 21 * 8;
    // Actor (C_Actor): CEntity * at +0x38 and C_Soul * at +0x650, GetHealth (float) at vtable slot 28. KCD1 has no
    // IsDead virtual: BasicActor:IsDead() is GetHealth() <= 0. The mod calls C_Actor::CanLoot itself
    // (AnchorId::CanLoot). [KCD2 soul +0x668, GetHealth slot 30, IsDead slot 38, CanLoot rebuilt from the actor state]
    inline constexpr std::ptrdiff_t ACTOR_ENTITY_OFFSET = 0x38;
    inline constexpr std::ptrdiff_t ACTOR_SOUL_OFFSET = 0x650;
    inline constexpr std::ptrdiff_t ACTOR_VTABLE_GET_HEALTH_OFFSET = 28 * 8;
    // C_Soul: WUID at +0x20, C_Inventory * at +0xC08, vtable slot 6 IsUnconscious (soul stat 53 at 0). The entity's
    // inventory script table binds that C_Inventory. [KCD2 WUID +0x30, inventory holder slot 60, IsUnconscious slot 7]
    inline constexpr std::ptrdiff_t SOUL_WUID_OFFSET = 0x20;
    inline constexpr std::ptrdiff_t SOUL_INVENTORY_OFFSET = 0xC08;
    inline constexpr std::ptrdiff_t SOUL_VTABLE_IS_UNCONSCIOUS_OFFSET = 6 * 8;
    // A dead body's loot from its soul class. Every KCD1 animal class postpones its default inventory preset, so the
    // carcass inventory stays empty until the first loot. Then C_RPGInventory slot 0 (0x1811C6C5C, reached from
    // actor:RequestItemExchange) adds the preset once and sets the u8 at +0x538 (saved with the soul). The engine runs
    // it only while the soul health (float +0x504) is 0 or below. The soul_class row (+0xBD8) keeps the preset GUID at
    // +0x10, all zero for a class without one. [KCD2 the butcher action]
    inline constexpr std::ptrdiff_t SOUL_HEALTH_OFFSET = 0x504;
    inline constexpr std::ptrdiff_t SOUL_LOOT_GENERATED_OFFSET = 0x538;
    inline constexpr std::ptrdiff_t SOUL_CLASS_ROW_OFFSET = 0xBD8;
    inline constexpr std::ptrdiff_t SOUL_CLASS_DEFAULT_PRESET_OFFSET = 0x10;
    // C_Soul vtable slot 29 (0x1811F608C): the location of the faction of the soul's root soul, or null. The loot
    // window names the owner of an item to steal only when it is non-null, and shows "take" otherwise. Slot 53
    // (0x18023B6BC) HasAbility(id). Ability 55 is HuntingPermit (perk hunting_permit).
    inline constexpr std::ptrdiff_t SOUL_VTABLE_FACTION_LOCATION_OFFSET = 29 * 8;
    inline constexpr std::ptrdiff_t SOUL_VTABLE_HAS_ABILITY_OFFSET = 53 * 8;
    inline constexpr std::uint32_t SOUL_ABILITY_HUNTING_PERMIT = 55;
    // C_FactionManager (AnchorId::FactionManager), vtable slot 14 (AnchorId::PublicEnemyRelation): the float relation
    // of a faction to a soul's faction. RPG.IsPublicEnemy asks it for faction 3 and calls a relation below 0 an enemy.
    // [KCD2 asks the soul's reputation component (soul slot 50) for AnchorId::PublicEnemyTag]
    inline constexpr std::ptrdiff_t FACTION_MANAGER_VTABLE_RELATION_OFFSET = 14 * 8;
    inline constexpr std::int32_t PUBLIC_ENEMY_FACTION = 3;
    // C_Inventory has no vtable and no RTTI. Its WUID is at +0x00, its item set's count (_Mysize) at +0x70, and its
    // read-only byte at +0xA3. EntityModule.CanUseInventory opens a read-only inventory only while it holds an item.
    // [KCD2 a vtable'd C_Inventory: items vector +0x08..+0x10, interface +0xE8, lockable +0x179]
    inline constexpr std::ptrdiff_t INVENTORY_WUID_OFFSET = 0x00;
    inline constexpr std::ptrdiff_t INVENTORY_ITEM_COUNT_OFFSET = 0x70;
    inline constexpr std::ptrdiff_t INVENTORY_READ_ONLY_OFFSET = 0xA3;
    // WUID handle tables: the inventory manager (C_EntityModule + 0x108) keeps one at +0x10, the C_SoulList one at
    // +0x48. Entry i has its generation (u16) at table + 16 * i + 0x28 and the object at table + 16 * i + 0x30. A WUID
    // is { u16 index, u16 generation, ..., u8 type in the top byte }. [KCD2 inventory manager +0xE8, table +0x28,
    // soul table at *(C_RPGModule + 0x80) + 0x38]
    inline constexpr std::ptrdiff_t ENTITY_MODULE_INVENTORY_MANAGER_OFFSET = 0x108;
    inline constexpr std::ptrdiff_t INVENTORY_MANAGER_TABLE_OFFSET = 0x10;
    inline constexpr std::ptrdiff_t SOUL_MANAGER_TABLE_OFFSET = 0x48;
    inline constexpr std::ptrdiff_t WUID_TABLE_GENERATION_OFFSET = 0x28;
    inline constexpr std::ptrdiff_t WUID_TABLE_OBJECT_OFFSET = 0x30;
    inline constexpr std::size_t WUID_TABLE_STRIDE = 0x10;
    inline constexpr std::uint8_t WUID_TYPE_ITEM = 2;
    inline constexpr std::uint8_t WUID_TYPE_INVENTORY = 3;
    inline constexpr std::uint8_t WUID_TYPE_SOUL = 5;
    // The invalid WUID: an inventory without an owner, an item in no inventory. The game copies it from
    // qword_18300F940 and qword_18300F8D0, which sit in zero-filled .data with no writer, so it is 0. IDA shows those
    // unloaded bytes as 0xFF.
    inline constexpr std::uint64_t WUID_INVALID = 0;
    // C_ItemManager (C_EntityModule + 0x110) keeps the items in a salt buffer at +0x40: 24-byte slots { u16 salt,
    // ..., C_Item * at +0x10 }. An item WUID keeps the slot (1 to 0x1C138) in its low 17 bits and the salt above them.
    // [KCD2 keeps a C_Item * in the world item]
    inline constexpr std::ptrdiff_t ENTITY_MODULE_ITEM_MANAGER_OFFSET = 0x110;
    inline constexpr std::ptrdiff_t ITEM_MANAGER_SALT_BUFFER_OFFSET = 0x40;
    inline constexpr std::size_t ITEM_SALT_SLOT_STRIDE = 24;
    inline constexpr std::ptrdiff_t ITEM_SALT_SLOT_ITEM_OFFSET = 0x10;
    inline constexpr std::uint32_t ITEM_WUID_SLOT_BITS = 17;
    inline constexpr std::uint32_t ITEM_SALT_LAST_SLOT = 0x1C138;
    // C_PickableItem: the WUID of its C_Item at +0x58, in-use bit 0 of the byte at +0x60, vtable slot 92
    // CanSteal(user). C_Item: WUID at +0x08, class (S_ItemData *) at +0x20, flags u32 at +0x48 (0x4 = shop goods).
    // The class's vtable slot 1 returns its type flags. The C_Item keeps the WUID of the inventory that holds it at
    // +0x68 (WUID_INVALID in none). [KCD2 C_Item * at +0x58, CanSteal slot 91, class +0x48 with IsA slot 3, flags
    // +0x60, owner +0x98, else +0x90]
    inline constexpr std::ptrdiff_t PICKABLE_ITEM_ENTITY_OFFSET = 0x38;
    inline constexpr std::ptrdiff_t PICKABLE_ITEM_DATA_OFFSET = 0x58;
    inline constexpr std::ptrdiff_t PICKABLE_ITEM_STATE_OFFSET = 0x60;
    inline constexpr std::uint8_t PICKABLE_ITEM_IN_USE = 0x01;
    inline constexpr std::ptrdiff_t PICKABLE_ITEM_VTABLE_CAN_STEAL_OFFSET = 92 * 8;
    inline constexpr std::ptrdiff_t ITEM_WUID_OFFSET = 0x08;
    inline constexpr std::ptrdiff_t ITEM_CLASS_OFFSET = 0x20;
    inline constexpr std::ptrdiff_t ITEM_FLAGS_OFFSET = 0x48;
    inline constexpr std::uint32_t ITEM_FLAG_SHOP = 0x4;
    inline constexpr std::ptrdiff_t ITEM_INVENTORY_OFFSET = 0x68;
    inline constexpr std::ptrdiff_t ITEM_CLASS_VTABLE_FLAGS_OFFSET = 1 * 8;
    // item:CanUse accepts only items whose class carries this type flag (PlayerItem). [KCD2 IsA id 25]
    inline constexpr std::uint32_t ITEM_CLASS_PLAYER_ITEM = 0x4;

    // MSVC decorated RTTI type names of the classes the mod identifies by vtable.
    inline constexpr const char *C_PLAYER_RTTI_NAME = ".?AVC_Player@entitymodule@wh@@";
    inline constexpr const char *CACTIONGAME_RTTI_NAME = ".?AVCActionGame@@";
    inline constexpr const char *C_ENTITY_RTTI_NAME = ".?AVCEntity@@";
    inline constexpr const char *C_ACTOR_MODEL_RTTI_NAME = ".?AVC_ActorModel@entitymodule@wh@@";
    inline constexpr const char *C_CAMERA_MANAGER_RTTI_NAME = ".?AVC_CameraManager@game@wh@@";
    inline constexpr const char *C_PLAYER_MODULE_RTTI_NAME = ".?AVC_PlayerModule@playermodule@wh@@";
    inline constexpr const char *C_CRY_ACTION_RTTI_NAME = ".?AVCCryAction@@";
    inline constexpr const char *C_RENDER_PROXY_RTTI_NAME = ".?AVCRenderProxy@@";
    inline constexpr const char *C_ENTITY_SYSTEM_RTTI_NAME = ".?AVCEntitySystem@@";
    inline constexpr const char *C_3DENGINE_RTTI_NAME = ".?AVC3DEngine@@";
    inline constexpr const char *C_CHAR_INSTANCE_RTTI_NAME = ".?AVCCharInstance@@";
    inline constexpr const char *C_HUD_SILHOUETTES_RTTI_NAME = ".?AVCHudSilhouettes@@";
    inline constexpr const char *C_MAT_MAN_RTTI_NAME = ".?AVCMatMan@@";
    inline constexpr const char *C_MAT_INFO_RTTI_NAME = ".?AVCMatInfo@@";
    inline constexpr const char *C_BRUSH_RTTI_NAME = ".?AVCBrush@@";
    // Actors and the gameplay objects engine/game_natives.hpp reads.
    inline constexpr const char *C_NPC_ACTOR_RTTI_NAME = ".?AVC_NPCActor@entitymodule@wh@@";
    inline constexpr const char *C_HORSE_RTTI_NAME = ".?AVC_Horse@entitymodule@wh@@";
    inline constexpr const char *C_DOG_RTTI_NAME = ".?AVC_Dog@entitymodule@wh@@";
    inline constexpr const char *C_ANIMAL_RTTI_NAME = ".?AVC_Animal@entitymodule@wh@@";
    inline constexpr const char *C_SOUL_RTTI_NAME = ".?AVC_Soul@rpgmodule@wh@@";
    inline constexpr const char *C_PICKABLE_ITEM_RTTI_NAME = ".?AVC_PickableItem@entitymodule@wh@@";
    inline constexpr const char *C_ITEM_RTTI_NAME = ".?AVC_Item@entitymodule@wh@@";
    inline constexpr const char *C_ACTOR_SYSTEM_RTTI_NAME = ".?AVCActorSystem@@";
    inline constexpr const char *C_ITEM_SYSTEM_RTTI_NAME = ".?AVCItemSystem@@";
    inline constexpr const char *C_ENTITY_MODULE_RTTI_NAME = ".?AVC_EntityModule@entitymodule@wh@@";
    inline constexpr const char *C_INVENTORY_MANAGER_RTTI_NAME = ".?AVC_InventoryManager@entitymodule@wh@@";
    // KCD1 gameplay objects without a KCD2 counterpart in the mod: the item and soul tables and the faction relations.
    inline constexpr const char *C_ITEM_MANAGER_RTTI_NAME = ".?AVC_ItemManager@entitymodule@wh@@";
    inline constexpr const char *C_SOUL_LIST_RTTI_NAME = ".?AVC_SoulList@rpgmodule@wh@@";
    inline constexpr const char *C_FACTION_MANAGER_RTTI_NAME = ".?AVC_FactionManager@rpgmodule@wh@@";
    // The engine's parsed XML node (the tree of the mod's particle library).
    inline constexpr const char *C_XML_NODE_RTTI_NAME = ".?AVCXmlNode@@";
    // Loot effects: the legacy (pfx1) emitter an entity slot holds.
    inline constexpr const char *C_PARTICLE_EMITTER_RTTI_NAME = ".?AVCParticleEmitter@@";
    inline constexpr const char *C_PARTICLE_MANAGER_RTTI_NAME = ".?AVCParticleManager@@";
    // The mod's particle library: the XML utilities that parse it and the node tree they build.
    inline constexpr const char *C_XML_UTILS_RTTI_NAME = ".?AVCXmlUtils@@";
    // Herbs: a merged-mesh cell, the merged-mesh cell index and an unmerged vegetation instance (the pickable
    // mushrooms).
    inline constexpr const char *C_MERGED_MESH_NODE_RTTI_NAME = ".?AVCMergedMeshRenderNode@@";
    inline constexpr const char *C_MERGED_MESHES_MANAGER_RTTI_NAME = ".?AVCMergedMeshesManager@@";
    inline constexpr const char *C_VEGETATION_RTTI_NAME = ".?AVCVegetation@@";

    // CHudSilhouettes, reached through the renderer (AnchorId::RenDev): the post-effects manager and its effect list.
    inline constexpr std::ptrdiff_t RENDERER_POST_EFFECTS_MGR_OFFSET = 0xEF68;    // CD3D9Renderer -> CPostEffectsMgr *
    inline constexpr std::ptrdiff_t POST_EFFECTS_MGR_EFFECTS_BEGIN_OFFSET = 0xA8; // CPostEffect ** vector begin
    inline constexpr std::ptrdiff_t POST_EFFECTS_MGR_EFFECTS_END_OFFSET = 0xB0;   // CPostEffect ** vector end
    // CHudSilhouettes members: the parameter objects and the "optimised technique compiled" byte.
    inline constexpr std::ptrdiff_t HUD_SILHOUETTES_AMOUNT_OFFSET = 0x30;     // CParamFloat *
    inline constexpr std::ptrdiff_t HUD_SILHOUETTES_FILL_STR_OFFSET = 0x38;   // CParamFloat *
    inline constexpr std::ptrdiff_t HUD_SILHOUETTES_TYPE_OFFSET = 0x40;       // CParamInt *
    inline constexpr std::ptrdiff_t HUD_SILHOUETTES_TECH_READY_OFFSET = 0x50; // uint8
    // The value of a CParamFloat or CParamInt (the main-thread copy).
    inline constexpr std::ptrdiff_t POST_EFFECT_PARAM_VALUE_OFFSET = 0x08;
    // The render-state bit that turns the depth test off (FX_SetState clears DepthEnable for it). The mask-pass hook
    // ORs it into the renderer's ForceStateOr for the HUD silhouette mask draw. [KCD2 0x800000]
    inline constexpr std::uint32_t GS_NODEPTHTEST = 0x40000;
    // SRendParams, the render parameters CStatObj::Render (vtable slot 36) fills a temporary render object from. The
    // mod builds one per outline copy. [KCD2 word +0x78, flags +0x68, no material override or sorter]
    inline constexpr std::size_t SRENDPARAMS_BUFFER_SIZE = 0x100;             // the struct is 0xDC bytes
    inline constexpr std::ptrdiff_t SRENDPARAMS_MATRIX_OFFSET = 0x00;         // const Matrix34 *, copied
    inline constexpr std::ptrdiff_t SRENDPARAMS_MATERIAL_OFFSET = 0x28;       // IMaterial * override
    inline constexpr std::ptrdiff_t SRENDPARAMS_ALPHA_OFFSET = 0x7C;          // float, below 1 is transparent
    inline constexpr std::ptrdiff_t SRENDPARAMS_DISTANCE_OFFSET = 0x80;       // float camera distance (sort key)
    inline constexpr std::ptrdiff_t SRENDPARAMS_QUALITY_OFFSET = 0x84;        // float, times 65535
    inline constexpr std::ptrdiff_t SRENDPARAMS_HUD_SILHOUETTE_OFFSET = 0x98; // uint32 word, to the object data +0x60
    inline constexpr std::ptrdiff_t SRENDPARAMS_LOD_OFFSET = 0xC6;            // CLodValue {int16 lod, int16 lodB}
    inline constexpr std::ptrdiff_t SRENDPARAMS_AFTER_WATER_OFFSET = 0xCF;    // uint8
    inline constexpr std::ptrdiff_t SRENDPARAMS_SORTER_OFFSET = 0xD4;         // uint32 render-item sorter
    // SRenderingPassInfo: the pass a static-mesh render runs in.
    inline constexpr std::ptrdiff_t PASS_INFO_RECURSION_OFFSET = 0x01; // uint8 render stack level (0 = main view)
    inline constexpr std::ptrdiff_t PASS_INFO_SHADOW_OFFSET = 0x02;    // uint8 shadow-map rendering (0 = none)
    inline constexpr std::ptrdiff_t PASS_INFO_FRAME_ID_OFFSET = 0x10;  // int32 render frame id
    inline constexpr std::ptrdiff_t PASS_INFO_CAMERA_OFFSET = 0x18;    // const CCamera *
    // CCamera starts with its world Matrix34: the translation column is the position.
    inline constexpr std::ptrdiff_t CAMERA_POSITION_X_OFFSET = 0x0C;
    inline constexpr std::ptrdiff_t CAMERA_POSITION_Y_OFFSET = 0x1C;
    inline constexpr std::ptrdiff_t CAMERA_POSITION_Z_OFFSET = 0x2C;
    // An outline copy's alpha: low enough to stay invisible in the scene, and not 0, which EF_AddEf drops.
    inline constexpr float HERB_PROXY_ALPHA = 0.01f;
    // With the mask depth test on, a herb copy is pulled this far toward the camera, so its wind-bent original does
    // not hide it. The pull scales the copy about the camera, so it covers the same pixels.
    // The scale stays at least HERB_DEPTH_PULL_MIN_SCALE.
    inline constexpr float HERB_DEPTH_PULL = 0.25f;
    inline constexpr float HERB_DEPTH_PULL_MIN_SCALE = 0.5f;
    // CStatObj flags word and its merged-mesh deformation bit: RenderObject skips LOD 0 of such a model.
    inline constexpr std::ptrdiff_t STAT_OBJ_FLAGS2_OFFSET = 0x16C;
    inline constexpr std::uint32_t STAT_OBJ_MERGED_DEFORM_FLAG = 0x400000;
    // I3DEngine::GetMaterialManager, vtable slot 189. CMatMan::LoadMaterialFromXml(this, name, XmlNodeRef node),
    // vtable slot 8: it reuses a material of that name, and it Releases the node (passed by value, so by address).
    inline constexpr std::ptrdiff_t ENGINE_3D_VTABLE_GET_MATERIAL_MANAGER_OFFSET = 189 * 8;
    inline constexpr std::ptrdiff_t MAT_MAN_VTABLE_LOAD_FROM_XML_OFFSET = 8 * 8;
    // CMatInfo AddRef and Release, vtable slots 1 and 2 (the count at +0x4C). Release at 0 defers the delete through
    // the material manager, so a render list that still holds the pointer stays valid. The name (char *) is at +0x38.
    inline constexpr std::ptrdiff_t MAT_INFO_VTABLE_ADD_REF_OFFSET = 1 * 8;
    inline constexpr std::ptrdiff_t MAT_INFO_VTABLE_RELEASE_OFFSET = 2 * 8;
    inline constexpr std::ptrdiff_t MAT_INFO_NAME_OFFSET = 0x38;
    // The CustomRenderPass test of EF_BatchFlags (0x180529E00), read without calls. CMatInfo: flags at +0x50 (0x100 =
    // it has sub-materials), its SShaderItem at +0x58 and its sub-materials (CMatInfo **) at +0x70. The sub-material
    // count is the u32 before the first element. SShaderItem: CShader * +0x00, resources +0x08, technique index +0x10
    // (int32, below 0 picks 0), preprocess flags +0x14 (-1 draws nothing). CShader: flags +0x34 (EF_NODRAW 0x8), flags2
    // +0x38 (EF2_NODRAW 0x10), technique array +0x50 and its u32 count +0x58. A technique keeps the index of its
    // CustomRenderPass technique in the int8 at +0x2C, -1 when it has none (Vegetation).
    inline constexpr std::ptrdiff_t MAT_INFO_FLAGS_OFFSET = 0x50;
    inline constexpr std::uint32_t MTL_FLAG_MULTI_SUBMTL = 0x100;
    inline constexpr std::ptrdiff_t MAT_INFO_SHADER_ITEM_OFFSET = 0x58;
    inline constexpr std::ptrdiff_t MAT_INFO_SUB_MTLS_OFFSET = 0x70;
    inline constexpr std::uint32_t DYN_ARRAY_COUNT_MASK = 0x7FFFFFFF;
    inline constexpr std::ptrdiff_t SHADER_ITEM_SHADER_OFFSET = 0x00;
    inline constexpr std::ptrdiff_t SHADER_ITEM_RESOURCES_OFFSET = 0x08;
    inline constexpr std::ptrdiff_t SHADER_ITEM_TECHNIQUE_OFFSET = 0x10;
    inline constexpr std::ptrdiff_t SHADER_ITEM_PREPROCESS_OFFSET = 0x14;
    inline constexpr std::ptrdiff_t SHADER_FLAGS_OFFSET = 0x34;
    inline constexpr std::uint32_t EF_NODRAW = 0x8;
    inline constexpr std::ptrdiff_t SHADER_FLAGS2_OFFSET = 0x38;
    inline constexpr std::uint32_t EF2_NODRAW = 0x10;
    inline constexpr std::ptrdiff_t SHADER_TECHNIQUES_OFFSET = 0x50;
    inline constexpr std::ptrdiff_t SHADER_TECHNIQUE_COUNT_OFFSET = 0x58;
    inline constexpr std::ptrdiff_t TECHNIQUE_CUSTOM_RENDER_OFFSET = 0x2C;
    // A model's LOD 0 render mesh sits at CStatObj +0x48 and its chunks at CRenderMesh +0x138, with the count in the
    // u32 before the first. Each chunk is 0x30 bytes, with the render element at +0x08 and the material slot (u16) at
    // +0x26. [AddRenderElements 0x18028A2A4]
    inline constexpr std::ptrdiff_t STAT_OBJ_RENDER_MESH_OFFSET = 0x48;
    inline constexpr std::ptrdiff_t RENDER_MESH_CHUNKS_OFFSET = 0x138;
    inline constexpr std::size_t RENDER_CHUNK_STRIDE = 0x30;
    inline constexpr std::ptrdiff_t RENDER_CHUNK_RE_OFFSET = 0x08;
    inline constexpr std::ptrdiff_t RENDER_CHUNK_MAT_ID_OFFSET = 0x26;
    // A mask material is named after its source plus this suffix and a per-load tag. It sits in the source's folder,
    // so relative texture paths resolve as the source's do.
    inline constexpr const char *MASK_MATERIAL_SUFFIX = "_hsmask";
    // A mask material's opacity and, for a source with an alpha test, its alpha test. EF_AddEf drops an item whose
    // opacity is 0 or not above its alpha test (0x28AFDD), and KCD1's Illum takes its alpha from the opacity alone.
    // So the copy stays in the render lists at an all but invisible 0.4 %. The mask pass clips at a fixed 0.5 alpha
    // for any alpha-tested material, so the mask keeps the leaf shapes.
    inline constexpr const char *MASK_MATERIAL_OPACITY = "0.004";
    inline constexpr const char *MASK_MATERIAL_ALPHA_TEST = "0.002";
    // Mask materials built per main-thread tick (an XML read plus a material load each).
    inline constexpr int MASK_MATERIAL_BUILDS_PER_TICK = 2;
    // The material a plant is drawn with: its vegetation group's override at +0x180, otherwise the model's own
    // (CStatObj::GetMaterial, +0xE0). [CVegetation::Render 0x3235D4]
    inline constexpr std::ptrdiff_t VEG_GROUP_MATERIAL_OFFSET = 0x180;
    inline constexpr std::ptrdiff_t STATOBJ_MATERIAL_OFFSET = 0xE0;
    // r_CustomVisions mode whose composite needs the optimised technique.
    inline constexpr std::int32_t CUSTOM_VISIONS_OPTIMISED = 3;

    // The CHudSilhouettes post-effect parameters (I3DEngine::SetPostEffectParam names).
    inline constexpr const char *HUD_SILHOUETTES_TYPE_PARAM = "HudSilhouettes_Type";
    inline constexpr const char *HUD_SILHOUETTES_AMOUNT_PARAM = "HudSilhouettes_Amount";
    inline constexpr const char *HUD_SILHOUETTES_FILL_STR_PARAM = "HudSilhouettes_FillStr";

} // namespace HenrySenses::constants

#endif // HENRYSENSES_CONSTANTS_HPP
