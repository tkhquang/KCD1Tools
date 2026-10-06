/**
 * @file aob_resolver.hpp
 * @brief The AOB candidate ladders, the anchor registry and the feature gates.
 *
 * Every code or data location the mod hooks, calls or reads is located at startup by a ladder of ordered AOB
 * candidates rather than a single signature, so a game patch that shifts code only has to leave one rung intact.
 * DetourModKit resolves each ladder in declared order (most specific first), confined to the WHGame.dll image (the
 * default scope, DMK::Region::host(), is the game executable), and only on executable pages: an instruction signature
 * can then never alias an identical byte run in data, nor a generic rung shadow a match in another module. A rung that
 * matches twice is skipped as ambiguous (require_unique).
 *
 * Signature rules (DetourModKit docs/misc/aob-signatures.md): every relative branch or call target, RIP displacement,
 * address immediate and virtual-call slot is wildcarded; a branch inside a pattern is a bounded gap ([2-6] for a
 * conditional jump, [2-5] for a jump) because compilers switch between the rel8 and rel32 encodings; no pattern
 * crosses the padding between functions; and every code ladder holds at least one rung that starts past the first 14
 * bytes of its function, so a sibling mod's inline hook on the prologue cannot hide every rung.
 *
 * Resolution shapes (DMK::scan::Candidate factories):
 *   - direct       address = match + walk_back (a mid-body rung walks back to the function entry).
 *   - rip_relative address = (match + instr_len) + disp32, for a load whose [rip+disp32] names a data slot. A call
 *                  site is never a rip_relative rung: the decoder accepts only a RIP-relative memory operand.
 *   - string_xref  the function enclosing the one reference to a unique string literal (.pdata bounds). A string
 *                  survives patches far better than the code bytes around it, so where a target references one it
 *                  leads its ladder.
 *
 * Every anchor passes a validator. A code anchor must lie on an executable page and agree with any covering unwind
 * function entry. A data anchor must be readable and non-executable inside the image. gEnv, the global context and the
 * CCryAction slot resolve as 2-of-N quorums over their rungs, because every other read goes through them.
 * KCD1_HenrySenses.signatures.ini beside the ASI can replace any ladder by label (manifest::overlay, gated by
 * constants::SIGNATURE_REVISION), and [Settings] ExportSignatures writes the built-in set in that format.
 *
 * A feature is enabled only through anchor::evaluate_gate over its own anchors (feature_ready): a missed anchor fails
 * its features closed.
 *
 * Every rung below matches exactly once in the KCD1 Steam 1.9.8 WHGame.dll (PE timestamp 0x69CCD815). The Genv,
 * Context and CryActionFramework ladders are the KCD1 TPVCamera ones, unique on the Steam 1.9.8, GOG 1.9.8 and 1.9.7
 * builds.
 */
#ifndef HENRYSENSES_AOB_RESOLVER_HPP
#define HENRYSENSES_AOB_RESOLVER_HPP

#include <DetourModKit.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace HenrySenses
{
    namespace aob
    {
        using DMK::scan::Candidate;
        using DMK::scan::Pattern;

        // Genv: SSystemGlobalEnvironment base (data). gEnv is an embedded struct in this CryEngine 3.8 fork, reached
        // through RIP-relative references in three different functions. 3 rungs, one vote each.
        inline const Candidate GENV_CANDIDATES[] = {
            // Struct init: `lea rax,gEnv; lea rcx,Y; mov [rdi],rcx`.
            Candidate::rip_relative(
                "Genv_P1_LeaStructInit",
                Pattern::literal("48 8D 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 0F"),
                3,
                7
            ),
            // `mov rdx,[rax]; call [rdx+8]; mov rcx,gEnv; test rcx,rcx; jz +8; mov rax,[rcx]; xor edx,edx; call
            // [rax+18h]`. The call lead-in and the null-check tail make the generic gEnv load unique.
            Candidate::rip_relative(
                "Genv_P2_MovNullCheckVCall",
                Pattern::literal("48 8B 10 FF 52 08 | 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 08 48 8B 01 33 D2 FF 50 18"),
                3,
                7
            ),
            // `call X; mov rcx,gEnv; test rcx,rcx; jz +15h; mov rax,[rcx]; xor edx,edx; call [rax+18h]`. The jz
            // displacement and the tail tell it from the other null-check sites.
            Candidate::rip_relative(
                "Genv_P3_CallMovNullCheck",
                Pattern::literal("E8 ?? ?? ?? ?? | 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 15 48 8B 01 33 D2 FF 50 18"),
                3,
                7
            ),
        };

        // Context: Global-context storage slot (data). Each rung decodes one magic-static getter's `mov rax,
        // cs:[rip+ctx]` behind its guard. The instructions after the load carry the identity. 3 rungs, one vote each.
        inline const Candidate CONTEXT_CANDIDATES[] = {
            // `mov rax,cs:ctx; mov rcx,r12; mov rbx,[rax+disp32]`.
            Candidate::rip_relative(
                "Context_P1_GetterMovRcxR12",
                Pattern::literal(
                    "39 0D ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 49 8B CC 48 8B 98 ?? ?? ?? ??"
                ),
                3,
                7
            ),
            // `mov rax,cs:ctx; mov rbx,[rsp+disp]; mov rax,[rax+8]`.
            Candidate::rip_relative(
                "Context_P2_GetterMovRbxStack",
                Pattern::literal(
                    "39 05 ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B 40 08"
                ),
                3,
                7
            ),
            // The framework getter: `mov rax,cs:ctx; mov rbx,[rsp+disp]; add rsp,20h; pop rdi; ret`.
            Candidate::rip_relative(
                "Context_P3_GetterEpilogue",
                Pattern::literal(
                    "39 05 ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 20 5F C3"
                ),
                3,
                7
            ),
        };

        // CryActionFramework: CCryAction singleton storage slot (data). KCD2 reaches the framework through
        // gEnv->pGame->GetIGameFramework(). KCD1 keeps it in a fixed .data slot that the framework constructor fills.
        // Each rung decodes a `mov reg, cs:slot`. 3 rungs, one vote each.
        inline const Candidate CRY_ACTION_FRAMEWORK_CANDIDATES[] = {
            // Shutdown path: `mov rcx,cs:slot; test rcx,rcx; jz; mov rax,[rcx]; call [rax+50h]`.
            Candidate::rip_relative(
                "CryActionFramework_P1_ShutdownVCall",
                Pattern::literal("48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 50 50"),
                3,
                7
            ),
            // C_Game::CreateInstance path: two slot loads bracket `call [rax+98h]`.
            Candidate::rip_relative(
                "CryActionFramework_P2_CreateInstance",
                Pattern::literal("48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 98 00 00 00 48 8B 0D ?? ?? ?? ?? E8"),
                3,
                7
            ),
            // Framework-create prologue: `mov rax,cs:slot; mov r13,r8; mov rsi,rdx; mov r15,rcx; test rax,rax`.
            Candidate::rip_relative(
                "CryActionFramework_P3_CreatePrologue",
                Pattern::literal("48 8B 05 ?? ?? ?? ?? 4D 8B E8 48 8B F2 4C 8B F9 48 85 C0"),
                3,
                7
            ),
        };

        // PostUpdate: CCryAction::PostUpdate, CCryAction vtable slot 12 (hooked, main-thread tick). 4 rungs, most
        // specific first.
        inline const Candidate POST_UPDATE_CANDIDATES[] = {
            Candidate::string_xref(
                "PostUpdate_X1_ProfilerLabelXref",
                DMK::scan::StringRefQuery{
                    .text = "CCryAction::PostUpdate",
                    .return_mode = DMK::scan::XrefReturn::EnclosingFunction,
                }
            ),
            Candidate::direct(
                "PostUpdate_P1_Prologue",
                Pattern::literal(
                    "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 20 41 56 48 83 EC 60 48 8B F1 0F 29 70 E8 48 8D 48 18 "
                    "45 8B F0"
                )
            ),
            Candidate::direct(
                "PostUpdate_P2_BodyFlagTests",
                Pattern::literal(
                    "45 8B F0 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 41 F6 C6 20 [2-6] 41 F6 C6 10 [2-6] 48 8B 8E ?? ?? ?? "
                    "?? 48 8B 01 FF 50 ??"
                ),
                -0x20
            ),
            Candidate::direct(
                "PostUpdate_P3_BodyGameCheck",
                Pattern::literal(
                    "48 8B 8E ?? ?? ?? ?? 48 8B 01 FF 50 ?? 8A 8E ?? ?? ?? ?? 85 C0 [2-6] 84 C9 [2-6] 48 8B 0D ?? ?? ?? ?? "
                    "33 D2"
                ),
                -0x43
            ),
        };

        // GetEntity: CEntitySystem::GetEntity, vtable slot 12 (vtable validator). 2 rungs, most specific first.
        inline const Candidate GET_ENTITY_CANDIDATES[] = {
            Candidate::direct(
                "GetEntity_P1_ReadLockArgs",
                Pattern::literal("48 8D 99 D0 00 00 00 4C 8B F1 48 8B CB 48 8D 73 10 8B EA E8"),
                -0x12
            ),
            Candidate::direct(
                "GetEntity_P2_SaltSplit",
                Pattern::literal(
                    "8B C5 49 8D 8E 38 02 00 00 C1 E8 11 48 8D 54 24 40 44 8B D5 66 89 44 24 40 41 81 E2 FF FF 01 00"
                ),
                -0x3C
            ),
        };

        // GetEntityIterator: CEntitySystem::GetEntityIterator, vtable slot 20 (vtable validator). 1 rung.
        inline const Candidate GET_ENTITY_ITERATOR_CANDIDATES[] = {
            Candidate::direct(
                "GetEntityIterator_P1_IteratorInit",
                Pattern::literal("48 89 77 08 48 8D 05 ?? ?? ?? ?? 48 89 07 48 8B CF 66 89 6F 14 89 6F 18 89 6F 10 E8"),
                -0x5F
            ),
        };

        // GetProxy: CEntity::GetProxy, vtable slot 67 (vtable validator). The proxy map head at CEntity + 0xB0 leads
        // the body. 1 rung.
        inline const Candidate GET_PROXY_CANDIDATES[] = {
            Candidate::direct(
                "GetProxy_P1_ProxyMapHead",
                Pattern::literal("4C 8B 89 B0 00 00 00 49 8B C9 4D 8B C1 49 8B 41 08")
            ),
        };

        // GetWorldBounds: CEntity::GetWorldBounds, vtable slot 33 (vtable validator). 1 rung.
        inline const Candidate GET_WORLD_BOUNDS_CANDIDATES[] = {
            Candidate::direct(
                "GetWorldBounds_P1_Prologue",
                Pattern::literal("48 8B C4 53 57 48 81 EC D8 00 00 00 0F 29 70 D8 48 8B DA 0F 29 78 C8 48 8B F9")
            ),
        };

        // RegisterEntity: C3DEngine::RegisterEntity, vtable slot 34 (vtable validator). 1 rung.
        inline const Candidate REGISTER_ENTITY_CANDIDATES[] = {
            Candidate::direct(
                "RegisterEntity_P1_LockFrameId",
                Pattern::literal(
                    "48 8D 99 28 20 01 00 48 8B E9 48 8B CB 41 8B F8 48 8B F2 FF 15 ?? ?? ?? ?? 48 8B 0D ?? ?? ?? ?? "
                    "B2 01 48 8B 01 FF 90"
                ),
                -0x14
            ),
        };

        // UnRegisterEntity: C3DEngine::UnRegisterEntityDirect, vtable slot 37 (vtable validator). 1 rung.
        inline const Candidate UNREGISTER_ENTITY_CANDIDATES[] = {
            Candidate::direct(
                "UnRegisterEntity_P1_LockUnregister",
                Pattern::literal(
                    "48 8D 99 28 20 01 00 48 8B F1 48 8B CB 48 8B FA FF 15 ?? ?? ?? ?? 48 8B D7 48 8B CE E8"
                ),
                -0xF
            ),
        };

        // SetPostEffectParam: C3DEngine::SetPostEffectParam(name, float, bool), vtable slot 161 (vtable validator).
        // 1 rung.
        inline const Candidate SET_POST_EFFECT_PARAM_CANDIDATES[] = {
            Candidate::direct(
                "SetPostEffectParam_P1_Prologue",
                Pattern::literal(
                    "48 85 D2 [2-6] 48 89 5C 24 08 57 48 83 EC 40 48 8B F9 0F 29 74 24 30 48 8D 4C 24 58 41 8A D9 0F 28 F2"
                )
            ),
        };

        // CustomVisionsCvar: the r_CustomVisions value (int, data). CHudSilhouettes::Preprocess reads it first, and
        // the batch-flag routine tests it before it sets FB_CUSTOM_RENDER. 2 rungs, most specific first.
        inline const Candidate CUSTOM_VISIONS_CVAR_CANDIDATES[] = {
            Candidate::rip_relative(
                "CustomVisionsCvar_P1_PreprocessLoad",
                Pattern::literal("40 53 48 83 EC 20 | 8B 05 ?? ?? ?? ?? 48 8B D9 83 F8 03 [2-6] 80 79 50 00"),
                2,
                6
            ),
            Candidate::rip_relative(
                "CustomVisionsCvar_P2_BatchFlagTest",
                Pattern::literal("44 39 48 60 [2-6] 41 8B C9 | 44 39 0D ?? ?? ?? ?? [2-6] 85 C9"),
                3,
                7
            ),
        };

        // PostProcessGameFxCvar: the r_PostProcessGameFx value (int, data), the second test in
        // CHudSilhouettes::Preprocess. 1 rung.
        inline const Candidate POST_PROCESS_GAME_FX_CVAR_CANDIDATES[] = {
            Candidate::rip_relative(
                "PostProcessGameFxCvar_P1_PreprocessTest",
                Pattern::literal("80 79 50 00 [2-6] | 83 3D ?? ?? ?? ?? 00 [2-6] 85 C0"),
                2,
                7
            ),
        };

        // RenDev: gRenDev, the CD3D9Renderer singleton slot (data), loaded by CHudSilhouettes::Preprocess for the
        // custom render mode test. 1 rung.
        inline const Candidate REN_DEV_CANDIDATES[] = {
            Candidate::rip_relative(
                "RenDev_P1_PreprocessRenderMode",
                Pattern::literal("85 C0 [2-6] | 4C 8B 05 ?? ?? ?? ?? BA 07 00 00 00"),
                3,
                7
            ),
        };

        // RenderCustomScene: CD3D9Renderer::FX_RenderCustomScene, which draws the HUD silhouette mask (hooked, mask
        // state). 2 rungs, most specific first.
        inline const Candidate RENDER_CUSTOM_SCENE_CANDIDATES[] = {
            Candidate::direct(
                "RenderCustomScene_P1_PrologueGate",
                Pattern::literal(
                    "48 89 5C 24 08 57 48 83 EC 20 F6 81 ?? ?? ?? ?? 20 48 8B D9 [2-6] 8B 81 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? "
                    "?? 83 3C 81 01"
                )
            ),
            Candidate::direct(
                "RenderCustomScene_P2_BatchFlagUnion",
                Pattern::literal(
                    "B9 02 00 00 00 44 8B D0 E8 ?? ?? ?? ?? B9 05 00 00 00 44 0B D0 E8 ?? ?? ?? ?? B9 0F 00 00 00 44 0B D0 "
                    "E8 ?? ?? ?? ?? 41 0B C2 BF 00 08 00 00 85 C7"
                ),
                -0x42
            ),
        };

        // ForceStateOr: the renderer's forced render-state bits (CD3D9Renderer m_RP.m_ForceStateOr), the memory
        // displacement of FX_CommitStates' `or ebx, [rdi+disp32]` in `state = ForceStateOr | (state & ~ForceStateAnd)`
        // (code operand). 1 rung.
        inline const Candidate FORCE_STATE_OR_CANDIDATES[] = {
            Candidate::direct(
                "ForceStateOr_P1_CommitStatesFold",
                Pattern::literal(
                    "8B 9F ?? ?? ?? ?? BD 00 00 00 04 48 8B 87 ?? ?? ?? ?? F7 D3 41 23 DA | 0B 9F ?? ?? ?? ??"
                )
            ),
        };

        // PersFlags2: the renderer's pipeline flags (m_RP.m_PersFlags2), the memory displacement of
        // FX_CustomRenderScene's `bts [rsi+disp32], 0Bh` that marks the custom render pass (code operand). 1 rung.
        inline const Candidate PERS_FLAGS2_CANDIDATES[] = {
            Candidate::direct(
                "PersFlags2_P1_CustomPassMark",
                Pattern::literal("| 0F BA AE ?? ?? ?? ?? 0B [2-5] 8B 05 ?? ?? ?? ?? FF C8 A9 FD FF FF FF")
            ),
        };

        // Post3dSample5Bit: the PersFlags2 bit that adds %_RT_SAMPLE5 to the custom render pass (code operand). It is
        // the immediate of the `test dl, imm8` in FX_CommitStates between its SAMPLE2 and SAMPLE5 merges. The SAMPLE5
        // permutation of SilhoueteVisionOptimised skips the near fade. 1 rung.
        inline const Candidate POST3D_SAMPLE5_BIT_CANDIDATES[] = {
            Candidate::direct(
                "Post3dSample5Bit_P1_RtFlagGate",
                Pattern::literal("48 0B 05 ?? ?? ?? ?? 48 89 87 ?? ?? ?? ?? | F6 C2 ?? [2-6] 48 0B 05 ?? ?? ?? ??")
            ),
        };

        // ShadersAllowCompilationCvar: the r_ShadersAllowCompilation value (int, data). A new permutation (the SAMPLE5
        // mask shader) compiles only while it is 1. 1 rung.
        inline const Candidate SHADERS_ALLOW_COMPILATION_CVAR_CANDIDATES[] = {
            Candidate::rip_relative(
                "ShadersAllowCompilationCvar_P1_CompileGate",
                Pattern::literal("48 85 FF [2-6] | 83 3D ?? ?? ?? ?? 00 [2-6] 48 8B 84 24 ?? ?? ?? ?? 4C 8D 4C 24 60"),
                2,
                7
            ),
        };

        // StatObjRenderInternal: CStatObj::RenderInternal, which every static-mesh render (CBrush, CVegetation, merged
        // meshes, CStatObj::Render) ends in (hooked, outline copies). 1 rung.
        inline const Candidate STAT_OBJ_RENDER_INTERNAL_CANDIDATES[] = {
            Candidate::direct(
                "StatObjRenderInternal_P1_PrologueHiddenTest",
                Pattern::literal(
                    "40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 F1 48 81 EC D8 00 00 00 48 8B 05 ?? ?? ?? ?? 48 33 "
                    "C4 48 89 45 FF F6 81 68 01 00 00 01 49 8B D9"
                )
            ),
        };

        // StatObjRender: CStatObj::Render(this, const SRendParams &, const SRenderingPassInfo &), vtable slot 36
        // (called, outline copies). 1 rung.
        inline const Candidate STAT_OBJ_RENDER_CANDIDATES[] = {
            Candidate::direct(
                "StatObjRender_P1_PrologueHiddenTest",
                Pattern::literal("48 89 5C 24 10 55 56 57 48 83 EC 50 F6 81 68 01 00 00 01 49 8B E8 48 8B F2 48 8B F9")
            ),
        };

        // MatManLoadFromXml: CMatMan::LoadMaterialFromXml, CMatMan vtable slot 8 (vtable validator, mask materials).
        // 1 rung.
        inline const Candidate MAT_MAN_LOAD_FROM_XML_CANDIDATES[] = {
            Candidate::direct(
                "MatManLoadFromXml_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 10 56 57 41 56 48 83 EC 40 48 8D 79 40 48 8B F1 48 8B CF 4D 8B F0 48 8B DA"
                )
            ),
        };

        // XmlLoadFromFile: CXmlUtils::LoadXmlFromFile, CXmlUtils vtable slot 1 (vtable validator, mask materials).
        // 1 rung.
        inline const Candidate XML_LOAD_FROM_FILE_CANDIDATES[] = {
            Candidate::direct(
                "XmlLoadFromFile_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 08 48 89 74 24 18 57 48 83 EC 40 48 8B DA 48 8B F9 41 8A D1 48 8D 4C 24 20 49 8B F0 E8"
                )
            ),
        };

        // XmlNodeSetAttr: CXmlNode::setAttr(key, const char *value), CXmlNode vtable slot 67 (vtable validator, mask
        // materials). 1 rung.
        inline const Candidate XML_NODE_SET_ATTR_CANDIDATES[] = {
            Candidate::direct(
                "XmlNodeSetAttr_P1_Prologue",
                Pattern::literal("48 89 5C 24 10 55 56 57 48 83 EC 30 48 83 79 38 00 49 8B F0 48 8B EA 48 8B F9 0F 85")
            ),
        };

        // XmlNodeFindChild: CXmlNode::findChild, CXmlNode vtable slot 40 (vtable validator, mask materials). 1 rung.
        inline const Candidate XML_NODE_FIND_CHILD_CANDIDATES[] = {
            Candidate::direct(
                "XmlNodeFindChild_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 56 41 57 48 83 EC 20 48 8B 79 30 4D 8B F8 48 "
                    "8B DA"
                )
            ),
        };

        // XmlNodeGetChild: CXmlNode::getChild, CXmlNode vtable slot 39 (vtable validator, mask materials). 1 rung.
        inline const Candidate XML_NODE_GET_CHILD_CANDIDATES[] = {
            Candidate::direct(
                "XmlNodeGetChild_P1_Body",
                Pattern::literal("40 53 48 83 EC 20 48 8B 41 30 48 8B DA 4D 63 C0 48 8B CB 48 8B 10 4A 8B 14 C2 E8")
            ),
        };

        // XmlNodeGetAttr: CXmlNode::getAttr(key), which returns the value or "", CXmlNode vtable slot 29 (vtable
        // validator, mask materials). 1 rung: the whole function, then the next one's prologue (the body alone matches
        // twice).
        inline const Candidate XML_NODE_GET_ATTR_CANDIDATES[] = {
            Candidate::direct(
                "XmlNodeGetAttr_P1_BodyNextPrologue",
                Pattern::literal(
                    "48 83 EC 28 E8 ?? ?? ?? ?? 48 85 C0 75 07 48 8D 05 ?? ?? ?? ?? 48 83 C4 28 C3 CC CC 40 53 48 83 "
                    "EC 20 48 8B 41 30"
                )
            ),
        };

        // XmlNodeGetChildCount: CXmlNode::getChildCount, CXmlNode vtable slot 38 (vtable validator, mask materials).
        // 1 rung: the whole function.
        inline const Candidate XML_NODE_GET_CHILD_COUNT_CANDIDATES[] = {
            Candidate::direct(
                "XmlNodeGetChildCount_P1_Body",
                Pattern::literal("48 8B 51 30 48 85 D2 74 0C 48 8B 42 08 48 2B 02 48 C1 F8 03 C3 33 C0 C3")
            ),
        };

        // GetObjectsInBox: C3DEngine::GetObjectsInBox, vtable slot 233 (called, and the validator of slot 232). A
        // wrapper that fills a stack PodArray and copies it to the list, which it keeps in rdi. The typed query in
        // slot 232 has the same shape with the list in r9. `mov rdi, r8` and `lea r8, [rax-18h]` tell the two apart.
        // 2 rungs, most specific first.
        inline const Candidate GET_OBJECTS_IN_BOX_CANDIDATES[] = {
            Candidate::direct(
                "GetObjectsInBox_P1_WrapperHead",
                Pattern::literal("48 8B C4 48 89 58 08 57 48 83 EC 30 48 83 60 E8 00 49 8B F8 83 60 F0 00 4C 8D 40 E8")
            ),
            Candidate::direct(
                "GetObjectsInBox_P2_ListCopy",
                Pattern::literal(
                    "49 8B F8 83 60 F0 00 4C 8D 40 E8 83 60 F4 00 E8 ?? ?? ?? ?? 8B 5C 24 28 48 85 FF [2-6] 85 DB [2-6] "
                    "48 8B 54 24 20 44 8B C3 41 C1 E0 03 48 8B CF E8"
                ),
                -0x11
            ),
        };

        // ObjManager: CObjManager instance slot (data). Each rung decodes a `mov reg, cs:slot` ahead of a read of the
        // vegetation group table (0x190-byte groups). 3 rungs, most specific first.
        inline const Candidate OBJ_MANAGER_CANDIDATES[] = {
            // CVegetation::GetEntityStatObj: `movsxd rax,[rdi+68h]; mov rcx,cs:slot; imul r8,rax,190h; mov rdx,[rcx];
            // mov rax,[rdx]`.
            Candidate::rip_relative(
                "ObjManager_P1_VegetationStatObj",
                Pattern::literal("48 63 47 68 | 48 8B 0D ?? ?? ?? ?? 4C 69 C0 90 01 00 00 48 8B 11 48 8B 02"),
                3,
                7
            ),
            // The merged-mesh group model helper: `movsxd rax,[rax+rdx+4Ch]; imul rdx,rax,190h; mov rax,cs:slot;
            // mov rcx,[rax]; mov rax,[rcx]; mov rcx,[rdx+rax]`.
            Candidate::rip_relative(
                "ObjManager_P2_MergedGroupStatObj",
                Pattern::literal(
                    "48 63 44 10 4C 48 69 D0 90 01 00 00 | 48 8B 05 ?? ?? ?? ?? 48 8B 08 48 8B 01 48 8B 0C 02"
                ),
                3,
                7
            ),
            // A group loop: `mov rax,cs:slot; xor ebx,ebx; mov rdi,[rax]; cmp [rdi+8],ebx; jbe; movsxd rax,ebx;
            // imul rcx,rax,190h`.
            Candidate::rip_relative(
                "ObjManager_P3_GroupLoop",
                Pattern::literal("48 8B 05 ?? ?? ?? ?? 33 DB 48 8B 38 39 5F 08 [2-6] 48 63 C3 48 69 C8 90 01 00 00"),
                3,
                7
            ),
        };

        // HerbType: the herb-type lookup by model-path hash (called). It returns a pointer to the herb type byte of a
        // hash, or to a default record of type 0 for a hash the table lacks. 3 rungs, most specific first.
        inline const Candidate HERB_TYPE_CANDIDATES[] = {
            Candidate::direct(
                "HerbType_P1_PrologueHashKey",
                Pattern::literal(
                    "89 54 24 10 48 83 EC 28 44 8B DA 41 B8 04 00 00 00 48 8D 54 24 38 E8 ?? ?? ?? ?? 48 8B 0D "
                    "?? ?? ?? ?? 4C 8B 0D ?? ?? ?? ??"
                )
            ),
            Candidate::direct(
                "HerbType_P2_BucketWalk",
                Pattern::literal(
                    "48 23 C8 48 8B 15 ?? ?? ?? ?? 48 8B C1 48 03 C0 48 03 C9 4D 8B 04 C1 49 39 14 C9 [2-6] "
                    "49 8B 44 C9 08 48 8B 00 4C 3B C0 [2-6] 45 39 58 10"
                ),
                -0x29
            ),
            Candidate::direct(
                "HerbType_P3_KeyCompareReturn",
                Pattern::literal("45 39 58 10 [2-6] 4C 3B C2 [2-6] 49 8B 40 18 48 83 C4 28 C3"),
                -0x53
            ),
        };

        // MergedMeshesManager: CMergedMeshesManager instance slot (data). Each rung decodes a `mov reg, cs:slot`.
        // [KCD2 finds the manager by RTTI next to the CObjManager slot] 3 rungs, most specific first.
        inline const Candidate MERGED_MESHES_MANAGER_CANDIDATES[] = {
            // The bucket walk: `mov rdi,cs:slot; mov r14d,20h; add rdi,8; mov ebp,20h; mov esi,2`.
            Candidate::rip_relative(
                "MergedMeshesManager_P1_BucketWalk",
                Pattern::literal("48 8B 3D ?? ?? ?? ?? 41 BE 20 00 00 00 48 83 C7 08 BD 20 00 00 00 BE 02 00 00 00"),
                3,
                7
            ),
            // The update profiler scope: `sub rsp,70h; mov rbx,cs:slot; lea rcx,[rax+18h]; mov rdi,rdx; lea rdx,
            // "MMRMGR: update"`.
            Candidate::rip_relative(
                "MergedMeshesManager_P2_UpdateScope",
                Pattern::literal("48 83 EC 70 | 48 8B 1D ?? ?? ?? ?? 48 8D 48 18 48 8B FA 48 8D 15 ?? ?? ?? ??"),
                3,
                7
            ),
            // `mov rdi,cs:slot; xor r15d,r15d; mov r12d,1; movzx eax,word [rdi+disp32]; test ax,ax`.
            Candidate::rip_relative(
                "MergedMeshesManager_P3_FlagTest",
                Pattern::literal("48 8B 3D ?? ?? ?? ?? 45 33 FF 41 BC 01 00 00 00 0F B7 87 ?? ?? ?? ?? 66 85 C0"),
                3,
                7
            ),
        };

        // LegalToTake: C_RPGInventory vtable slot 6, bool (this, item, C_Soul *owner, C_Soul *taker) (called). CanSteal
        // asks it whether the taker can take an item of the owner legally. The answer is yes when the taker is the
        // owner or the owner is a public enemy. It is also yes for huntable game (race not human, hunting_role 1)
        // while the taker has ability 55 HuntingPermit. It reads neither this nor the item. 2 rungs, most specific
        // first.
        inline const Candidate LEGAL_TO_TAKE_CANDIDATES[] = {
            Candidate::direct(
                "LegalToTake_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 49 8B F1 49 8B F8 4D 3B C1 74 ?? E8 ?? ?? ?? ?? 4C "
                    "8B C7 BA 03 00 00 00 48 8B C8 E8 ?? ?? ?? ?? 0F 57 C9 0F 2F C8 77"
                )
            ),
            Candidate::direct(
                "LegalToTake_P2_HuntingPermit",
                Pattern::literal("BA 37 00 00 00 48 8B CE 8B 78 2C 48 8B 06 FF 90 A8 01 00 00"),
                -0x52
            ),
        };

        // InventoryOwner: EntityModule.GetInventoryOwner's resolver, u64 *(C_Inventory *, u64 *out) (called). It
        // answers the owner WUID at +0x20, or asks the context's ownership map when that holds the invalid WUID.
        // 2 rungs, most specific first.
        inline const Candidate INVENTORY_OWNER_CANDIDATES[] = {
            Candidate::direct(
                "InventoryOwner_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 10 57 48 83 EC 20 48 8B 41 20 48 8B DA 48 3B 05 ?? ?? ?? ?? 48 8B F9 [2-6] 48 89 02 "
                    "48 8B C3"
                )
            ),
            Candidate::direct(
                "InventoryOwner_P2_ContextResolve",
                Pattern::literal(
                    "E8 ?? ?? ?? ?? 4C 8B 80 18 01 00 00 48 8B 07 48 89 44 24 30 49 8B 88 F0 00 00 00 48 8B 01 FF 50 "
                    "?? 4C 8D 44 24 30 48 8B D3 E8"
                ),
                -0x2E
            ),
        };

        // PublicEnemyRelation: C_FactionManager vtable slot 14, float(manager, faction, C_Soul *), the relation behind
        // RPG.IsPublicEnemy (vtable validator). 2 rungs, most specific first.
        inline const Candidate PUBLIC_ENEMY_RELATION_CANDIDATES[] = {
            Candidate::direct(
                "PublicEnemyRelation_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 08 57 48 83 EC 20 49 8B 00 8B DA 48 8B F9 B2 01 49 8B C8 FF 90 ?? ?? ?? ?? 8B D3 48 "
                    "8B CF 44 8B C0"
                )
            ),
            Candidate::direct(
                "PublicEnemyRelation_P2_FactionTail",
                Pattern::literal(
                    "B2 01 49 8B C8 FF 90 ?? ?? ?? ?? 8B D3 48 8B CF 44 8B C0 48 8B 5C 24 30 48 83 C4 20 5F E9"
                ),
                -0x12
            ),
        };

        // FactionManager: the wh::rpgmodule::C_FactionManager singleton (data), a magic static that RPG.IsPublicEnemy
        // reaches through its getter. Each rung decodes a store or a load of the object in its constructor. 2 rungs.
        inline const Candidate FACTION_MANAGER_CANDIDATES[] = {
            // `lea rax,vftable; xorps xmm1,xmm1; mov cs:manager,rax`.
            Candidate::rip_relative(
                "FactionManager_P1_CtorVtableStore",
                Pattern::literal(
                    "0F 57 C0 48 8D 05 ?? ?? ?? ?? 0F 57 C9 | 48 89 05 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 66 0F 7F 05 ?? "
                    "?? ?? ??"
                ),
                3,
                7
            ),
            // `movdqa cs:member,xmm0; lea rcx,manager; mov cs:secondary_vptr,rax`.
            Candidate::rip_relative(
                "FactionManager_P2_CtorThisLoad",
                Pattern::literal(
                    "66 0F 7F 05 ?? ?? ?? ?? | 48 8D 0D ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 66 0F 7F 0D ?? ?? ?? ?? 66 0F "
                    "7F 05"
                ),
                3,
                7
            ),
        };

        // CanLoot: C_Actor::CanLoot, bool(C_Actor *looter, EntityId victim), the test behind player.actor:CanLoot
        // (called). 2 rungs, most specific first.
        inline const Candidate CAN_LOOT_CANDIDATES[] = {
            Candidate::direct(
                "CanLoot_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 8B FA 48 8B F1 E8 ?? ?? ?? ?? 8B D7 48 8B 88 28 01 "
                    "00 00 48 8B 01 FF 50 ??"
                )
            ),
            Candidate::direct(
                "CanLoot_P2_SoulCorpseTests",
                Pattern::literal(
                    "48 8B 8B 50 06 00 00 48 85 C9 [2-6] 48 8B 01 FF 50 ?? 84 C0 [2-6] 48 8B 86 70 01 00 00"
                ),
                -0x75
            ),
        };

        // FindEffect: CParticleManager::FindEffect, IParticleManager vtable slot 6 (vtable validator, loot effects).
        // 3 rungs, most specific first. Only a cold chunk references the "Particle effect not found" string, so no
        // string rung.
        inline const Candidate FIND_EFFECT_CANDIDATES[] = {
            Candidate::direct(
                "FindEffect_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 20 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 "
                    "C4 48 89 84 24 ?? ?? ?? ?? 33 FF 45 8A E1 49 8B E8"
                )
            ),
            Candidate::direct(
                "FindEffect_P2_EnabledNameTest",
                Pattern::literal(
                    "45 8A E1 49 8B E8 48 8B F2 4C 8B F1 40 38 B9 ?? ?? ?? ?? [2-6] 48 85 D2 [2-6] 40 38 3A [2-6] 48 "
                    "83 C1 F8 E8"
                ),
                -0x2B
            ),
            Candidate::direct(
                "FindEffect_P3_FindByNameValidate",
                Pattern::literal(
                    "48 83 C1 F8 E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 [2-6] 48 8B 03 48 8B CB FF 50 ?? 84 C0 [2-6] 45 84 "
                    "E4"
                ),
                -0x4A
            ),
        };

        // ProxyLoadParticleEmitter: CRenderProxy::LoadParticleEmitter (called, loot effects). 3 rungs, most specific
        // first.
        inline const Candidate PROXY_LOAD_PARTICLE_EMITTER_CANDIDATES[] = {
            Candidate::direct(
                "ProxyLoadParticleEmitter_P1_Prologue",
                Pattern::literal(
                    "48 8B C4 48 89 58 08 48 89 70 20 89 50 10 55 57 41 56 48 8D 68 ?? 48 81 EC ?? ?? ?? ?? 49 8B F1 "
                    "49 8B F8 4C 8B F1 4D 85 C0 [2-6] 83 C8 FF"
                )
            ),
            Candidate::direct(
                "ProxyLoadParticleEmitter_P2_ReserveSlotParams",
                Pattern::literal(
                    "48 8D 55 ?? E8 ?? ?? ?? ?? 48 8B 07 48 8B CF FF 50 ?? 48 8B 17 48 8B CF 48 8B D8 FF 52 ??"
                ),
                -0x33
            ),
            Candidate::direct(
                "ProxyLoadParticleEmitter_P3_PrimeSerializeQueue",
                Pattern::literal("8A 45 ?? 49 8D 4E 70 88 45 ?? 48 8D 55 ?? 8A 45 ?? 88 45 ?? E8"),
                -0xA8
            ),
        };

        // ProxySetSlotLocalTM: CRenderProxy::SetSlotLocalTM (called, loot effects). 2 rungs, most specific first.
        inline const Candidate PROXY_SET_SLOT_LOCAL_TM_CANDIDATES[] = {
            Candidate::direct(
                "ProxySetSlotLocalTM_P1_Prologue",
                Pattern::literal(
                    "40 55 48 8B EC 48 83 EC 60 4D 8B D0 E8 ?? ?? ?? ?? 84 C0 [2-6] 41 0F 10 02 83 65 FC 00 48 89 4D "
                    "C0 48 83 C1 70"
                )
            ),
            Candidate::direct(
                "ProxySetSlotLocalTM_P2_QueueRowCopy",
                Pattern::literal(
                    "48 83 C1 70 0F 11 45 CC 89 55 C8 48 8D 55 C0 41 0F 10 42 10 0F 11 45 DC 41 0F 10 42 20"
                ),
                -0x21
            ),
        };

        // ProxyFreeSlot: CRenderProxy::FreeSlot (called, loot effects). 3 rungs, most specific first.
        inline const Candidate PROXY_FREE_SLOT_CANDIDATES[] = {
            Candidate::direct(
                "ProxyFreeSlot_P1_Prologue",
                Pattern::literal(
                    "4C 8B DC 49 89 5B 08 49 89 73 10 57 48 83 EC 40 0F BA A9 ?? ?? ?? ?? 1A 48 8B D9 85 D2 [2-6] 48 "
                    "8B 89 88 00 00 00"
                )
            ),
            Candidate::direct(
                "ProxyFreeSlot_P2_QueueSlotDelete",
                Pattern::literal(
                    "49 89 5B E8 49 63 40 08 49 8D 53 E8 49 89 73 F0 48 8D 0C 80 48 C1 E1 05 48 03 0D ?? ?? ?? ?? E8"
                ),
                -0x54
            ),
            Candidate::direct(
                "ProxyFreeSlot_P3_TrimTrailingSlots",
                Pattern::literal(
                    "48 FF C8 48 3B F8 [2-6] 48 85 FF [2-6] 48 8B 83 ?? ?? ?? ?? 48 83 3C F8 00 [2-6] 48 83 83 ?? ?? "
                    "?? ?? F8 48 83 EF 01"
                ),
                -0x96
            ),
        };

        // ParticleLoadLibrary: CParticleManager::LoadLibrary(name, XmlNodeRef &, bLoadResources), IParticleManager
        // vtable slot 9 (vtable validator, the mod's particle library). 3 rungs, most specific first. "System.Default"
        // is referenced twice, so no string rung.
        inline const Candidate PARTICLE_LOAD_LIBRARY_CANDIDATES[] = {
            Candidate::direct(
                "ParticleLoadLibrary_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ?? 80 "
                    "B9 ?? ?? ?? ?? 00"
                )
            ),
            Candidate::direct(
                "ParticleLoadLibrary_P2_EnabledArgs",
                Pattern::literal("80 B9 ?? ?? ?? ?? 00 45 8A E9 4D 8B F0 4C 8B E2 48 8B F9 [2-6] 32 C0"),
                -0x1F
            ),
            Candidate::direct(
                "ParticleLoadLibrary_P3_ChildLoop",
                Pattern::literal(
                    "49 8B 0E 48 8B 01 FF 90 ?? ?? ?? ?? 33 F6 44 8B F8 85 C0 [2-6] 49 8B 0E 48 8D 55 ?? 44 8B C6"
                ),
                -0xCE
            ),
        };

        // XmlLoadFromBuffer: CXmlUtils::LoadXmlFromBuffer, CXmlUtils vtable slot 2 (vtable validator, the mod's
        // particle library). 2 rungs, most specific first.
        inline const Candidate XML_LOAD_FROM_BUFFER_CANDIDATES[] = {
            Candidate::direct(
                "XmlLoadFromBuffer_P1_Prologue",
                Pattern::literal(
                    "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 50 48 8B F2 48 8D 4C 24 30 8A 94 24 80 00 00 00 49 8B "
                    "D9 49 8B F8 E8"
                )
            ),
            Candidate::direct(
                "XmlLoadFromBuffer_P2_ParseBufferArgs",
                Pattern::literal(
                    "44 8B CB C6 44 24 20 01 4C 8B C7 48 8D 4C 24 30 48 8B D6 E8 ?? ?? ?? ?? 48 8D 4C 24 30 E8"
                ),
                -0x29
            ),
        };

        // ManagerCreateEmitter: CParticleManager::CreateEmitter(loc, effect, uEmitterFlags, SpawnParams *) (called,
        // free-standing effects). 3 rungs, most specific first.
        inline const Candidate MANAGER_CREATE_EMITTER_CANDIDATES[] = {
            Candidate::direct(
                "ManagerCreateEmitter_P1_Prologue",
                Pattern::literal(
                    "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 56 41 57 48 83 EC 30 45 8B F9 "
                    "49 8B F0 4C 8B E2 48 8B E9 4D 85 C0"
                )
            ),
            Candidate::direct(
                "ManagerCreateEmitter_P2_EmitterListAlloc",
                Pattern::literal("48 8D 99 ?? ?? ?? ?? 49 8B C8 E8 ?? ?? ?? ?? 48 8B CB 0F BA E0 09 [2-6] E8"),
                -0x32
            ),
            Candidate::direct(
                "ManagerCreateEmitter_P3_ConstructAddRef",
                Pattern::literal(
                    "4D 8B C4 48 89 44 24 20 48 8B D6 49 8B CA E8 ?? ?? ?? ?? 48 8B F8 F0 FF 40 50 4C 8B 00 B2 01 48 "
                    "8B C8 41 FF 90 ?? ?? ?? ??"
                ),
                -0x75
            ),
        };

        // EmitterKill: the CParticleEmitter::Kill body behind the slot 68 command thunk (call-chain validator,
        // free-standing effects). The thunks of slots 68 to 70 differ only in their call target, so the ladder names
        // the body that the Kill dispatcher calls. 2 rungs, most specific first.
        inline const Candidate EMITTER_KILL_CANDIDATES[] = {
            Candidate::direct(
                "EmitterKill_P1_Prologue",
                Pattern::literal(
                    "40 53 48 83 EC 20 48 8B D9 48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B 0B E8 ?? ?? ?? "
                    "?? 48 8B 03 0F 57 C0"
                )
            ),
            Candidate::direct(
                "EmitterKill_P2_DeadAgeStore",
                Pattern::literal(
                    "F3 0F 10 88 ?? ?? ?? ?? 0F 2F C8 [2-6] C7 40 ?? 28 6B 6E CE C7 80 ?? ?? ?? ?? 28 6B 6E CE"
                ),
                -0x27
            ),
        };
    } // namespace aob

    /**
     * @brief Stable identity for every game-image anchor the mod resolves at startup.
     * @details Indexes the declarative anchor table and the resolved-address store. The enumerator order IS the table
     *          order. Count is the element count, not a valid anchor.
     */
    enum class AnchorId : std::size_t
    {
        /// SSystemGlobalEnvironment base (data).
        Genv,
        /// Global-context storage slot (data).
        Context,
        /// CCryAction singleton storage slot (data).
        CryActionFramework,
        /// CCryAction::PostUpdate (hooked, main-thread tick).
        PostUpdate,
        /// CEntitySystem::GetEntity (vtable validator).
        GetEntity,
        /// CEntitySystem::GetEntityIterator (vtable validator).
        GetEntityIterator,
        /// CEntity::GetProxy (vtable validator).
        GetProxy,
        /// CEntity::GetWorldBounds (vtable validator).
        GetWorldBounds,
        /// C3DEngine::RegisterEntity (vtable validator).
        RegisterEntity,
        /// C3DEngine::UnRegisterEntityDirect (vtable validator).
        UnRegisterEntity,
        /// C3DEngine::SetPostEffectParam (vtable validator).
        SetPostEffectParam,
        /// The r_CustomVisions value (data).
        CustomVisionsCvar,
        /// The r_PostProcessGameFx value (data).
        PostProcessGameFxCvar,
        /// The gRenDev renderer slot (data).
        RenDev,
        /// C3DEngine::GetObjectsInBox (called).
        GetObjectsInBox,
        /// CObjManager instance slot (data).
        ObjManager,
        /// The herb-type lookup by model-path hash (called).
        HerbType,
        /// CMergedMeshesManager instance slot (data).
        MergedMeshesManager,
        /// EntityModule.GetInventoryOwner's resolver: the WUID of an inventory's owner (called).
        InventoryOwner,
        /// C_FactionManager's relation of a faction to a soul (vtable validator).
        PublicEnemyRelation,
        /// The C_FactionManager singleton (data).
        FactionManager,
        /// C_Actor::CanLoot (called).
        CanLoot,
        /// C_RPGInventory's legality test for an item a soul owns (called).
        LegalToTake,
        /// CParticleManager::FindEffect (vtable validator, loot effects).
        FindEffect,
        /// CRenderProxy::LoadParticleEmitter (called, loot effects).
        ProxyLoadParticleEmitter,
        /// CRenderProxy::SetSlotLocalTM (called, loot effects).
        ProxySetSlotLocalTM,
        /// CRenderProxy::FreeSlot (called, loot effects).
        ProxyFreeSlot,
        /// CParticleManager::LoadLibrary from an XML node (vtable validator, the mod's particle library).
        ParticleLoadLibrary,
        /// CXmlUtils::LoadXmlFromBuffer (vtable validator, the mod's particle library).
        XmlLoadFromBuffer,
        /// CParticleManager::CreateEmitter (called, free-standing effects).
        ManagerCreateEmitter,
        /// CParticleEmitter::Kill body behind the slot 68 command thunk (call-chain validator, free-standing effects).
        EmitterKill,
        /// CD3D9Renderer::FX_RenderCustomScene, the HUD silhouette mask draw (hooked, mask state).
        RenderCustomScene,
        /// The renderer's ForceStateOr member offset (code operand).
        ForceStateOr,
        /// The renderer's PersFlags2 member offset (code operand).
        PersFlags2,
        /// The PersFlags2 bit that selects the %_RT_SAMPLE5 custom-pass permutation (code operand).
        Post3dSample5Bit,
        /// The r_ShadersAllowCompilation value (data).
        ShadersAllowCompilationCvar,
        /// CStatObj::RenderInternal (hooked, outline copies).
        StatObjRenderInternal,
        /// CStatObj::Render (called, outline copies).
        StatObjRender,
        /// CMatMan::LoadMaterialFromXml (vtable validator, mask materials).
        MatManLoadFromXml,
        /// CXmlUtils::LoadXmlFromFile (vtable validator, mask materials).
        XmlLoadFromFile,
        /// CXmlNode::setAttr, the string overload (vtable validator, mask materials).
        XmlNodeSetAttr,
        /// CXmlNode::findChild (vtable validator, mask materials).
        XmlNodeFindChild,
        /// CXmlNode::getChild (vtable validator, mask materials).
        XmlNodeGetChild,
        /// CXmlNode::getChildCount (vtable validator, mask materials).
        XmlNodeGetChildCount,
        /// CXmlNode::getAttr(key), the string overload (vtable validator, mask materials).
        XmlNodeGetAttr,
        /// Enumerator count. Not an anchor.
        Count,
    };

    /// Number of anchors in the registry.
    inline constexpr std::size_t ANCHOR_COUNT = static_cast<std::size_t>(AnchorId::Count);

    /**
     * @brief A mod feature gated on the anchors it depends on.
     * @details The enumerator order IS the order of the feature table in aob_resolver.cpp.
     */
    enum class Feature : std::size_t
    {
        /// gEnv, which everything engine-facing reads through.
        Core,
        /// The global context the dialogue, combat and minigame gates read.
        GameState,
        /// The CCryAction singleton the local-player chain starts from.
        Framework,
        /// Entity lookup and its render proxy: every highlight.
        EntityLookup,
        /// Entity world bounds (markers and interactable sizes).
        EntityBounds,
        /// The entity-system iterator (the container index walk).
        EntityIteration,
        /// Render-node re-registration (the always-visible list).
        RenderRegistration,
        /// An inventory's owner (stolen-item rules).
        InventoryOwner,
        /// The public-enemy test (the Hostile tag, legal loot, the stash steal prompt).
        PublicEnemy,
        /// The game's own loot test, C_Actor::CanLoot (corpse rules).
        CanLoot,
        /// The game's own theft test for what a soul owns (carcass rules).
        LegalToTake,
        /// The 3D-engine octree query (interactables and static objects).
        Octree,
        /// The octree query, the CObjManager slot and the herb-type lookup (herbs).
        HerbScan,
        /// The main-thread tick.
        Tick,
        /// The CHudSilhouettes parameters (strength and fill of every silhouette).
        NativeSilhouette,
        /// The renderer state a native silhouette needs (r_CustomVisions, r_PostProcessGameFx, the effect itself).
        SilhouetteState,
        /// Particle effects attached to highlighted loot (a group's Effect).
        LootEffects,
        /// The mod's own particle library (KCD1_HenrySenses.particles.xml, effects HenrySenses.*).
        EffectLibrary,
        /// Free-standing effects on objects without an entity slot (interactables, herbs, static objects).
        WorldEffects,
        /// The mask-pass state override: see-through and no near fade ([Render] SeeThrough).
        MaskState,
        /// Outline copies of herbs and static scenery (CStatObj::RenderInternal and CStatObj::Render).
        OutlineCopies,
        /// The materials outline copies are drawn with (material XML load, edit and material creation).
        MaskMaterial,
        /// Enumerator count. Not a feature.
        Count,
    };

    /// Number of feature gates.
    inline constexpr std::size_t FEATURE_COUNT = static_cast<std::size_t>(Feature::Count);

    /**
     * @brief Resolves every anchor in one parallel pass, records the results and publishes the gates.
     * @details Loads the signature file first. Confined to the WHGame.dll image [module_base, module_base +
     *          module_size). A miss records 0 and its features fail their gates. With [Settings] ExportSignatures,
     *          the built-in signatures are then written to the export file.
     * @param module_base WHGame.dll base address.
     * @param module_size WHGame.dll image size.
     * @note Setup and control plane only: allocates and spawns a transient worker pool. Call once from init().
     */
    void resolve_all_anchors(std::uintptr_t module_base, std::size_t module_size);

    /**
     * @brief Returns the resolved absolute address for an anchor, or 0 if it did not resolve.
     * @note Callback-safe: a bounds check and an array read. Enable a feature through feature_ready(), not through
     *       this address.
     */
    [[nodiscard]] std::uintptr_t anchor_address(AnchorId id) noexcept;

    /**
     * @brief Returns the label of an anchor, for log lines.
     * @return The static label; "?" for an out-of-range id.
     */
    [[nodiscard]] const char *anchor_label(AnchorId id) noexcept;

    /**
     * @brief Returns the retained per-anchor resolution report (the drift report).
     * @return The report span, empty before resolve_all_anchors() runs.
     * @note The entries live in static storage for the process lifetime; the span never dangles.
     */
    [[nodiscard]] std::span<const DMK::anchor::ResolvedAnchor> anchor_report() noexcept;

    /**
     * @brief Returns a feature's gate verdict (anchor::evaluate_gate over its anchors, the fail-closed default).
     * @return Fail before resolve_all_anchors() has run.
     * @note Callback-safe: two atomic loads.
     */
    [[nodiscard]] DMK::anchor::GateVerdict feature_gate(Feature feature) noexcept;

    /**
     * @brief Returns whether a feature can run: its gate did not fail.
     * @note Callback-safe.
     */
    [[nodiscard]] bool feature_ready(Feature feature) noexcept;

    /**
     * @brief Returns an anchor's address when @p feature is ready, else 0.
     * @note Callback-safe.
     */
    [[nodiscard]] std::uintptr_t gated_anchor_address(Feature feature, AnchorId id) noexcept;

    /**
     * @brief Returns the value a code-operand anchor decoded (a member offset, a bit) when @p feature is ready.
     * @return The value, or std::nullopt when the feature failed or the anchor did not resolve.
     * @note Callback-safe.
     */
    [[nodiscard]] std::optional<std::int64_t> gated_anchor_value(Feature feature, AnchorId id) noexcept;

    /**
     * @brief Returns a feature's name, for log lines.
     * @return The static name; "?" for an out-of-range feature.
     */
    [[nodiscard]] const char *feature_name(Feature feature) noexcept;

} // namespace HenrySenses

#endif // HENRYSENSES_AOB_RESOLVER_HPP
