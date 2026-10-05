/**
 * @file aob_resolver.hpp
 * @brief Cascading AOB candidate tables and the declarative anchor registry for the mod.
 *
 * Every memory location the mod hooks or reads is located by a cascade of ordered AOB candidates rather
 * than a single signature, so a game patch that shifts code only has to leave ONE of the anchors intact for
 * the feature to keep working. DetourModKit's declarative anchor registry drives the resolve over the
 * DMK::scan::resolve ladder, confined to the WHGame.dll image the caller passes as module_base and
 * module_size, NOT the whole process: a generic prologue candidate could otherwise false-match inside
 * another injected module and shadow the correct in-module one.
 *
 * Every game-image address the mod hooks or reads is resolved at runtime; no static RVAs are baked in. Most
 * targets carry a multi-candidate cascade here (Context, Genv, CryActionFramework, Frustum, HeadVisibility,
 * InputDispatch, ActionDispatch, InteractorLookRay, OverlayHide, MenuOpen); a total cascade miss fails closed
 * at the consumer (the feature degrades or that init step fails). To keep the KCD1 mod a faithful mirror of
 * KCD2 (same AnchorId set, same anchor_address() API so the ported modules compile unchanged), the AnchorId
 * enum mirrors KCD2's; the KCD1 anchor TABLE wires the cascades above and leaves the rest empty (their ids
 * resolve to 0). RayWorldIntersection / GetObjectsInBox are reached via gEnv member + live vtable slot, so
 * they are not in the table.
 *
 * Resolution shapes (DMK::scan::Mode -> the DMK::scan::Candidate factory):
 *   - Direct      address = match + walk_back. Entry-hook targets resolve to the function entry (walk_back
 *                 0); mid-body anchors use a negative walk_back equal to the entry->anchor byte distance.
 *   - RipRelative address = (match + instruction_length) + int32(match + displacement_at). Resolves a
 *                 mov/lea [rip+disp32] to the data slot it references (the global-context storage slot, the
 *                 g_env base, the CCryAction singleton slot).
 *
 * Both offsets are measured from the pattern's `|` result marker, or from the pattern start when the pattern
 * carries none. instruction_length is bounded at the x86-64 maximum instruction length of 15 bytes, so every
 * RipRelative candidate whose referencing instruction is not at the pattern start marks it with `|`.
 *
 * A direct call (`E8 rel32`) carries no RIP-relative MEMORY operand, so a RipRelative candidate cannot decode
 * its target. The call-site rungs therefore live in their own table (k_call_site_fallbacks): each is a Direct
 * candidate that lands on the E8 itself, and resolve_all_anchors() decodes the call target with
 * DMK::scan::resolve_rip_relative when, and only when, the target's own cascade missed. That keeps the three-
 * way redundancy the cascades were authored with (two in-function rungs plus one independent call site).
 *
 * Every candidate below was verified to return exactly one match inside WHGame.dll, and every cascade (call
 * site included) resolves to one target.
 */
#ifndef TPVCAMERA_AOB_RESOLVER_HPP
#define TPVCAMERA_AOB_RESOLVER_HPP

#include <DetourModKit.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace TPVCamera
{
    namespace Aob
    {
        using DMK::scan::Candidate;
        using DMK::scan::Pattern;

        // Global context singleton storage slot (qword_1834FFD10)
        // The root of the camera-manager + minigame game-state walks. A magic-static getter returns the
        // pointer held in this fixed .data slot; each candidate decodes one getter's `mov rax, cs:[rip+ctx]`
        // (the guard-then-load shape `cmp cs:guard,reg; jg init; mov rax, cs:ctx`) back to the SLOT address.
        // The distinctive instruction(s) AFTER the load make each site unique - the guard+load prefix alone is
        // the generic shape shared by every such getter, so the suffix carries the identity. game_interface
        // publishes this slot ADDRESS (not the pointer it holds, which is null until a level loads); a total
        // cascade miss fails closed. The `|` marks the 7-byte `mov rax,[rip+ctx]` load (disp32 at +3).
        inline const Candidate k_contextCandidates[] = {
            // sub_18033BF10: mov rax, cs:ctx; mov rcx,r12; mov rbx,[rax+128h].
            Candidate::rip_relative(
                "Context_P1_GetterMovRcxR12",
                Pattern::literal("39 0D ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 49 8B CC 48 8B 98 ?? ?? "
                                 "?? ??"),
                3, 7),
            // sub_18033C628: mov rax, cs:ctx; mov rbx,[rsp+disp]; mov rax,[rax+8].
            Candidate::rip_relative(
                "Context_P2_GetterMovRbxStack",
                Pattern::literal("39 05 ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 8B 40 "
                                 "08"),
                3, 7),
            // sub_180430AA4 (the framework getter): mov rax, cs:ctx; mov rbx,[rsp+disp]; add rsp,20h; pop rdi;
            // ret. The epilogue tail is kept literal to beat the generic getter shape.
            Candidate::rip_relative(
                "Context_P3_GetterEpilogue",
                Pattern::literal("39 05 ?? ?? ?? ?? 0F 8F ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 "
                                 "20 5F C3"),
                3, 7),
        };

        // SSystemGlobalEnvironment (g_env) base
        // g_env is an embedded global struct in this CryEngine 3.8 fork (not a pointer), reached by code
        // through RIP-relative references. Each candidate decodes one such reference back to the struct base;
        // the disp32 is wildcarded so the pattern survives the struct or the referencing code moving. Three
        // independent reference sites in three different functions give real cascade redundancy; resolve_genv()
        // in camera_hook fails closed (returns 0) on a total miss. All three resolve to the same g_env base.
        inline const Candidate k_genvCandidates[] = {
            // sub_180E91554 struct-init: `lea rax,g_env; lea rcx,Y; mov [rdi],rcx`. The lea is at the pattern
            // start (disp32 at +3, 7-byte lea). KCD1 analog of KCD2's Genv_P2_LeaStructInit.
            Candidate::rip_relative("Genv_P1_LeaStructInit",
                                    Pattern::literal("48 8D 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 0F"), 3, 7),
            // sub_181A1F380: `mov rdx,[rax]; call [rdx+8]; mov rcx,g_env; test rcx,rcx; jz; mov rax,[rcx]; xor
            // edx,edx; call [rax+0x18]`. The `|` marks the mov rcx,g_env; the call lead-in + null-check tail make
            // the otherwise-generic mov-g_env site unique.
            Candidate::rip_relative(
                "Genv_P2_MovNullCheckVCall",
                Pattern::literal("48 8B 10 FF 52 08 | 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 08 48 8B 01 33 D2 FF 50 18"), 3,
                7),
            // sub_1819BAEEC: `call X; mov rcx,g_env; test rcx,rcx; jz +0x15; mov rax,[rcx]; xor edx,edx; call
            // [rax+0x18]`. The `|` marks the mov past the call; the 0x15 jz displacement + tail distinguish it
            // from the other null-check sites.
            Candidate::rip_relative(
                "Genv_P3_CallMovNullCheck",
                Pattern::literal("E8 ?? ?? ?? ?? | 48 8B 0D ?? ?? ?? ?? 48 85 C9 74 15 48 8B 01 33 D2 FF 50 18"), 3, 7),
        };

        // CCryAction (game framework) singleton pointer slot (g_pGameFramework)
        // The root of the C_Player chain. KCD2 reached the framework via gEnv->pGame->GetIGameFramework();
        // KCD1 has the CCryAction singleton in a fixed .data slot that the framework-creation path fills
        // (CCryAction::CCryAction -> `mov cs:g_pGameFramework, rax`). The embedded singleton's module-relative
        // offset is build-specific (it moves between game builds), so rather than hard-coding it the slot
        // ADDRESS is resolved here from three independent RIP-relative references and the consumer dereferences
        // it (camera_hook resolve_cry_action()), exactly as the Context / Genv slots are. Each candidate decodes
        // a `mov reg, cs:g_pGameFramework` back to the SLOT; the load sits at the pattern start (disp32 at +3,
        // 7-byte instruction). The slot's VALUE is the live CCryAction object the player walk reads; it holds
        // null until the framework is constructed, and resolution is runtime-only (a total cascade miss returns
        // 0). All three are unique and resolve to the same slot on both the Steam and GOG builds.
        inline const Candidate k_cryActionFrameworkCandidates[] = {
            // sub_18212E348 shutdown path: `mov rcx, cs:g_pGameFramework; test rcx,rcx; jz; mov rax,[rcx];
            // call [rax+50h]`. The `call qword[rax+0x50]` (FF 50 50) past the null-check is the rare landmark.
            Candidate::rip_relative("CryActionFramework_P1_ShutdownVCall",
                                    Pattern::literal("48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 50 50"), 3, 7),
            // sub_1821399BC (C_Game::CreateInstance path): `mov rcx,cs:slot; mov rax,[rcx]; call [rax+98h];
            // mov rcx,cs:slot; call CreateInstance`. The two slot loads bracketing call[rax+0x98] are unique.
            Candidate::rip_relative(
                "CryActionFramework_P2_CreateInstance",
                Pattern::literal("48 8B 0D ?? ?? ?? ?? 48 8B 01 FF 90 98 00 00 00 48 8B 0D ?? ?? ?? ?? E8"), 3, 7),
            // sub_182135608 (framework-create prologue): `mov rax,cs:slot; mov r13,r8; mov rsi,rdx; mov r15,rcx;
            // test rax,rax`. The r13/rsi/r15 arg-shuffle of this specific function is the landmark.
            Candidate::rip_relative("CryActionFramework_P3_CreatePrologue",
                                    Pattern::literal("48 8B 05 ?? ?? ?? ?? 4D 8B E8 48 8B F2 4C 8B F9 48 85 C0"), 3, 7),
        };

        // Camera frustum builder (CCamera::UpdateFrustumPlanes) entry
        // The engine function that turns a camera's 3x4 matrix into world cull planes. It runs once per
        // CView per frame with the camera in rcx, immediately after CView::Update rebuilds the matrix, so it
        // is the final render-camera chokepoint where a third-person offset both moves the view and keeps
        // culling consistent. P1 pins the function entry; P2 pins the matrix-read body 15 bytes in and walks
        // back to the entry, so resolution survives a sibling mod inline-hooking the 5-byte prologue. The
        // third, fully independent rung is the call site in sub_1803E36CC (k_frustumCallSite below).
        inline const Candidate k_frustumCandidates[] = {
            Candidate::direct("Frustum_P1_PrologueMatrixRead",
                              Pattern::literal("48 8B C4 55 48 8D 68 ?? 48 81 EC ?? ?? ?? ?? F3 0F 10 51 14 4C 8B C1")),
            Candidate::direct("Frustum_P2_MatrixReadBody",
                              Pattern::literal("F3 0F 10 51 14 4C 8B C1 F3 0F 10 69 10 F3 0F 10 41 08 F3 0F 10 59 18"),
                              -15),
        };

        // Head-visibility setter entry
        // SetHeadHidden(entity /*rcx*/, bool hide /*dl*/, char flags /*r8b*/) - the first-person rig calls
        // this to hide the player's head; forcing hide = false keeps it visible from behind. P1 is the unique
        // argument-shuffle body `mov sil,r8b; mov dil,dl; mov rbx,rcx; call; test al,al`, walked back 0x0F (the
        // prologue's exact stack saves are not pinned, and the trailing branch is left out - a Jcc opcode can
        // flip between its rel8 and rel32 encodings across builds); P2 is the distinctive flag-write pair
        // `mov [rbx+disp],dil; mov [rbx+disp],sil` deeper in the body (disps wildcarded so it survives a
        // struct-layout shift). The independent call-site rung is k_headVisibilityCallSite below.
        inline const Candidate k_headVisibilityCandidates[] = {
            Candidate::direct("Head_P1_BodyMovSilDilRbxCall",
                              Pattern::literal("41 8A F0 40 8A FA 48 8B D9 E8 ?? ?? ?? ?? 84 C0"), -0xF),
            Candidate::direct(
                "Head_P2_FlagWriteDilSil",
                Pattern::literal("48 8B 8B ?? ?? ?? ?? 40 88 BB ?? ?? ?? ?? 40 88 B3 ?? ?? ?? ?? 48 85 C9"), -0x48),
        };

        // Generic input-event dispatcher entry (CBaseInput::PostInputEvent)
        // KCD1 hook point sub_1803E60B8 (CBaseInput vtable slot 12). Every input event funnels through it; the
        // free-look orbit hooks it to capture the look delta and freeze look input while orbiting. It is only
        // ever called virtually (no direct call site exists), so all three anchors are in-function landmarks
        // in different regions of the body, each walking back to the entry; resolution is runtime-only (a total
        // miss fails closed, disabling free-look orbit). P1 is the prologue; P2 is the
        // `m_flags |= 2` self-init guard (`mov al,[rcx+disp]; test al,2; jnz; or al,2; mov [rcx+disp],al`,
        // disps wildcarded); P3 is the deeper event-type dispatch (`call; cmp [rdi+disp], 1002h`), the most
        // independent of the three.
        inline const Candidate k_inputDispatchCandidates[] = {
            Candidate::direct("Input_P1_Prologue",
                              Pattern::literal("48 89 5C 24 ?? 57 48 83 EC 50 48 8B FA 48 8B D9 45 84 C0")),
            Candidate::direct("Input_P2_SelfInitFlag",
                              Pattern::literal("8A 81 ?? ?? ?? ?? A8 02 0F 85 ?? ?? ?? ?? 0C 02 88 81 ?? ?? ?? ??"),
                              -0x21),
            Candidate::direct("Input_P3_EventTypeDispatch",
                              Pattern::literal("48 8B D7 48 8B CB E8 ?? ?? ?? ?? 81 7F ?? 02 10 00 00"), -0x57),
        };

        // Global action dispatcher (sub_1801FF740, the C++ source of Lua Player:OnAction)
        // The orbit move-detection hook taps this: it fires once per action-map action with the action name,
        // activation and value. It is reached only virtually (every xref is a vtable data slot), so the three
        // anchors are in-function landmarks at increasing depth, each walking back to the entry; resolution is
        // runtime-only (a total miss fails closed, disabling orbit move-detection).
        inline const Candidate k_actionDispatchCandidates[] = {
            // Prologue: mov rax,rsp; shadow-save rbx/rsi; movss [rax+disp],xmm3; push rbp/rdi/r12/r14/r15;
            // lea rbp,[rax-disp]; sub rsp,imm32. The xmm3 store and the r12/r14/r15 push run are the rare bytes.
            Candidate::direct("ActionDispatch_P1_Prologue",
                              Pattern::literal("48 8B C4 48 89 58 ?? 48 89 70 ?? F3 0F 11 58 ?? 55 57 41 54 41 56 41 "
                                               "57 48 8D 68 ?? 48 81 EC ?? ?? ?? ??")),
            // Mid-body (entry+0xA5): mov r8d,esi; lea rdx,[rbp-disp]; mov rcx,[rax+disp32]; mov rcx,[rcx+disp32];
            // call; mov rax,[r14+disp]. The chained double-deref (48 8B 88 / 48 8B 89) is the rare landmark.
            Candidate::direct("ActionDispatch_P2_DoubleDeref",
                              Pattern::literal("44 8B C6 48 8D 55 ?? 48 8B 88 ?? ?? ?? ?? 48 8B 89 ?? ?? ?? ?? E8 ?? "
                                               "?? ?? ?? 49 8B 46 ??"),
                              -0xA5),
            // Mid-body (entry+0xBF): mov rax,[r14+disp]; lea rdx,[rbp+disp]; mov [rsp+disp],rdx;
            // lea rcx,[r14+disp32]; movss [rsp+disp],xmm6; mov r9,r15; mov rdx,r14.
            Candidate::direct("ActionDispatch_P3_StructLea",
                              Pattern::literal("49 8B 46 ?? 48 8D 55 ?? 48 89 54 24 ?? 49 8D 8E ?? ?? ?? ?? F3 0F 11 "
                                               "74 24 ?? 4D 8B CF 49 8B D6"),
                              -0xBF),
        };

        // In-game menu open/close toggle (sub_1805B84CC, DisplayIngameMenu; state byte at this+0x41)
        // The menu game-state hook taps this. KCD1 has a single toggle (no separate open/close functions), so
        // it is wired to AnchorId::MenuOpen and the MenuClose row stays empty. Both in-function rungs resolve to
        // the entry; the independent call-site rung is k_menuToggleCallSite below. Resolution is runtime-only (a
        // total miss fails closed).
        inline const Candidate k_menuToggleCandidates[] = {
            // Prologue: shadow-save rbx/rbp/rsi; push rdi; sub rsp,20h; mov sil,dl; mov rdi,rcx; cmp [rcx+disp],dl.
            Candidate::direct("MenuToggle_P1_Prologue",
                              Pattern::literal("48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 40 8A F2 "
                                               "48 8B F9 38 51 ??")),
            // Mid-body (entry+0x55): mov r8,[rbx]; mov rcx,rbx; mov rdx,[rax+disp]; add rdx,imm32;
            // call qword[r8+disp32]. The add-immediate (struct offset) is needed to beat the generic vtable-call
            // shape, which collides without it.
            Candidate::direct(
                "MenuToggle_P2_AddStructVCall",
                Pattern::literal("4C 8B 03 48 8B CB 48 8B 50 ?? 48 81 C2 ?? ?? ?? ?? 41 FF 90 ?? ?? ?? ??"), -0x55),
        };

        // Action-filter Enable/DisableFilter worker (sub_1804FCC0C)
        // The overlay / apse UI signal hook taps this enable/disable convergence point. KCD1 has a single
        // worker (no separate hide/show functions), so it is wired to AnchorId::OverlayHide and the OverlayShow
        // row stays empty. Both in-function rungs resolve to the entry; the independent call-site rung is
        // k_actionFilterWorkerCallSite below. Resolution is runtime-only (a total miss fails closed).
        inline const Candidate k_actionFilterWorkerCandidates[] = {
            // Prologue: mov rax,rsp; shadow-save rbx/rbp/rsi; push rdi; sub rsp,30h; mov esi,r9d; mov bpl,r8b;
            // mov rdi,rdx; mov rbx,rcx. The bpl/esi byte moves of the 4-arg shuffle are the rare bytes.
            Candidate::direct("ActionFilterWorker_P1_Prologue",
                              Pattern::literal("48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70 ?? 57 48 83 EC ?? 41 8B F1 "
                                               "41 8A E8 48 8B FA 48 8B D9")),
            // Mid-body (entry+0x55), the "filter found vs map.end()" check: mov rax,[rsp+disp];
            // cmp rax,[rbx+disp]; jz <missing-filter path>; mov rcx,[rax+disp]; mov edx,esi; mov rax,[rcx];
            // test bpl,bpl (the enable/disable selector). The far jz keeps its 0F 84 opcode, rel32 wildcarded.
            Candidate::direct("ActionFilterWorker_P2_FilterCompare",
                              Pattern::literal("48 8B 44 24 ?? 48 3B 43 ?? 0F 84 ?? ?? ?? ?? 48 8B 48 ?? 8B D6 48 8B "
                                               "01 40 84 ED"),
                              -0x55),
        };

        // Interactor selection / look-ray builder (sub_1803E51EC)
        // The camera-space interaction hook wraps this to slide the selection ray onto the render camera +
        // crosshair. It is reached virtually, so the three anchors are in-function landmarks (all already past
        // the 5-byte prologue, so a sibling prologue hook does not break them), each walking back to the entry;
        // resolution is runtime-only (a total miss fails closed).
        inline const Candidate k_interactorLookRayCandidates[] = {
            // Near-entry frame setup (entry+0x16): lea rbp,[rax+disp32]; sub rsp,imm32; mov r14d,[rbp+disp32];
            // mov r15,r8; movaps [rax+disp],xmm6; mov rbp,rdx.
            Candidate::direct("InteractorLookRay_P1_FrameSetup",
                              Pattern::literal("48 8D A8 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 44 8B B5 ?? ?? ?? ?? 4D 8B "
                                               "F8 0F 29 70 ?? 4C 8B EA"),
                              -0x16),
            // Mid-body float-load block (entry+0xFD): movss xmm6,[rdi+disp]; xorps xmm9,xmm9;
            // movss xmm7,[rdi+disp]; movaps xmm4,xmm6; movss xmm8,[rdi+disp]; movaps xmm0,xmm7.
            Candidate::direct("InteractorLookRay_P2_FloatLoads",
                              Pattern::literal("F3 0F 10 77 ?? 45 0F 57 C9 F3 0F 10 7F ?? 0F 28 E6 F3 44 0F 10 47 ?? "
                                               "0F 28 C7"),
                              -0xFD),
            // Mid-body cross-product math (entry+0x194): movaps xmm12,xmm6; addss xmm12,[rip+disp32];
            // addss xmm12,xmm6; movaps xmm6,xmm7; addss xmm6,xmm9. The disp32 is a .rdata float constant ref.
            Candidate::direct("InteractorLookRay_P3_CrossProduct",
                              Pattern::literal("44 0F 28 E6 F3 44 0F 58 25 ?? ?? ?? ?? F3 44 0F 58 E6 0F 28 F7 F3 41 "
                                               "0F 58 F1"),
                              -0x194),
        };

        // Independent call-site rungs (E8 rel32 into the target entry)
        // Each lands, through its `|` marker, on the 5-byte `call target` instruction in a DIFFERENT function from
        // the target, so it survives a rewrite of the target body entirely. resolve_all_anchors() decodes the
        // rel32 (scan::resolve_rip_relative(site, 1, 5)) only when the target's own cascade missed.

        // sub_1803E36CC: `movss [rip+disp], xmm13; call UpdateFrustumPlanes`. The xmm13 RIP store
        // (F3 44 0F 11 2D) is rare enough to make the call unique.
        inline const Candidate k_frustumCallSite[] = {
            Candidate::direct("Frustum_P3_CallSiteMovssXmm13",
                              Pattern::literal("F3 44 0F 11 2D ?? ?? ?? ?? | E8 ?? ?? ?? ??")),
        };

        // `mov r8b,[rdi+disp]; mov rcx,rbx; call SetHeadHidden`.
        inline const Candidate k_headVisibilityCallSite[] = {
            Candidate::direct("Head_P3_CallSite", Pattern::literal("44 8A 47 ?? 48 8B CB | E8 ?? ?? ?? ??")),
        };

        // sub_1805B7B10: `call X; mov dl,1; mov rcx,[rax+18h]; call MenuToggle; add rsp,28h; retn`. The `|`
        // marks the SECOND call (the target); the epilogue tail is kept literal for uniqueness.
        inline const Candidate k_menuToggleCallSite[] = {
            Candidate::direct("MenuToggle_P3_CallSite",
                              Pattern::literal("E8 ?? ?? ?? ?? B2 01 48 8B 48 18 | E8 ?? ?? ?? ?? 48 83 C4 28 C3")),
        };

        // The EnableFilter thunk sub_1804FC414: `sub rsp,38h; mov r9d,r8d; mov [rsp+disp],0; mov r8b,1
        // (enable=true); call ActionFilterWorker`.
        inline const Candidate k_actionFilterWorkerCallSite[] = {
            Candidate::direct("ActionFilterWorker_P3_CallSite",
                              Pattern::literal("48 83 EC ?? 45 8B C8 C6 44 24 ?? ?? 41 B0 ?? | E8 ?? ?? ?? ??")),
        };

        // Return address of the IsThirdPerson call in C_PlayerMovementAction's turn trigger (ComputeMoveState)
        // Direct, NOT a hook target: the IsThirdPerson detour compares its own return address with this one and
        // answers "third person" there, so the free-roam locomotion action starts its turn-in-place fragments once
        // the look leads the body by more than 35 degrees. The `|` marker sits on the instruction after the call.
        // P1 pins the |angle| computation (cvtss2sd, andps abs mask, cvtpd2ps into xmm6, comiss against the move
        // threshold, jbe rel32) into the virtual call; P2 pins the call and the jnz to the decision chunk with the
        // join's 65-degree load; P3 drops P1's float conversions. Each matches exactly once on the Steam and GOG builds.
        inline const Candidate k_turnTriggerReturnCandidates[] = {
            Candidate::direct(
                "TurnTrigger_P1_AbsThroughCall",
                Pattern::literal("F3 41 0F 5A CD 0F 54 0D ?? ?? ?? ?? 66 0F 5A F1 41 0F 2F F0 0F 86 ?? ?? ?? ?? 48 8B "
                                 "03 48 8B CB FF 90 40 02 00 00 |")),
            Candidate::direct("TurnTrigger_P2_CallThroughJoin",
                              Pattern::literal("FF 90 40 02 00 00 | 84 C0 0F 85 ?? ?? ?? ?? 32 C9 F3 0F 10 3D ?? ?? "
                                               "?? ?? 0F 2F FE")),
            Candidate::direct(
                "TurnTrigger_P3_CompareThroughCall",
                Pattern::literal("41 0F 2F F0 0F 86 ?? ?? ?? ?? 48 8B 03 48 8B CB FF 90 40 02 00 00 |")),
        };

        // CAnimatedCharacter::UpdatePhysicalEntityMovement entry
        // Direct entry hook. It receives the frame's movement as a QuatT (rotation, then translation): it composes the
        // rotation into the body and requests the translation from physics as a velocity. Hooked so a native
        // turn-in-place step turns the body without moving it. P1 is the full prologue (mov rax,rsp, the pushes, frame
        // lea and sub) through `mov rdi,rdx`; P2 drops the leading `mov rax,rsp` and walks back 3; P3 anchors on the
        // body after the prologue (`mov r14,[rcx+38h]; xor r13d,r13d`, the xmm saves) and walks back 0x19. Frame
        // sizes wildcarded. Each matches exactly once on the Steam and GOG builds.
        inline const Candidate k_physEntMovementCandidates[] = {
            Candidate::direct(
                "PhysEntMove_P1_PrologueThroughArgs",
                Pattern::literal("48 8B C4 55 53 56 57 41 54 41 55 41 56 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 4C 8B 71 "
                                 "38 45 33 ED 0F 29 70 B8 48 8B D9 0F 29 78 A8 48 8B FA")),
            Candidate::direct(
                "PhysEntMove_P2_PushesThroughBody",
                Pattern::literal("55 53 56 57 41 54 41 55 41 56 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 4C 8B 71 38 45 33 "
                                 "ED 0F 29 70 B8 48 8B D9"),
                -3),
            Candidate::direct(
                "PhysEntMove_P3_BodyAfterPrologue",
                Pattern::literal("4C 8B 71 38 45 33 ED 0F 29 70 B8 48 8B D9 0F 29 78 A8 48 8B FA 44 0F 29 40 98 44 0F "
                                 "29 48 88"),
                -0x19),
        };

        // Return address of the IsThirdPerson call in C_PlayerMovementAction's idle LockBodyTurn sync
        // Direct, NOT a hook target. On an idle fragment start and on SGameObjectEvent 39 the action re-reads
        // IsThirdPerson here and takes (third person) or drops (first person) its LockBodyTurn reference; the
        // detour answers "third person" at this return address so the body stops following the look while idle.
        // P1 pins the preceding GetAnimatedCharacter call (vtable +0x2D0) through the call and the latch-byte read
        // (mov cl,[rbp+0D2h]) that follows; P2 and P3 are shorter windows around the call and the latch read. Each
        // matches exactly once on the Steam and GOG builds.
        inline const Candidate k_lockSyncReturnCandidates[] = {
            Candidate::direct(
                "LockSync_P1_AnimCharThroughLatch",
                Pattern::literal("48 8B 10 FF 92 D0 02 00 00 48 8B 17 48 8B CF 48 8B F0 FF 92 40 02 00 00 | 8A 8D D2 "
                                 "00 00 00")),
            Candidate::direct(
                "LockSync_P2_CallThroughTest",
                Pattern::literal("48 8B 17 48 8B CF 48 8B F0 FF 92 40 02 00 00 | 8A 8D ?? ?? 00 00 84 C0")),
            Candidate::direct("LockSync_P3_CallThroughLatch",
                              Pattern::literal("FF 92 40 02 00 00 | 8A 8D D2 00 00 00 84 C0")),
        };
    } // namespace Aob

    /**
     * @brief Stable identity for every game-image anchor the mod resolves at startup.
     * @details Mirrors the KCD2 AnchorId set so the ported modules compile unchanged, plus the KCD1-specific
     *          CryActionFramework id after GetObjectsInBox, ahead of the native-turn ids (KCD2 reaches the framework
     *          through gEnv, KCD1 through a .data singleton slot). The enumerator order IS the table order; Count is
     *          the element count and is not a valid anchor. On KCD1 the Context, Genv, CryActionFramework, Frustum,
     *          HeadVisibility, InputDispatch, ActionDispatch, InteractorLookRay, OverlayHide (the action-filter
     *          worker), MenuOpen (the menu toggle), TurnTriggerReturn, LockSyncReturn and PhysEntMovement ids carry a
     *          cascade; every other id resolves to 0 (its consumer reaches the target via a gEnv member / vtable
     *          slot, or is stubbed).
     */
    enum class AnchorId : std::size_t
    {
        Context,              // global-context storage slot (KCD1: RIP-relative AOB cascade)
        Genv,                 // SSystemGlobalEnvironment base (KCD1: RIP-relative AOB cascade)
        Frustum,              // camera frustum builder (mandatory hook target)
        HeadVisibility,       // head-visibility setter
        InputDispatch,        // generic input-event dispatcher (KCD1: AOB cascade)
        ActionDispatch,       // global action dispatcher (KCD1: AOB cascade)
        RayWorldIntersection, // IPhysicalWorld::RayWorldIntersection (KCD1: vtable slot, not in the table)
        InteractionRayBuild,  // interaction ray-query builder (KCD1: unused; reserved)
        InteractorLookRay,    // interactor look-ray builder (KCD1: AOB cascade)
        InteractionOnScreen,  // on-screen reticle projection gate (KCD1: stubbed)
        OverlayHide,          // action-filter worker (KCD1: AOB cascade; one toggle for hide/show)
        OverlayShow,          // ShowOverlays (KCD1: folded into OverlayHide's single worker; not in the table)
        MenuOpen,             // menu open/close toggle (KCD1: AOB cascade; one toggle for both)
        MenuClose,            // UI menu-close entry (KCD1: folded into MenuOpen's single toggle; not in the table)
        GetObjectsInBox,      // I3DEngine::GetObjectsInBox (KCD1: vtable slot, not in the table)
        CryActionFramework,   // CCryAction game-framework singleton .data slot (KCD1-specific: RIP-rel AOB cascade)
        TurnTriggerReturn,    // IsThirdPerson return address in the turn trigger (compared, not hooked)
        LockSyncReturn,       // IsThirdPerson return address in the idle LockBodyTurn sync (compared, not hooked)
        PhysEntMovement,      // CAnimatedCharacter::UpdatePhysicalEntityMovement (turn steps kept in place)
        Count,
    };

    /**
     * @brief Resolves every game-image anchor in one parallel pass and records the results.
     * @details Builds the declarative DMK::anchor table over the KCD1 cascade candidate arrays above and
     *          resolves it with anchor::resolve_all_parallel, confined to the WHGame.dll image
     *          [module_base, module_base + module_size). The explicit range is required: the DMK default
     *          DMK::Region::host() is the host EXE, not WHGame.dll. The call-site fallbacks resolve in the same pass
     *          and stand in for a target whose own cascade missed. Each resolved address is stored for
     *          anchor_address(); a per-anchor status line, an assess_quality() summary, and the startup gate
     *          verdict are logged. Anchors with no cascade record 0 and their consumers degrade (fail closed, or
     *          reach the target via a gEnv member / vtable slot).
     * @note Setup/control-plane only: allocates and spawns a transient worker pool. Call once at init.
     */
    void resolve_all_anchors(std::uintptr_t module_base, std::size_t module_size);

    /**
     * @brief Returns the resolved absolute address for an anchor, or 0 if it did not resolve.
     * @note Valid only after resolve_all_anchors() has run; returns 0 before then or on a cascade miss.
     */
    [[nodiscard]] std::uintptr_t anchor_address(AnchorId id) noexcept;

    /**
     * @brief Returns the retained per-anchor resolution report (wired cascades and call-site rungs).
     * @details The same span resolve_all_anchors() logged its quality summary from, kept so
     *          diagnostics::collect() can roll it into the mod's health snapshot rather than the mod
     *          re-deriving the counts. Empty before resolve_all_anchors() has run.
     * @note The entries live in static storage for the process lifetime; the span never dangles.
     */
    [[nodiscard]] std::span<const DMK::anchor::ResolvedAnchor> anchor_report() noexcept;

    /**
     * @brief True when the bytes at @p address are exactly @p code (at most 32 bytes).
     * @details Proves the instructions a hook or an engine call depends on, at their fixed offset from a resolved
     *          address, before the hook goes in or the call is trusted, so a build that moved them is refused.
     * @note One guarded read per call: for install time or a change of the checked code, never per frame.
     */
    [[nodiscard]] bool code_matches(std::uintptr_t address, std::span<const std::uint8_t> code) noexcept;
} // namespace TPVCamera

#endif // TPVCAMERA_AOB_RESOLVER_HPP
