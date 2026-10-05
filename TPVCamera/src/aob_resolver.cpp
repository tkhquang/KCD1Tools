/**
 * @file aob_resolver.cpp
 * @brief Declarative anchor table, one-pass resolution, and the resolved-address store.
 *
 * The candidate ladders in aob_resolver.hpp enter a DetourModKit anchor registry as RipGlobal, CodeOperand and
 * Quorum entries, together with the independent call-site rungs. resolve_all_anchors() resolves the whole table in
 * a single parallel pass at startup and records each result; anchor_address() and anchor_value() hand it, or
 * nothing on a miss, to the call sites. The resolve_* helpers then prove the native-turn hook sites inside the
 * functions those anchors found, with anchors scoped to each function's .pdata range.
 */

#include "aob_resolver.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <optional>
#include <span>
#include <string_view>
#include <tuple>

namespace TPVCamera
{
    namespace
    {
        using DMK::anchor::Anchor;
        using DMK::anchor::AnchorKind;
        using DMK::anchor::AnchorStatus;
        using DMK::anchor::ResolvedAnchor;
        using DMK::scan::Candidate;
        using DMK::scan::OperandKind;
        using DMK::scan::Pages;

        constexpr std::size_t k_anchor_count = static_cast<std::size_t>(AnchorId::Count);

        // The WHGame.dll image the table resolves against, filled by resolve_all_anchors() before the sweep and
        // handed to every anchor's validator as its opaque context.
        DMK::Region s_image_range{};

        /**
         * @brief Post-resolve validator: the resolved value must land inside the game image.
         * @details The scan SCOPE constrains where a candidate's bytes are FOUND, not where the value it decodes
         *          POINTS. A RipRelative candidate resolves an absolute address from a disp32, and a Direct
         *          candidate applies a signed walk-back, so either can compute a target outside WHGame.dll from a
         *          freak match. Every anchor in this table names something inside the game image (a function
         *          entry or a data slot the image owns), so a target outside it is proof the match was wrong.
         *          Returning false resets the value to 0 and reports Failed, exactly like a backend miss, so the
         *          consumer degrades instead of hooking or reading a bogus address.
         * @param value The resolved address.
         * @param context The image Region, forwarded verbatim from Anchor::validator_context.
         */
        [[nodiscard]] bool anchor_target_in_image(std::int64_t value, const void *context) noexcept
        {
            const auto *image = static_cast<const DMK::Region *>(context);
            if (image == nullptr || image->size == 0 || value <= 0)
            {
                return false;
            }
            return image->contains(DMK::Address{static_cast<std::uintptr_t>(value)});
        }

        /**
         * @brief Decodes the callee of the 5-byte `E8 rel32` at @p site, confined to the game image.
         * @return The callee entry, or 0 when the rel32 cannot be read or decodes outside the image.
         */
        [[nodiscard]] std::uintptr_t call_site_target(std::uintptr_t site, const DMK::Region &image) noexcept
        {
            const auto target = DMK::scan::resolve_rip_relative(DMK::Address{site}, 1, 5);
            if (!target || !image.contains(*target))
            {
                return 0;
            }
            return target->raw();
        }

        /**
         * @brief Post-resolve validator for a call-site rung: the site must be an E8 whose callee lies in the image.
         * @details The site itself is in the image by construction of the scope; what proves the rung matched the
         *          intended call is that its rel32 decodes back into WHGame.dll.
         */
        [[nodiscard]] bool call_site_targets_image(std::int64_t value, const void *context) noexcept
        {
            if (!anchor_target_in_image(value, context))
            {
                return false;
            }
            const auto *image = static_cast<const DMK::Region *>(context);
            const auto opcode = DMK::memory::read<std::uint8_t>(DMK::Address{static_cast<std::uintptr_t>(value)});
            return opcode && *opcode == 0xE8 && call_site_target(static_cast<std::uintptr_t>(value), *image) != 0;
        }

        /**
         * @brief A RipGlobal anchor over one ladder.
         * @details Every rung anchors on an in-image instruction, so the byte tiers sweep executable pages only:
         *          an identical byte run in .rdata or .data cannot alias or make a unique code match ambiguous.
         */
        [[nodiscard]] Anchor code_ladder(std::string_view label, std::span<const Candidate> site) noexcept
        {
            return Anchor{
                .label = label,
                .kind = AnchorKind::RipGlobal,
                .site = site,
                .validator = anchor_target_in_image,
                .validator_context = &s_image_range,
                .pages = Pages::Executable,
            };
        }

        /// The call-site form of code_ladder(): the same sweep, with the E8 + in-image callee validator.
        [[nodiscard]] Anchor call_site_ladder(std::string_view label, std::span<const Candidate> site) noexcept
        {
            Anchor anchor = code_ladder(label, site);
            anchor.validator = call_site_targets_image;
            return anchor;
        }

        /// The values a decoded scalar may take: a closed range and an alignment.
        struct ScalarRange
        {
            std::int64_t min;
            std::int64_t max;
            std::int64_t align;
        };

        // A vtable slot's byte offset: pointer-aligned, inside a vtable of at most 1024 slots.
        constexpr ScalarRange k_vtable_offset_range{8, 0x2000, 8};
        // A member offset inside a game object, for a uint8 field and for an int32 or float field.
        constexpr ScalarRange k_byte_field_range{1, 0x4000, 1};
        constexpr ScalarRange k_dword_field_range{4, 0x4000, 4};
        // An SGameObjectEvent id. HandleEvent compares it as `cmp eax, imm8`, which only encodes 0..0x7F.
        constexpr ScalarRange k_event_id_range{1, 0x7F, 1};
        // The event's target/flags word, a non-zero uint32.
        constexpr ScalarRange k_event_flags_range{1, 0xFFFFFFFF, 1};

        /**
         * @brief Post-resolve validator for a scalar anchor: the decoded value must lie in the ScalarRange passed as
         *        @p context.
         * @details A CodeOperand decodes whatever instruction its rung lands on, so a coincidental match yields a
         *          wrong but well-formed number. The range rejects the implausible ones (a vtable offset that is not
         *          pointer-aligned, a member offset beyond any game object), which then report Failed.
         */
        [[nodiscard]] bool scalar_in_range(std::int64_t value, const void *context) noexcept
        {
            const auto *range = static_cast<const ScalarRange *>(context);
            return range != nullptr && value >= range->min && value <= range->max && value % range->align == 0;
        }

        /**
         * @brief A CodeOperand anchor: decodes operand @p operand_index of the instruction its ladder lands on.
         * @param byte_width 0 keeps the decoded value; 4 reads an imm32 as a sign-extended int32.
         */
        [[nodiscard]] Anchor code_operand(std::string_view label, std::span<const Candidate> site, OperandKind kind,
                                          std::uint8_t operand_index, const ScalarRange &range,
                                          std::uint8_t byte_width = 0) noexcept
        {
            return Anchor{
                .label = label,
                .kind = AnchorKind::CodeOperand,
                .site = site,
                .operand_kind = kind,
                .operand_index = operand_index,
                .byte_width = byte_width,
                .validator = scalar_in_range,
                .validator_context = &range,
            };
        }

        /**
         * @brief A Quorum anchor over independent CodeOperand members.
         * @param threshold How many members must resolve to the same value; 0 means all of them.
         */
        [[nodiscard]] Anchor quorum(std::string_view label, std::span<const Anchor *const> members,
                                    std::size_t threshold, const ScalarRange &range) noexcept
        {
            return Anchor{
                .label = label,
                .kind = AnchorKind::Quorum,
                .validator = scalar_in_range,
                .validator_context = &range,
                .quorum_members = members,
                .quorum_threshold = threshold,
            };
        }

        // Quorum members. Each is resolved only through its quorum, never on its own, so none is a table entry.
        const Anchor k_is_third_person_slot_trigger =
            code_operand("IsThirdPersonSlot.Trigger", Aob::k_isThirdPersonSlotTriggerCandidates,
                         OperandKind::MemoryDisplacement, 0, k_vtable_offset_range);
        const Anchor k_is_third_person_slot_lock_sync =
            code_operand("IsThirdPersonSlot.LockSync", Aob::k_isThirdPersonSlotLockSyncCandidates,
                         OperandKind::MemoryDisplacement, 0, k_vtable_offset_range);
        const Anchor *const k_is_third_person_slot_votes[] = {&k_is_third_person_slot_trigger,
                                                              &k_is_third_person_slot_lock_sync};

        const Anchor k_camera_event_id_send = code_operand("CameraEventId.Send", Aob::k_cameraEventSendIdCandidates,
                                                           OperandKind::Immediate, 1, k_event_id_range, 4);
        const Anchor k_camera_event_id_handle_event =
            code_operand("CameraEventId.HandleEvent", Aob::k_cameraEventHandleEventIdCandidates, OperandKind::Immediate,
                         1, k_event_id_range);
        const Anchor k_camera_event_id_on_event =
            code_operand("CameraEventId.OnEvent", Aob::k_cameraEventOnEventIdCandidates, OperandKind::Immediate, 1,
                         k_event_id_range);
        const Anchor *const k_camera_event_id_votes[] = {&k_camera_event_id_send, &k_camera_event_id_handle_event,
                                                         &k_camera_event_id_on_event};

        const Anchor k_turn_state_trigger =
            code_operand("TurnInstalledState.Trigger", Aob::k_turnStateTriggerCandidates,
                         OperandKind::MemoryDisplacement, 1, k_dword_field_range);
        const Anchor k_turn_state_on_event =
            code_operand("TurnInstalledState.OnEvent", Aob::k_turnStateOnEventCandidates,
                         OperandKind::MemoryDisplacement, 0, k_dword_field_range);
        const Anchor *const k_turn_state_votes[] = {&k_turn_state_trigger, &k_turn_state_on_event};

        // The registry, indexed by AnchorId. The enumerator order IS this order. An empty ladder ({}) marks an
        // anchor KCD1 does not pattern-resolve (its consumer reaches the target via a gEnv member / vtable slot,
        // or is stubbed); resolve_all_anchors() skips it and records 0.
        const std::array<Anchor, k_anchor_count> k_anchor_table = {{
            code_ladder("Context", Aob::k_contextCandidates),
            code_ladder("Genv", Aob::k_genvCandidates),
            code_ladder("CameraFrustumBuild", Aob::k_frustumCandidates),
            code_ladder("SetHeadHidden", Aob::k_headVisibilityCandidates),
            code_ladder("InputDispatch", Aob::k_inputDispatchCandidates),
            code_ladder("ActionDispatch", Aob::k_actionDispatchCandidates),
            code_ladder("RayWorldIntersection", {}),
            code_ladder("InteractionRayBuild", {}),
            code_ladder("InteractorLookRay", Aob::k_interactorLookRayCandidates),
            code_ladder("InteractionOnScreen", {}),
            code_ladder("ActionFilterWorker", Aob::k_actionFilterWorkerCandidates),
            code_ladder("OverlayShow", {}),
            code_ladder("MenuToggle", Aob::k_menuToggleCandidates),
            code_ladder("MenuClose", {}),
            code_ladder("GetObjectsInBox", {}),
            code_ladder("CryActionFramework", Aob::k_cryActionFrameworkCandidates),
            code_ladder("TurnTriggerIsThirdPersonReturn", Aob::k_turnTriggerReturnCandidates),
            code_ladder("LockSyncIsThirdPersonReturn", Aob::k_lockSyncReturnCandidates),
            code_ladder("UpdatePhysicalEntityMovement", Aob::k_physEntMovementCandidates),
            quorum("IsThirdPersonSlot", k_is_third_person_slot_votes, 0, k_vtable_offset_range),
            code_operand("HandleEventSlot", Aob::k_cameraEventSendSlotCandidates, OperandKind::MemoryDisplacement, 0,
                         k_vtable_offset_range),
            quorum("CameraEventId", k_camera_event_id_votes, 2, k_event_id_range),
            code_operand("CameraEventFlags", Aob::k_cameraEventSendFlagsCandidates, OperandKind::Immediate, 1,
                         k_event_flags_range, 4),
            quorum("TurnInstalledState", k_turn_state_votes, 0, k_dword_field_range),
            code_operand("LockBodyTurnCount", Aob::k_lockBodyTurnCountCandidates, OperandKind::MemoryDisplacement, 1,
                         k_dword_field_range),
        }};

        /// True for a table entry that carries a ladder or quorum members; an empty RipGlobal is a placeholder.
        [[nodiscard]] bool is_wired(const Anchor &anchor) noexcept
        {
            return !anchor.site.empty() || !anchor.quorum_members.empty();
        }

        /// One independent call-site rung and the cascade it stands in for.
        struct CallSiteFallback
        {
            AnchorId target;
            Anchor site;
        };

        const std::array<CallSiteFallback, 4> k_call_site_fallbacks = {{
            {AnchorId::Frustum, call_site_ladder("CameraFrustumBuild.CallSite", Aob::k_frustumCallSite)},
            {AnchorId::HeadVisibility, call_site_ladder("SetHeadHidden.CallSite", Aob::k_headVisibilityCallSite)},
            {AnchorId::MenuOpen, call_site_ladder("MenuToggle.CallSite", Aob::k_menuToggleCallSite)},
            {AnchorId::OverlayHide, call_site_ladder("ActionFilterWorker.CallSite", Aob::k_actionFilterWorkerCallSite)},
        }};

        // Room after the startup pass for the function-scoped anchors resolve_turn_decision_layout() (seven) and
        // resolve_movement_type_offset() (one) append.
        constexpr std::size_t k_max_scoped_report = 8;
        constexpr std::size_t k_max_report =
            k_anchor_count + std::tuple_size_v<decltype(k_call_site_fallbacks)> + k_max_scoped_report;

        // Resolved absolute addresses, indexed by AnchorId; 0 means unresolved or a scalar anchor. Zero-initialized
        // (constant init, no static-init-order hazard). Written once by resolve_all_anchors() on the init thread
        // before any consumer reads, then read-only, so no synchronization is required.
        std::array<std::uintptr_t, k_anchor_count> s_resolved_addresses{};
        // Every resolved value, address and scalar anchors alike, under the same discipline.
        std::array<std::optional<std::int64_t>, k_anchor_count> s_resolved_values{};

        // The per-anchor report (wired cascades first, then the call-site rungs, then the function-scoped anchors),
        // written on the init thread only and read after init, so the shutdown diagnostics snapshot can roll it up
        // through diagnostics::collect() instead of the mod recomputing it.
        std::array<ResolvedAnchor, k_max_report> s_report{};
        std::size_t s_report_count = 0;

        /**
         * @brief Grades every candidate pattern in the table and reports the weak ones.
         * @details sighealth is offline and side-effect-free: it reads the COMPILED pattern bytes and mask and
         *          scores atom rarity, byte entropy, and expected ambiguity in a nominal module. It touches no
         *          process memory and never gates resolution, so this runs before the sweep and only reports.
         *          Its value is on patch day: a cascade that stops resolving against a new WHGame.dll is usually
         *          a signature that was already weakly selective, and this line says which rung was, without a
         *          disassembler.
         */
        void report_signature_health(std::span<const Anchor> anchors)
        {
            DMK::Logger &logger = DMK::log();
            std::size_t fragile = 0;
            std::size_t unusable = 0;

            const auto grade_ladder = [&](const Anchor &entry)
            {
                for (const Candidate &candidate : entry.site)
                {
                    const DMK::scan::Pattern *pattern = nullptr;
                    if (const auto *direct = candidate.as_direct())
                    {
                        pattern = &direct->pattern;
                    }
                    else if (const auto *rip = candidate.as_rip_relative())
                    {
                        pattern = &rip->pattern;
                    }
                    if (pattern == nullptr)
                    {
                        continue;
                    }

                    const DMK::sighealth::PatternHealth health = DMK::sighealth::analyze_pattern(*pattern);
                    if (health.grade == DMK::sighealth::Grade::Robust)
                    {
                        logger.trace("Signature health: {}/{} Robust", entry.label, candidate.name());
                        continue;
                    }
                    (health.grade == DMK::sighealth::Grade::Unusable ? ++unusable : ++fragile);
                    logger.debug("Signature health: {}/{} {} - {}", entry.label, candidate.name(),
                                 DMK::sighealth::to_string(health.grade),
                                 DMK::sighealth::format_report(health, candidate.name()));
                }
            };
            for (const Anchor &entry : anchors)
            {
                grade_ladder(entry);
                for (const Anchor *member : entry.quorum_members)
                {
                    grade_ladder(*member);
                }
            }

            if (unusable > 0)
            {
                logger.warning("Signature health: {} candidate(s) grade Unusable and {} Fragile; re-author them "
                               "before the next game patch (details at Debug level)",
                               unusable, fragile);
            }
            else
            {
                logger.info("Signature health: {} fragile candidate(s), 0 unusable", fragile);
            }
        }

        // Function-scoped quorum members (see resolve_turn_decision_layout()), resolved inside ComputeMoveState's
        // fragment through their quorum only. report_signature_health() does not grade the function-scoped ladders:
        // its estimate assumes a whole-module scan, and these are kept short on purpose because they scan one
        // function.
        const Anchor k_turn_latch_compare = code_operand("TurnSpinLatch.Compare", Aob::k_turnLatchCompareCandidates,
                                                         OperandKind::MemoryDisplacement, 0, k_byte_field_range);
        const Anchor k_turn_latch_store = code_operand("TurnSpinLatch.Store", Aob::k_turnLatchStoreCandidates,
                                                       OperandKind::MemoryDisplacement, 0, k_byte_field_range);
        const Anchor *const k_turn_latch_votes[] = {&k_turn_latch_compare, &k_turn_latch_store};

        const Anchor k_turn_sign_store = code_operand("TurnLastSign.Store", Aob::k_turnSignStoreCandidates,
                                                      OperandKind::MemoryDisplacement, 0, k_dword_field_range);
        const Anchor k_turn_sign_moving = code_operand("TurnLastSign.MovingPath", Aob::k_turnSignMovingCandidates,
                                                       OperandKind::MemoryDisplacement, 0, k_dword_field_range);
        const Anchor *const k_turn_sign_votes[] = {&k_turn_sign_store, &k_turn_sign_moving};

        /// The .pdata bounds of the code around an address (see function_bounds()).
        struct FunctionBounds
        {
            /// The RUNTIME_FUNCTION range that holds the address: one fragment of a possibly split function.
            DMK::Region fragment;
            /// The function's entry fragment, reached through chained unwind info; it starts with the prologue.
            DMK::Region entry;
            /// The prologue length the entry's unwind info declares.
            std::size_t prologue_size = 0;
        };

        /**
         * @brief Looks up the .pdata entry that holds @p address and follows chained unwind info to the function's
         *        entry fragment.
         * @details A compiler can split a function into an entry fragment and cold fragments, each with its own
         *          RUNTIME_FUNCTION. A cold fragment's UNWIND_INFO carries UNW_FLAG_CHAININFO and ends, after its
         *          unwind codes (padded to an even count), with its parent's RUNTIME_FUNCTION. DetourModKit exposes no
         *          function-bounds API, so this walks the same table the OS unwinder does; every UNWIND_INFO read is
         *          guarded.
         * @return The bounds, or std::nullopt when @p address has no entry or its unwind chain cannot be read.
         */
        [[nodiscard]] std::optional<FunctionBounds> function_bounds(std::uintptr_t address) noexcept
        {
            DWORD64 image_base = 0;
            const PRUNTIME_FUNCTION found = RtlLookupFunctionEntry(address, &image_base, nullptr);
            if (found == nullptr || image_base == 0)
            {
                return std::nullopt;
            }
            const auto region_of = [image_base](std::uint32_t begin, std::uint32_t end)
            {
                return DMK::Region{DMK::Address{static_cast<std::uintptr_t>(image_base) + begin},
                                   end > begin ? std::size_t{end - begin} : std::size_t{0}};
            };

            FunctionBounds bounds{.fragment = region_of(found->BeginAddress, found->EndAddress)};
            std::array<std::uint32_t, 3> entry{found->BeginAddress, found->EndAddress, found->UnwindData};
            constexpr int k_max_chain = 8;
            for (int hop = 0; hop < k_max_chain; ++hop)
            {
                // UNWIND_INFO header: version (low 3 bits) and flags (high 5 bits), prologue size, unwind code count,
                // frame register.
                const std::uintptr_t unwind_info = static_cast<std::uintptr_t>(image_base) + entry[2];
                const auto header = DMK::memory::read<std::array<std::uint8_t, 4>>(DMK::Address{unwind_info});
                if (!header)
                {
                    return std::nullopt;
                }
                if ((((*header)[0] >> 3) & UNW_FLAG_CHAININFO) == 0)
                {
                    bounds.entry = region_of(entry[0], entry[1]);
                    bounds.prologue_size = (*header)[1];
                    return bounds;
                }
                const std::size_t code_slots = (static_cast<std::size_t>((*header)[2]) + 1) & ~std::size_t{1};
                const auto parent = DMK::memory::read<std::array<std::uint32_t, 3>>(
                    DMK::Address{unwind_info + 4 + code_slots * sizeof(std::uint16_t)});
                if (!parent)
                {
                    return std::nullopt;
                }
                entry = *parent;
            }
            return std::nullopt;
        }

        /// The longest span any Direct rung of @p ladder can match.
        [[nodiscard]] std::size_t ladder_reach(std::span<const Candidate> ladder) noexcept
        {
            std::size_t reach = 0;
            for (const Candidate &candidate : ladder)
            {
                if (const auto *direct = candidate.as_direct())
                {
                    reach = std::max(reach, direct->pattern.max_match_length());
                }
            }
            return reach;
        }

        /**
         * @brief Resolves @p anchor inside @p scope and appends the result to the report.
         * @return The result, or std::nullopt when the report has no room left, which leaves the anchor unresolved.
         */
        [[nodiscard]] std::optional<ResolvedAnchor> resolve_scoped(const Anchor &anchor, DMK::Region scope)
        {
            if (s_report_count >= s_report.size())
            {
                return std::nullopt;
            }
            ResolvedAnchor &entry = s_report[s_report_count++];
            entry = DMK::anchor::resolve(anchor, scope);
            if (entry.status == AnchorStatus::Resolved)
            {
                DMK::log().debug("Anchor {} = {:#x}", entry.label, entry.value);
            }
            else
            {
                DMK::log().debug("Anchor {} unresolved ({})", entry.label,
                                 DMK::anchor::anchor_status_to_string(entry.status));
            }
            return entry;
        }

        /// The address a scoped code anchor resolves to, or 0.
        [[nodiscard]] std::uintptr_t scoped_address(const Anchor &anchor, DMK::Region scope)
        {
            const std::optional<ResolvedAnchor> entry = resolve_scoped(anchor, scope);
            return entry && entry->status == AnchorStatus::Resolved ? static_cast<std::uintptr_t>(entry->value) : 0;
        }

        /// The value a scoped scalar anchor resolves to, or std::nullopt.
        [[nodiscard]] std::optional<std::int64_t> scoped_value(const Anchor &anchor, DMK::Region scope)
        {
            const std::optional<ResolvedAnchor> entry = resolve_scoped(anchor, scope);
            if (!entry || entry->status != AnchorStatus::Resolved)
            {
                return std::nullopt;
            }
            return entry->value;
        }
    } // namespace

    void resolve_all_anchors(std::uintptr_t module_base, std::size_t module_size)
    {
        DMK::Logger &logger = DMK::log();

        // Confine resolution to the WHGame.dll image. The DMK default DMK::Region::host() is the host EXE
        // (KingdomCome.exe), not WHGame.dll, so the region is built explicitly from the scanned base/size. The
        // same region is published to the per-anchor validators, which reject a resolved target outside it.
        const DMK::Region range{DMK::Address{module_base}, module_size};
        s_image_range = range;
        s_resolved_addresses.fill(0);
        s_resolved_values.fill(std::nullopt);

        // Resolve only the anchors that carry a ladder or quorum members, plus every call-site rung, in one parallel
        // pass. The rest stay 0 (gEnv / vtable / stub consumers). wired_index maps each pass slot back to its
        // AnchorId.
        std::array<Anchor, k_max_report> pass{};
        std::array<std::size_t, k_anchor_count> wired_index{};
        std::size_t wired_count = 0;
        for (std::size_t i = 0; i < k_anchor_count; ++i)
        {
            if (is_wired(k_anchor_table[i]))
            {
                pass[wired_count] = k_anchor_table[i];
                wired_index[wired_count] = i;
                ++wired_count;
            }
        }
        std::size_t pass_count = wired_count;
        for (const CallSiteFallback &fallback : k_call_site_fallbacks)
        {
            pass[pass_count++] = fallback.site;
        }

        // Offline signature grading first: it needs no game memory and says which rungs are structurally weak
        // BEFORE the sweep reports which ones missed, so the two lines read together on a patch-day log.
        report_signature_health(std::span<const Anchor>(pass.data(), pass_count));

        // resolve_all_parallel writes s_report[i] for pass[i], in input order.
        s_report_count =
            DMK::anchor::resolve_all_parallel(std::span<const Anchor>(pass.data(), pass_count),
                                              std::span<ResolvedAnchor>(s_report.data(), pass_count), range);

        for (std::size_t j = 0; j < s_report_count && j < wired_count; ++j)
        {
            const ResolvedAnchor &entry = s_report[j];
            const std::size_t slot = wired_index[j];
            if (entry.status == AnchorStatus::Resolved)
            {
                s_resolved_values[slot] = entry.value;
                // Per-anchor values are for RE / external tooling, not routine status, so keep them at Debug; the
                // one-line quality summary below is the default-level health check, and a failure still warns.
                if (entry.domain == DMK::anchor::ResultDomain::Scalar)
                {
                    logger.debug("Anchor {} = {:#x}", entry.label, entry.value);
                }
                else
                {
                    s_resolved_addresses[slot] = static_cast<std::uintptr_t>(entry.value);
                    logger.debug("Anchor {} -> {}", entry.label,
                                 DMK::format::format_address(s_resolved_addresses[slot]));
                }
            }
            else
            {
                logger.warning("Anchor {} unresolved ({})", entry.label,
                               DMK::anchor::anchor_status_to_string(entry.status));
            }
        }

        // The call-site rungs stand in for a target only when its own cascade missed. When both resolved, the
        // two independent sites must agree; a disagreement means one of them matched the wrong code, so it is
        // reported (the in-function cascade is kept, exactly as the first-match-wins ladder ordered it before).
        for (std::size_t k = 0; k < k_call_site_fallbacks.size() && wired_count + k < s_report_count; ++k)
        {
            const ResolvedAnchor &entry = s_report[wired_count + k];
            const std::size_t slot = static_cast<std::size_t>(k_call_site_fallbacks[k].target);
            if (entry.status != AnchorStatus::Resolved)
            {
                logger.debug("Anchor {} unresolved ({})", entry.label,
                             DMK::anchor::anchor_status_to_string(entry.status));
                continue;
            }
            const std::uintptr_t callee = call_site_target(static_cast<std::uintptr_t>(entry.value), range);
            if (s_resolved_addresses[slot] == 0 && callee != 0)
            {
                s_resolved_addresses[slot] = callee;
                s_resolved_values[slot] = static_cast<std::int64_t>(callee);
                logger.warning("Anchor {} recovered through its call site -> {}", k_anchor_table[slot].label,
                               DMK::format::format_address(callee));
            }
            else if (callee != s_resolved_addresses[slot])
            {
                logger.warning("Anchor {} disagrees with its call site ({} vs {}); keeping the in-function match",
                               k_anchor_table[slot].label, DMK::format::format_address(s_resolved_addresses[slot]),
                               DMK::format::format_address(callee));
            }
        }

        const DMK::anchor::AnchorQuality quality = DMK::anchor::assess_quality(anchor_report());
        logger.info("Anchor resolution: {}/{} resolved, {} failed, {} unsupported (KCD1: other anchors use gEnv "
                    "member / vtable slot / stub)",
                    quality.resolved, quality.total, quality.failed, quality.unsupported);

        // The library's startup gate under its default, strictest policy: Pass means every wired cascade and
        // every call-site rung resolved. A lesser verdict is logged, not enforced: each consumer already fails
        // closed on its own anchor, and the optional features degrade independently of the camera.
        const DMK::anchor::GateVerdict gate = DMK::anchor::evaluate_gate(quality);
        if (gate == DMK::anchor::GateVerdict::Pass)
        {
            logger.info("Anchor gate: {}", DMK::anchor::gate_verdict_to_string(gate));
        }
        else
        {
            logger.warning("Anchor gate: {} (see the unresolved anchors above)",
                           DMK::anchor::gate_verdict_to_string(gate));
        }
    }

    std::uintptr_t anchor_address(AnchorId id) noexcept
    {
        const std::size_t index = static_cast<std::size_t>(id);
        return (index < k_anchor_count) ? s_resolved_addresses[index] : 0;
    }

    std::optional<std::int64_t> anchor_value(AnchorId id) noexcept
    {
        const std::size_t index = static_cast<std::size_t>(id);
        return (index < k_anchor_count) ? s_resolved_values[index] : std::nullopt;
    }

    std::optional<TurnDecisionLayout> resolve_turn_decision_layout(std::uintptr_t trigger_return)
    {
        DMK::Logger &logger = DMK::log();
        const auto refuse = [&logger](std::string_view proof) -> std::optional<TurnDecisionLayout>
        {
            logger.warning("Turn decision: {} did not resolve", proof);
            return std::nullopt;
        };

        const std::optional<FunctionBounds> bounds = function_bounds(trigger_return);
        if (!bounds || !s_image_range.contains(bounds->entry.base) ||
            !bounds->fragment.contains(DMK::Address{trigger_return}))
        {
            return refuse("ComputeMoveState's unwind entry");
        }
        const DMK::Region &body = bounds->fragment;

        // The contract window must end exactly on the return address, so its scope is its own length right before
        // it and the match must start at the scope's base.
        const std::size_t contract_length = ladder_reach(Aob::k_turnContractCandidates);
        const DMK::Region contract_scope{DMK::Address{trigger_return - contract_length}, contract_length};
        if (scoped_address(code_ladder("TurnContract", Aob::k_turnContractCandidates), contract_scope) !=
            contract_scope.base.raw())
        {
            return refuse("the register contract before the IsThirdPerson call");
        }

        // The test, branch and idle clear start exactly at the return address; the join follows them.
        const std::size_t join_length = ladder_reach(Aob::k_turnJoinCandidates);
        if (scoped_address(code_ladder("TurnJoin", Aob::k_turnJoinCandidates),
                           DMK::Region{DMK::Address{trigger_return}, join_length}) != trigger_return)
        {
            return refuse("the IsThirdPerson test, branch and idle clear");
        }
        const std::uintptr_t join = trigger_return + join_length;

        // The branch target is the decision chunk. It must open exactly with the compare, `seta cl` and the jump, so
        // its scope is the pattern's own length from the chunk's first byte, and the jump must land on the join,
        // which ties the chunk to this trigger.
        const auto chunk = DMK::scan::resolve_rip_relative(DMK::Address{trigger_return + 2}, 2, 6);
        if (!chunk || !s_image_range.contains(*chunk))
        {
            return refuse("the branch to the decision chunk");
        }
        const std::uintptr_t site =
            scoped_address(code_ladder("TurnDecisionSite", Aob::k_turnDecisionSiteCandidates),
                           DMK::Region{*chunk, ladder_reach(Aob::k_turnDecisionSiteCandidates)});
        if (site == 0)
        {
            return refuse("the decision chunk's compare and `seta cl`");
        }
        const auto back = DMK::scan::resolve_rip_relative(DMK::Address{site + 3}, 1, 5);
        if (!back || back->raw() != join)
        {
            return refuse("the decision chunk's jump back to the join");
        }

        // r12 holds the turn-angle output pointer from the prologue to the store through it.
        if (bounds->prologue_size == 0 ||
            scoped_address(code_ladder("TurnOutputSave", Aob::k_turnOutputSaveCandidates),
                           DMK::Region{bounds->entry.base, bounds->prologue_size}) == 0 ||
            scoped_address(code_ladder("TurnOutputStore", Aob::k_turnOutputStoreCandidates), body) == 0)
        {
            return refuse("the turn-angle output pointer in r12");
        }

        const std::optional<std::int64_t> spin_latch =
            scoped_value(quorum("TurnSpinLatch", k_turn_latch_votes, 0, k_byte_field_range), body);
        const std::optional<std::int64_t> last_sign =
            scoped_value(quorum("TurnLastSign", k_turn_sign_votes, 0, k_dword_field_range), body);
        const std::optional<std::int64_t> installed_state = anchor_value(AnchorId::TurnInstalledState);
        if (!spin_latch || !last_sign || !installed_state)
        {
            return refuse("the movement action's spin-latch fields");
        }

        logger.debug("Turn decision: site {}, spin latch +{:#x}, installed state +{:#x}, last sign +{:#x}",
                     DMK::format::format_address(site), *spin_latch, *installed_state, *last_sign);
        return TurnDecisionLayout{
            .site = site,
            .spin_latch_offset = static_cast<std::ptrdiff_t>(*spin_latch),
            .installed_state_offset = static_cast<std::ptrdiff_t>(*installed_state),
            .last_sign_offset = static_cast<std::ptrdiff_t>(*last_sign),
        };
    }

    std::optional<std::ptrdiff_t> resolve_movement_type_offset(std::uintptr_t update_physical_entity_movement)
    {
        // The anchor resolves the function entry, which must also be where its .pdata entry begins.
        const std::optional<FunctionBounds> bounds = function_bounds(update_physical_entity_movement);
        if (!bounds || bounds->fragment.base.raw() != update_physical_entity_movement)
        {
            DMK::log().warning("Turn steps: UpdatePhysicalEntityMovement's unwind entry did not resolve");
            return std::nullopt;
        }
        const std::optional<std::int64_t> offset =
            scoped_value(code_operand("MovementType", Aob::k_movementTypeCandidates, OperandKind::MemoryDisplacement, 0,
                                      k_dword_field_range),
                         bounds->fragment);
        if (!offset)
        {
            DMK::log().warning("Turn steps: the movement request type read did not resolve");
            return std::nullopt;
        }
        return static_cast<std::ptrdiff_t>(*offset);
    }

    std::span<const DMK::anchor::ResolvedAnchor> anchor_report() noexcept
    {
        return std::span<const DMK::anchor::ResolvedAnchor>(s_report.data(), s_report_count);
    }

    bool code_matches(std::uintptr_t address, const DMK::scan::Pattern &pattern) noexcept
    {
        std::array<std::byte, 64> bytes{};
        const std::size_t length = pattern.max_match_length();
        if (length > bytes.size())
        {
            return false;
        }
        const auto window = std::span{bytes}.first(length);
        return DMK::memory::read_into(DMK::Address{address}, window).has_value() && pattern.matches_at(window);
    }

    DMK::Result<DMK::scan::Pattern> handle_event_dispatch(std::uint8_t event_id)
    {
        return DMK::scan::Pattern::compile(std::format("41 8B 46 08 83 F8 {:02X} [2-6] 41 83 7E 08", event_id));
    }

} // namespace TPVCamera
