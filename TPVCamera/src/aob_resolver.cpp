/**
 * @file aob_resolver.cpp
 * @brief Declarative anchor table, one-pass resolution, and the resolved-address store.
 *
 * The candidate ladders in aob_resolver.hpp enter a DetourModKit anchor registry as RipGlobal entries,
 * together with the independent call-site rungs. resolve_all_anchors() resolves the whole table in a single
 * parallel pass at startup and records each address; anchor_address() hands the resolved address, or 0 on a
 * cascade miss, to the call sites.
 */

#include "aob_resolver.hpp"

#include <DetourModKit.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
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

        /// A RipGlobal anchor over one ladder. Every rung anchors on an in-image instruction, so the byte tiers
        /// sweep executable pages only: an identical byte run in .rdata or .data cannot alias or make a unique
        /// code match ambiguous.
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
        }};

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

        constexpr std::size_t k_max_report = k_anchor_count + std::tuple_size_v<decltype(k_call_site_fallbacks)>;

        // Resolved absolute addresses, indexed by AnchorId; 0 means unresolved. Zero-initialized (constant
        // init, no static-init-order hazard). Written once by resolve_all_anchors() on the init thread before
        // any consumer reads, then read-only, so no synchronization is required.
        std::array<std::uintptr_t, k_anchor_count> s_resolved_addresses{};

        // The per-anchor report (wired cascades first, then the call-site rungs), retained with the same
        // write-once-then-read-only discipline so the shutdown diagnostics snapshot can roll it up through
        // diagnostics::collect() instead of the mod recomputing it.
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

            for (const Anchor &entry : anchors)
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

        // Resolve only the anchors that carry a ladder, plus every call-site rung, in one parallel pass. The
        // rest stay 0 (gEnv / vtable / stub consumers). wired_index maps each pass slot back to its AnchorId.
        std::array<Anchor, k_max_report> pass{};
        std::array<std::size_t, k_anchor_count> wired_index{};
        std::size_t wired_count = 0;
        for (std::size_t i = 0; i < k_anchor_count; ++i)
        {
            if (!k_anchor_table[i].site.empty())
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
                s_resolved_addresses[slot] = static_cast<std::uintptr_t>(entry.value);
                // Per-anchor address is for RE / external tooling, not routine status, so keep it at Debug; the
                // one-line quality summary below is the default-level health check, and a failure still warns.
                logger.debug("Anchor {} -> {}", entry.label, DMK::format::format_address(s_resolved_addresses[slot]));
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

    std::span<const DMK::anchor::ResolvedAnchor> anchor_report() noexcept
    {
        return std::span<const DMK::anchor::ResolvedAnchor>(s_report.data(), s_report_count);
    }

} // namespace TPVCamera
