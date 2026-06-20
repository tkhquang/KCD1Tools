#include "aob_resolver.hpp"

#include <DetourModKit.hpp>

#include <array>
#include <span>
#include <string_view>

namespace TPVCamera
{
    namespace
    {
        using DMK::Anchors::Anchor;
        using DMK::Anchors::AnchorKind;

        constexpr std::size_t k_anchor_count = static_cast<std::size_t>(AnchorId::Count);

        // A RipGlobal anchor wrapping a single cascade of code candidates. (RipGlobal is DMK's general
        // code/data cascade kind; Direct candidates resolve to a code address, which is exactly what an
        // inline-hook target needs.) An empty site marks an anchor KCD1 does not pattern-resolve (its
        // consumer falls back to a static RVA / gEnv / vtable slot, or is stubbed); resolve_all_anchors
        // skips it and records 0.
        constexpr Anchor rip_global(std::string_view label, std::span<const AddrCandidate> site) noexcept
        {
            return Anchor{.label = label, .kind = AnchorKind::RipGlobal, .site = site};
        }

        // Index of each entry MUST match its AnchorId enumerator. Empty cascades ({}) are anchors KCD1 does
        // not pattern-resolve; resolve_all_anchors records 0 for them.
        constexpr std::array<Anchor, k_anchor_count> k_anchor_table = {{
            rip_global("Context", Aob::k_contextCandidates),        // AnchorId::Context (RIP-rel cascade + RVA fallback)
            rip_global("Genv", Aob::k_genvCandidates),              // AnchorId::Genv (RIP-rel cascade + static fallback)
            rip_global("CameraFrustumBuild", Aob::k_frustumCandidates),       // AnchorId::Frustum
            rip_global("SetHeadHidden", Aob::k_headVisibilityCandidates),     // AnchorId::HeadVisibility
            rip_global("InputDispatch", Aob::k_inputDispatchCandidates), // AnchorId::InputDispatch (cascade + RVA fallback)
            rip_global("ActionDispatch", Aob::k_actionDispatchCandidates), // AnchorId::ActionDispatch (cascade + RVA)
            rip_global("RayWorldIntersection", {}),                 // AnchorId::RayWorldIntersection (vtable slot)
            rip_global("InteractionRayBuild", {}),                  // AnchorId::InteractionRayBuild (unused; reserved)
            rip_global("InteractorLookRay", Aob::k_interactorLookRayCandidates), // AnchorId::InteractorLookRay (cascade + RVA)
            rip_global("InteractionOnScreen", {}),                  // AnchorId::InteractionOnScreen (stubbed)
            rip_global("ActionFilterWorker", Aob::k_actionFilterWorkerCandidates), // AnchorId::OverlayHide (cascade + RVA)
            rip_global("OverlayShow", {}),                          // AnchorId::OverlayShow (folded into OverlayHide)
            rip_global("MenuToggle", Aob::k_menuToggleCandidates),  // AnchorId::MenuOpen (cascade + RVA)
            rip_global("MenuClose", {}),                            // AnchorId::MenuClose (folded into MenuOpen)
            rip_global("GetObjectsInBox", {}),                      // AnchorId::GetObjectsInBox (vtable slot)
        }};

        std::array<std::uintptr_t, k_anchor_count> s_resolved_addresses{};
    } // namespace

    void resolve_all_anchors(std::uintptr_t module_base, std::size_t module_size)
    {
        DMK::Logger &logger = DMK::Logger::get_instance();

        // host_module_range() is the host EXE (KingdomCome.exe), not WHGame.DLL, so the game-image range is
        // built explicitly from the scanned module.
        const DMK::Memory::ModuleRange range{module_base, module_base + module_size};

        // Resolve only the anchors that carry a cascade; the rest stay 0 (static-RVA / vtable / stub
        // consumers). A compact sub-table of the wired anchors is resolved in one parallel pass, then each
        // result is written back to its AnchorId slot.
        std::array<Anchor, k_anchor_count> wired{};
        std::array<std::size_t, k_anchor_count> wired_index{};
        std::size_t wired_count = 0;
        for (std::size_t i = 0; i < k_anchor_count; ++i)
        {
            if (!k_anchor_table[i].site.empty())
            {
                wired[wired_count] = k_anchor_table[i];
                wired_index[wired_count] = i;
                ++wired_count;
            }
            s_resolved_addresses[i] = 0;
        }

        std::array<DMK::Anchors::ResolvedAnchor, k_anchor_count> report{};
        const std::size_t n = DMK::Anchors::resolve_all_parallel(
            std::span<const Anchor>(wired.data(), wired_count), std::span<DMK::Anchors::ResolvedAnchor>(report.data(), wired_count),
            range);

        for (std::size_t j = 0; j < n; ++j)
        {
            const auto &entry = report[j];
            const std::size_t slot = wired_index[j];
            if (entry.status == DMK::Anchors::AnchorStatus::Resolved)
            {
                s_resolved_addresses[slot] = static_cast<std::uintptr_t>(entry.value);
                logger.debug("Anchor {} -> {}", entry.label, DMK::Format::format_address(s_resolved_addresses[slot]));
            }
            else
            {
                s_resolved_addresses[slot] = 0;
                logger.warning("Anchor {} unresolved ({})", entry.label,
                               DMK::Anchors::anchor_status_to_string(entry.status));
            }
        }

        const auto quality =
            DMK::Anchors::assess_quality(std::span<const DMK::Anchors::ResolvedAnchor>(report.data(), n));
        logger.info("Anchor resolution: {}/{} wired resolved, {} failed, {} unsupported (KCD1: other anchors use "
                    "static RVA / vtable / stub)",
                    quality.resolved, quality.total, quality.failed, quality.unsupported);
    }

    std::uintptr_t anchor_address(AnchorId id) noexcept
    {
        const std::size_t i = static_cast<std::size_t>(id);
        return (i < k_anchor_count) ? s_resolved_addresses[i] : 0;
    }
} // namespace TPVCamera
