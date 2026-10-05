/**
 * @file rtti_types.cpp
 * @brief Construction and publication of the cached class vtable identities.
 */

#include "rtti_types.hpp"
#include "constants.hpp"
#include "game_state.hpp"

#include <DetourModKit.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

namespace TPVCamera
{
    namespace
    {
        constexpr std::size_t CLASS_COUNT = static_cast<std::size_t>(GameClass::Count);

        /// MSVC decorated names follow the GameClass enumerator order.
        constexpr std::array<std::string_view, CLASS_COUNT> CLASS_NAMES = {{
            Constants::C_PLAYER_RTTI_NAME,
            Constants::CVIEW_RTTI_NAME,
            Constants::ANIMATED_CHARACTER_RTTI_NAME,
            Constants::C_PLAYERINPUT_RTTI_NAME,
            Constants::C_ACTOR_MODEL_RTTI_NAME,
            Constants::C_CAMERA_OBSERVER_RTTI_NAME,
            Constants::CTIMER_RTTI_NAME,
            Constants::SGAME_OBJECT_EVENT_RTTI_NAME,
            Constants::ANIMATION_SET_RTTI_NAME,
        }};

        // A TypeIdentity is pinned, so a std::vector cannot hold one: a reallocation has to move its
        // elements. A std::deque never moves an element it already holds.
        std::deque<DMK::rtti::TypeIdentity> s_class_types;
        std::deque<DMK::rtti::TypeIdentity> s_minigame_types;

        // Only initialization takes this lock. Published tables stay immutable for query threads.
        std::mutex s_init_mutex;
        DMK::Region s_image{};

        // Which identities resolved during init_game_types(). Written before s_ready is published and read only
        // after it is observed, so a query never sees a half-written flag.
        std::array<bool, CLASS_COUNT> s_class_resolved{};
        std::array<bool, k_minigames.size()> s_minigame_resolved{};

        // Published with release once both deques are complete, and read with acquire, so a render thread
        // either sees no table and takes the direct RTTI walk, or sees a complete one.
        std::atomic<bool> s_ready{false};

        /**
         * @brief Answers from the cached identity when it resolved at init, and from the direct RTTI walk otherwise.
         * @details A class's primary vtable is static image data, so one that did not resolve over the whole image
         *          at init will not resolve on a later frame either. Asking its TypeIdentity again would re-run that
         *          full-image sweep on the CALLING thread (the render thread, inside a detour) every time the
         *          library's retry cooldown expires, so an unresolved class goes straight to the cheap per-vtable
         *          walk instead. For a resolved class, vtable() is a pointer compare plus a bounded generation
         *          re-read, and still re-resolves if the image is ever remapped under the cache.
         */
        [[nodiscard]] bool answer(const std::deque<DMK::rtti::TypeIdentity> &table, bool resolved_at_init,
                                  std::size_t index, std::uintptr_t vtable, std::string_view mangled) noexcept
        {
            if (vtable == 0)
            {
                return false;
            }
            if (resolved_at_init && s_ready.load(std::memory_order_acquire))
            {
                if (const std::optional<DMK::Address> primary = table[index].vtable(); primary.has_value())
                {
                    return DMK::Address{vtable} == *primary;
                }
            }
            return DMK::rtti::vtable_is_type(DMK::Address{vtable}, mangled);
        }
    } // namespace

    void init_game_types(DMK::Region image)
    {
        const std::lock_guard init_lock(s_init_mutex);
        if (!image.base || image.size == 0)
        {
            throw std::invalid_argument("RTTI initialization requires a nonempty game image");
        }
        if (s_image.base && (s_image.base != image.base || s_image.size != image.size))
        {
            throw std::invalid_argument("RTTI identities are bound to a different game image range");
        }
        if (s_ready.load(std::memory_order_acquire))
        {
            return;
        }
        s_image = image;
        // An allocation failure can leave an unpublished prefix. Resume that prefix without replacement or duplication.
        for (std::size_t i = s_class_types.size(); i < CLASS_COUNT; ++i)
        {
            s_class_types.emplace_back(CLASS_NAMES[i], image);
        }
        for (std::size_t i = s_minigame_types.size(); i < k_minigames.size(); ++i)
        {
            s_minigame_types.emplace_back(k_minigames[i].rtti_name, image);
        }

        // Resolve identities before publication because a cold identity scans the whole image.
        // Each worker owns a distinct identity. The caller also drains work if thread creation fails.
        // Unresolved identities use direct RTTI and retry under the library's cooldown. Every pool thread is
        // joined before this returns, so no thread outlives the call into this image.
        std::vector<const DMK::rtti::TypeIdentity *> identities;
        std::vector<std::string_view> names;
        for (std::size_t i = 0; i < CLASS_COUNT; ++i)
        {
            identities.push_back(&s_class_types[i]);
            names.push_back(CLASS_NAMES[i]);
        }
        for (std::size_t i = 0; i < k_minigames.size(); ++i)
        {
            identities.push_back(&s_minigame_types[i]);
            names.push_back(k_minigames[i].rtti_name);
        }
        std::vector<char> resolved(identities.size(), 0);
        std::atomic<std::size_t> next{0};
        const auto drain = [&identities, &resolved, &next]() noexcept
        {
            for (std::size_t i = next.fetch_add(1); i < identities.size(); i = next.fetch_add(1))
            {
                resolved[i] = identities[i]->vtable().has_value() ? 1 : 0;
            }
        };
        {
            constexpr unsigned max_warm_threads = 8;
            const unsigned workers = std::clamp(std::thread::hardware_concurrency(), 1u, max_warm_threads) - 1;
            std::vector<std::jthread> pool;
            pool.reserve(workers);
            try
            {
                for (unsigned k = 0; k < workers; ++k)
                {
                    pool.emplace_back(drain);
                }
            }
            catch (const std::system_error &)
            {
                // Fewer workers than asked for: the calling thread drains whatever they leave.
            }
            drain();
        }

        std::size_t resolved_count = 0;
        for (std::size_t i = 0; i < identities.size(); ++i)
        {
            if (i < CLASS_COUNT)
            {
                s_class_resolved[i] = resolved[i] != 0;
            }
            else
            {
                s_minigame_resolved[i - CLASS_COUNT] = resolved[i] != 0;
            }
            if (resolved[i] != 0)
            {
                ++resolved_count;
            }
            else
            {
                (void)DMK::log().try_log(DMK::LogLevel::Debug, "RTTI: {} did not resolve at init", names[i]);
            }
        }
        (void)DMK::log().try_log(DMK::LogLevel::Info, "RTTI: {}/{} class identities resolved", resolved_count,
                                 identities.size());

        s_ready.store(true, std::memory_order_release);
    }

    bool vtable_is(GameClass klass, std::uintptr_t vtable) noexcept
    {
        const std::size_t index = static_cast<std::size_t>(klass);
        if (index >= CLASS_COUNT)
        {
            return false;
        }
        return answer(s_class_types, s_class_resolved[index], index, vtable, CLASS_NAMES[index]);
    }

    std::optional<std::uintptr_t> class_vtable(GameClass klass) noexcept
    {
        const std::size_t index = static_cast<std::size_t>(klass);
        if (index >= CLASS_COUNT || !s_ready.load(std::memory_order_acquire) || !s_class_resolved[index])
        {
            return std::nullopt;
        }
        if (const std::optional<DMK::Address> primary = s_class_types[index].vtable(); primary.has_value())
        {
            return primary->raw();
        }
        return std::nullopt;
    }

    bool minigame_vtable_is(std::size_t index, std::uintptr_t vtable) noexcept
    {
        if (index >= k_minigames.size())
        {
            return false;
        }
        return answer(s_minigame_types, s_minigame_resolved[index], index, vtable, k_minigames[index].rtti_name);
    }
} // namespace TPVCamera
