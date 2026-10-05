/**
 * @file dev/mod_loader.cpp
 * @brief Resident dev loader: owns the process, replaces one logic generation at a time on Numpad 0.
 *
 * @details Structure follows DetourModKit's checked-in examples/staged_reload pair, which its hot-reload guide
 *          treats as the reference implementation. The properties that matter:
 *
 *          1. Unique staged names. Mapping the build output would lock it, so a rebuild could not replace it, and
 *             mapping a REUSED name can hand back a still-mapped predecessor with its statics intact. Each
 *             generation loads <mod>.genNNNN.logic.dll, a name never used before in this process.
 *          2. A resident wheel host. A mouse-wheel binding makes the input engine take a permanent module
 *             keepalive on whichever module hosts wheel capture. Hosting it here, in a module that is never
 *             unloaded, lets every logic generation keep its wheel bindings and still unmap. This loader
 *             therefore links only DetourModKit::WheelHost, never the full archive.
 *          3. A typed retirement. Shutdown() refuses (zero), retires cleanly (OK), or retires with retained
 *             resources (RETAINED). A refused image stays mapped and is never initialized again; a retained one
 *             keeps this loader's reference for the process; a clean one is released and probed for unmap.
 *             Every surviving image is charged against a count and a staged-file byte budget, and a full budget
 *             asks for a game restart instead of stacking more state.
 *
 *          Reload is serialized on one resident control thread, accepted only while the game owns the
 *          foreground window, and fires on the Numpad 0 key-down edge. Every decision is written to
 *          <mod>.loader.log beside the loader. This loader is dev-only: the release build is a single
 *          ASI with no reload path at all.
 */

#include "protocol.h"

#include <windows.h>

#include <process.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace
{
    using InitFn = std::uint32_t(DMK_WHEELHOST_CALL *)(const TpvReloadInitRequest *) noexcept;
    using ShutdownFn = std::uint32_t(DMK_WHEELHOST_CALL *)() noexcept;
    using RevisionFn = const char *(DMK_WHEELHOST_CALL *)() noexcept;

    /// The build supplies TPVCAMERA_MOD_NAME. One name derives the logic-DLL names, the sweep filter, and the logs.
    constexpr std::wstring_view MOD_NAME = L"" TPVCAMERA_MOD_NAME;

    /// The reload hotkey.
    constexpr int RELOAD_VK = VK_NUMPAD0;

    /// Caps retained generations before the loader requests a restart (the reference policy).
    constexpr std::size_t MAX_RETAINED_GENERATIONS = 32;
    constexpr std::uintmax_t MAX_RETAINED_BYTES = 128ull * 1024 * 1024;

    constexpr std::size_t MODULE_PATH_INITIAL_CHARS = 512;
    constexpr std::size_t MODULE_PATH_MAX_CHARS = 32'768;
    constexpr DWORD CONTROL_POLL_MS = 50;
    /// A release can complete slightly after FreeLibrary returns, so the unmap check polls rather than sampling once.
    constexpr DWORD UNMAP_POLL_MS = 10;
    constexpr DWORD UNMAP_TIMEOUT_MS = 2000;
    constexpr SHORT KEY_DOWN_MASK = static_cast<SHORT>(0x8000);
    /// Loader-owned owner id for the probe lease: ASCII "TPVPROBE". Any value a generation never uses.
    constexpr std::uint64_t LEASE_PROBE_OWNER = UINT64_C(0x54505650524F4245);
    constexpr std::uint32_t INIT_REQUEST_SIZE = static_cast<std::uint32_t>(sizeof(TpvReloadInitRequest));

    /// One loaded staged copy and its exports.
    struct Generation
    {
        std::filesystem::path path;
        HMODULE module = nullptr;
        InitFn init = nullptr;
        ShutdownFn shutdown = nullptr;
        RevisionFn revision = nullptr;
        /// An address inside the image, used to prove the unmap. Any exported code address works.
        const void *unmap_address = nullptr;
        std::uint64_t generation_id = 0;
        std::uintmax_t image_bytes = 0;
    };

    HMODULE s_loader_module = nullptr;
    /// Process-lifetime wheel host. Started once, never stopped: the loader outlives every generation.
    WheelHostTable s_wheel_host{};
    // Host identity captured once at start. The request carries this copy, so the logic-side identity check
    // compares against the start-time value instead of re-reading the same table field it validates.
    std::uint64_t s_host_identity = 0;
    std::optional<Generation> s_current;
    unsigned s_generation_counter = 0;
    std::size_t s_retained_count = 0;
    std::uintmax_t s_retained_bytes = 0;
    /// Latched when a generation could not be proved gone. Further reloads would stack unknown state.
    bool s_restart_required = false;
    std::array<HMODULE, MAX_RETAINED_GENERATIONS> s_retained_loader_refs{};

    static_assert(std::is_nothrow_move_constructible_v<Generation>);

    [[nodiscard]] std::optional<std::filesystem::path> loader_directory()
    {
        std::wstring buffer(MODULE_PATH_INITIAL_CHARS, L'\0');
        for (;;)
        {
            const DWORD capacity = static_cast<DWORD>(buffer.size());
            const DWORD length = ::GetModuleFileNameW(s_loader_module, buffer.data(), capacity);
            if (length == 0)
            {
                return std::nullopt;
            }
            if (length < capacity)
            {
                buffer.resize(length);
                return std::filesystem::path{buffer}.parent_path();
            }
            if (buffer.size() >= MODULE_PATH_MAX_CHARS)
            {
                return std::nullopt;
            }
            const std::size_t next_size = buffer.size() * 2;
            buffer.resize(next_size > MODULE_PATH_MAX_CHARS ? MODULE_PATH_MAX_CHARS : next_size);
        }
    }

    /// Appends one line to the loader-owned log, which outlives every generation.
    void append_log(std::string_view line) noexcept
    {
        try
        {
            const std::optional<std::filesystem::path> directory = loader_directory();
            if (!directory.has_value())
            {
                return;
            }
            std::ofstream file(*directory / std::format(L"{}.loader.log", MOD_NAME), std::ios::app);
            SYSTEMTIME now = {};
            ::GetLocalTime(&now);
            file << std::format("[{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}] {}\n", now.wYear, now.wMonth, now.wDay,
                                now.wHour, now.wMinute, now.wSecond, now.wMilliseconds, line);
        }
        catch (...)
        {
            // The log is best-effort and cannot terminate the loader.
        }
    }

    template <typename... Args> void append_formatted_log(std::format_string<Args...> text, Args &&...args) noexcept
    {
        try
        {
            append_log(std::format(text, std::forward<Args>(args)...));
        }
        catch (...)
        {
        }
    }

    void remove_file(const std::filesystem::path &path) noexcept
    {
        try
        {
            std::error_code error;
            [[maybe_unused]] const bool removed = std::filesystem::remove(path, error);
        }
        catch (...)
        {
        }
    }

    /**
     * @brief Starts one log per game run for the loader and for the mod.
     * @details Each generation opens the mod log with LogOpenMode::Append, so a reload keeps the outgoing
     *          generation's teardown records (including an XInput retention warning, the only line that explains
     *          a retained image). Append cannot tell "next generation" from "next game run", though, so the loader
     *          owns the per-run reset: once, before the first generation opens the file.
     */
    void start_run_logs() noexcept
    {
        try
        {
            const std::optional<std::filesystem::path> directory = loader_directory();
            if (!directory.has_value())
            {
                return;
            }
            remove_file(*directory / std::format(L"{}.loader.log", MOD_NAME));
            remove_file(*directory / std::format(L"{}.log", MOD_NAME));
        }
        catch (...)
        {
        }
    }

    /// Deletes staged copies from earlier sessions. A copy that still backs a mapped image stays locked and survives.
    void remove_stale_staged_files() noexcept
    {
        try
        {
            const std::optional<std::filesystem::path> directory = loader_directory();
            if (!directory.has_value())
            {
                return;
            }
            const std::wstring staged_prefix = std::format(L"{}.gen", MOD_NAME);
            std::size_t removed = 0;
            std::error_code error;
            for (const std::filesystem::directory_entry &entry : std::filesystem::directory_iterator(*directory, error))
            {
                const std::wstring name = entry.path().filename().wstring();
                if (name.starts_with(staged_prefix) && name.ends_with(L".logic.dll"))
                {
                    std::error_code remove_error;
                    if (std::filesystem::remove(entry.path(), remove_error))
                    {
                        ++removed;
                    }
                }
            }
            if (removed > 0)
            {
                append_formatted_log("Removed {} stale staged copies.", removed);
            }
        }
        catch (...)
        {
        }
    }

    void record_retained_generation(const Generation &generation, HMODULE loader_reference = nullptr) noexcept
    {
        if (s_retained_count < s_retained_loader_refs.size())
        {
            s_retained_loader_refs[s_retained_count] = loader_reference;
        }
        if (s_retained_count < (std::numeric_limits<std::size_t>::max)())
        {
            ++s_retained_count;
        }
        if (generation.image_bytes > (std::numeric_limits<std::uintmax_t>::max)() - s_retained_bytes)
        {
            s_retained_bytes = (std::numeric_limits<std::uintmax_t>::max)();
        }
        else
        {
            s_retained_bytes += generation.image_bytes;
        }
        append_formatted_log("Generation {} retained ({} of {} images, {} bytes total).", generation.generation_id,
                             s_retained_count, MAX_RETAINED_GENERATIONS, s_retained_bytes);
    }

    /**
     * @brief Waits until no loaded module owns an old generation address.
     * @details Address-based rather than name-based: it asks the loader the exact question that matters, and
     *          UNCHANGED_REFCOUNT keeps the probe from perturbing the count it measures. Probing a freed address
     *          is safe - the call simply fails, which IS the answer. The returned handle is never released.
     * @return true only when the address becomes unmapped before the deadline.
     */
    [[nodiscard]] bool wait_for_unmap(const void *address) noexcept
    {
        if (address == nullptr)
        {
            // No probe address means no unmap proof. Report the image as still mapped.
            return false;
        }
        for (DWORD waited = 0; waited < UNMAP_TIMEOUT_MS; waited += UNMAP_POLL_MS)
        {
            HMODULE owner = nullptr;
            if (::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                         GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                     reinterpret_cast<LPCWSTR>(address), &owner) == 0)
            {
                return true;
            }
            ::Sleep(UNMAP_POLL_MS);
        }
        return false;
    }

    /**
     * @brief Opens and closes a probe lease after logic shutdown.
     * @details The host allows one lease at a time, so a successful open proves the generation closed its own. A
     *          failed close leaves host state unknown, which is as serious as a failed unmap.
     * @return true only when the generation left no host lease open.
     */
    [[nodiscard]] bool host_lease_is_closed(std::uint64_t generation_id) noexcept
    {
        WheelHostLease probe = 0;
        const int32_t open_status =
            s_wheel_host.open_lease(s_wheel_host.host_context, LEASE_PROBE_OWNER, generation_id, &probe);
        if (open_status != DMK_WHEELHOST_OK)
        {
            append_formatted_log("Generation {} left its wheel-host lease open (status {}).", generation_id,
                                 open_status);
            return false;
        }
        const int32_t close_status =
            s_wheel_host.close_lease(s_wheel_host.host_context, probe, LEASE_PROBE_OWNER, generation_id);
        if (close_status != DMK_WHEELHOST_OK)
        {
            s_restart_required = true;
            append_formatted_log("The loader failed to close its wheel-host probe lease (status {}).", close_status);
            return false;
        }
        return true;
    }

    /**
     * @brief Releases a retired image or retains its loader reference within the development budget.
     * @return true after accepted retirement. A failed lease probe or module release returns false.
     */
    [[nodiscard]] bool release_generation(Generation &generation, std::uint32_t verdict) noexcept
    {
        if (generation.module == nullptr)
        {
            return true;
        }
        if (!host_lease_is_closed(generation.generation_id))
        {
            return false;
        }
        if (verdict == TPVCAMERA_RELOAD_RETAINED)
        {
            // Keep our reference even if a leaked resource holds no module pin.
            record_retained_generation(generation, generation.module);
            generation.module = nullptr;
            return true;
        }
        const HMODULE module = generation.module;
        if (::FreeLibrary(module) == 0)
        {
            append_formatted_log("FreeLibrary failed (error {}).", ::GetLastError());
            return false;
        }
        generation.module = nullptr;
        if (!wait_for_unmap(generation.unmap_address))
        {
            // Something still references the image. Its code may stay mapped for the process, so charge it.
            record_retained_generation(generation);
            return true;
        }
        remove_file(generation.path);
        return true;
    }

    [[nodiscard]] bool retire_generation(Generation &generation) noexcept
    {
        if (generation.shutdown == nullptr)
        {
            return false;
        }
        const std::uint32_t verdict = generation.shutdown();
        if (verdict != TPVCAMERA_RELOAD_OK && verdict != TPVCAMERA_RELOAD_RETAINED)
        {
            append_log("Shutdown refused retirement. The generation stays mapped.");
            return false;
        }
        return release_generation(generation, verdict);
    }

    void retire_failed_stage(Generation &generation) noexcept
    {
        if (!retire_generation(generation))
        {
            s_restart_required = true;
            record_retained_generation(generation, generation.module);
            generation.module = nullptr;
            append_log("The failed stage did not retire. Restart the game before another reload.");
        }
    }

    /**
     * @brief Copies the build output to a unique staged name.
     * @details A direct load locks the build output. A reused name can return a pinned predecessor as a stale image.
     */
    [[nodiscard]] bool stage_copy(Generation &generation)
    {
        const std::optional<std::filesystem::path> directory = loader_directory();
        if (!directory.has_value())
        {
            return false;
        }
        const std::filesystem::path source = *directory / std::format(L"{}.logic.dll", MOD_NAME);
        ++s_generation_counter;
        generation.generation_id = s_generation_counter;
        generation.path = *directory / std::format(L"{}.gen{:04}.logic.dll", MOD_NAME, s_generation_counter);
        std::error_code error;
        std::filesystem::copy_file(source, generation.path, std::filesystem::copy_options::overwrite_existing, error);
        if (error)
        {
            remove_file(generation.path);
            append_formatted_log("The stage copy failed: {}.", error.message());
            return false;
        }
        generation.image_bytes = std::filesystem::file_size(generation.path, error);
        if (error)
        {
            const std::error_code size_error = error;
            remove_file(generation.path);
            append_formatted_log("The staged image size query failed: {}.", size_error.message());
            return false;
        }
        return true;
    }

    template <class Fn> [[nodiscard]] Fn resolve(HMODULE module, const char *symbol) noexcept
    {
        return reinterpret_cast<Fn>(reinterpret_cast<void *>(::GetProcAddress(module, symbol)));
    }

    /// Stages, loads, resolves, and initializes one generation.
    [[nodiscard]] bool load_generation()
    {
        Generation generation;
        if (!stage_copy(generation))
        {
            return false;
        }
        if (s_retained_count >= MAX_RETAINED_GENERATIONS || s_retained_bytes > MAX_RETAINED_BYTES ||
            generation.image_bytes > MAX_RETAINED_BYTES - s_retained_bytes)
        {
            s_restart_required = true;
            remove_file(generation.path);
            append_log("The next image exceeds the retention budget. Restart the game before another reload.");
            return false;
        }
        generation.module = ::LoadLibraryW(generation.path.c_str());
        if (generation.module == nullptr)
        {
            const DWORD error = ::GetLastError();
            remove_file(generation.path);
            append_formatted_log("LoadLibrary failed (error {}).", error);
            return false;
        }
        generation.init = resolve<InitFn>(generation.module, TPVCAMERA_RELOAD_INIT_SYMBOL);
        generation.shutdown = resolve<ShutdownFn>(generation.module, TPVCAMERA_RELOAD_SHUTDOWN_SYMBOL);
        generation.revision = resolve<RevisionFn>(generation.module, TPVCAMERA_RELOAD_REVISION_SYMBOL);
        generation.unmap_address = reinterpret_cast<const void *>(generation.init);
        if (generation.init == nullptr || generation.shutdown == nullptr || generation.revision == nullptr)
        {
            retire_failed_stage(generation);
            append_log("The export resolution failed (Init / Shutdown / Revision).");
            return false;
        }
        const TpvReloadInitRequest request{
            .struct_size = INIT_REQUEST_SIZE,
            .abi_version = TPVCAMERA_RELOAD_ABI_VERSION,
            .generation_id = generation.generation_id,
            .expected_host_identity = s_host_identity,
            .wheel_host = &s_wheel_host,
        };
        if (generation.init(&request) != TPVCAMERA_RELOAD_OK)
        {
            retire_failed_stage(generation);
            append_log("Init failed (see " TPVCAMERA_MOD_NAME ".log).");
            return false;
        }
        s_current.emplace(std::move(generation));
        const char *revision = s_current->revision();
        append_formatted_log("Generation {} is live. Revision: {}.", s_generation_counter,
                             revision != nullptr ? std::string_view{revision} : std::string_view{"unknown"});
        return true;
    }

    /**
     * @brief Retires the current generation before a fresh load.
     * @return false after a teardown refusal or release failure. A release failure requests a restart. A refused
     *         generation stays mapped and is NEVER re-initialized: its globals and statics hold the previous state.
     */
    [[nodiscard]] bool unload_current() noexcept
    {
        if (!s_current.has_value())
        {
            return true;
        }
        const std::uint32_t verdict = s_current->shutdown();
        if (verdict != TPVCAMERA_RELOAD_OK && verdict != TPVCAMERA_RELOAD_RETAINED)
        {
            append_log("Shutdown refused retirement. The generation stays mapped (inert). Retry after quiescence, or "
                       "restart if the mod log reports a retained worker or hook.");
            return false;
        }
        if (!release_generation(*s_current, verdict))
        {
            s_restart_required = true;
            append_log("The current generation did not retire. Restart the game before another reload.");
            return false;
        }
        s_current.reset();
        return true;
    }

    /**
     * @brief Checks count capacity and the current image size before teardown.
     * @details The count check reserves both the current generation's slot and a failed successor's. The byte check
     *          includes only the current image; the successor size check precedes its load.
     */
    [[nodiscard]] bool budget_allows_reload() noexcept
    {
        const std::uintmax_t current_bytes = s_current.has_value() ? s_current->image_bytes : 0;
        const std::size_t current_slot = s_current.has_value() ? 1 : 0;
        const bool count_would_exceed = s_retained_count >= MAX_RETAINED_GENERATIONS - current_slot;
        const bool bytes_would_exceed =
            s_retained_bytes > MAX_RETAINED_BYTES || current_bytes > MAX_RETAINED_BYTES - s_retained_bytes;
        if (count_would_exceed || bytes_would_exceed)
        {
            s_restart_required = true;
            append_log("The retained-generation budget is full. Restart the game before another reload.");
            return false;
        }
        return true;
    }

    void reload_once()
    {
        // This control thread is the only reload caller, so it cannot re-enter this function.
        if (s_restart_required)
        {
            append_log("A previous reload could not be proved safe. Restart the game before another reload.");
            return;
        }
        if (!budget_allows_reload())
        {
            return;
        }
        append_log("Numpad 0 pressed. Reloading the logic DLL.");
        if (!unload_current())
        {
            return;
        }
        if (!load_generation())
        {
            append_log("The reload failed. No generation is live until the next press.");
        }
    }

    /**
     * @brief Accepts the hotkey only while this process owns the foreground window.
     * @details GetAsyncKeyState reads global key state, so an unguarded press in an editor window (for example
     *          while rebuilding) would trigger a game reload.
     */
    [[nodiscard]] bool foreground_belongs_to_this_process() noexcept
    {
        const HWND foreground = ::GetForegroundWindow();
        if (foreground == nullptr)
        {
            return false;
        }
        DWORD process_id = 0;
        ::GetWindowThreadProcessId(foreground, &process_id);
        return process_id == ::GetCurrentProcessId();
    }

    unsigned __stdcall control_thread(void *) noexcept
    {
        try
        {
            start_run_logs();
            append_log("The loader started.");
            remove_stale_staged_files();
            // ABI v2 starts unmounted in target-wait state. The logic-side poller resolves the game UI thread and
            // drives the host retarget through the C table, so the loader needs no window wait of its own.
            const int32_t host_status = wheel_host_start(
                0, DMK_WHEELHOST_ABI_VERSION, static_cast<std::uint32_t>(sizeof(s_wheel_host)), &s_wheel_host);
            if (host_status != DMK_WHEELHOST_OK)
            {
                append_formatted_log("The resident wheel host failed to start (status {}). Reload is unavailable.",
                                     host_status);
                return 0;
            }
            s_host_identity = s_wheel_host.host_identity;
            if (!load_generation())
            {
                append_log("The initial load failed. Press Numpad 0 after rebuilding to retry.");
            }
            bool was_down = false;
            for (;;) // The loader lives for the game session. Process exit ends this thread.
            {
                ::Sleep(CONTROL_POLL_MS);
                const bool down = (::GetAsyncKeyState(RELOAD_VK) & KEY_DOWN_MASK) != 0;
                if (down && !was_down && foreground_belongs_to_this_process())
                {
                    reload_once();
                }
                was_down = down;
            }
        }
        catch (...)
        {
            // An exception cannot cross the CRT thread boundary into the host process.
            return 0;
        }
    }
} // namespace

/// Starts the control thread on attach. The loader never unloads, so detach has no work.
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) noexcept
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        s_loader_module = module;
        ::DisableThreadLibraryCalls(module);
        const std::uintptr_t thread = _beginthreadex(nullptr, 0, &control_thread, nullptr, 0, nullptr);
        if (thread == 0)
        {
            return FALSE;
        }
        ::CloseHandle(reinterpret_cast<HANDLE>(thread));
    }
    return TRUE;
}
