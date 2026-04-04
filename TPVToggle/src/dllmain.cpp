/**
 * @file dllmain.cpp
 * @brief KCD1 Third-Person View toggle mod. AOB-scans for the GSC pointer and
 *        flips a camera-mode flag via configurable input bindings.
 */

#include <windows.h>
#include <Psapi.h>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <array>

#include <DetourModKit.hpp>

#include "version.hpp"

namespace Mod
{
    // --- Mod identity ---
    inline constexpr const char *MOD_VERSION = VERSION_STRING;
    inline constexpr const char *MOD_NAME = "KCD1_TPVToggle";
    inline constexpr const char *MOD_AUTHOR = "tkhquang";
    inline constexpr const char *MOD_SOURCE = "https://github.com/tkhquang/KCD1Tools";
    inline constexpr const char *MOD_NEXUS = "https://www.nexusmods.com/kingdomcomedeliverance/mods/2009";

    struct Config
    {
        DMKKeyComboList toggle_combos;
        DMKKeyComboList fpv_combos;
        DMKKeyComboList tpv_combos;
        std::string log_level_str = "INFO";
    };

    constexpr ptrdiff_t OFFSET_CAM_MANAGER_IN_GSC = 0x38;
    constexpr ptrdiff_t OFFSET_CAMERA_MODE_FLAG = 0x18;

    constexpr const char *TARGET_MODULE = "WHGame.dll";
    constexpr const char *INI_FILENAME = "KCD1_TPVToggle.ini";
    constexpr WORD CAMERA_MODE_FPV = 0;
    constexpr WORD CAMERA_MODE_TPV = 1;
    constexpr int INIT_RETRY_MS = 500;

    constexpr const char *CAMERA_MODE_NAME_FPV = "FPV";
    constexpr const char *CAMERA_MODE_NAME_TPV = "TPV";

    const char *get_camera_mode_name(WORD mode)
    {
        return mode == CAMERA_MODE_TPV ? CAMERA_MODE_NAME_TPV : CAMERA_MODE_NAME_FPV;
    }

    /** @brief AOB pattern definition. The `|` marker sets the offset to the MOV RAX,[RIP+disp32] instruction. */
    struct PatternDef
    {
        const char *name;
        const char *aob;
    };

    constexpr std::array PATTERNS = {
        PatternDef{
            "v1.9.7",
            "39 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? | 48 8B 05 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 ?? 5F C3"},
        PatternDef{
            "v1.9.6",
            "8B 04 0A 39 05 ?? ?? ?? ?? 7F ?? | 48 8B 05 ?? ?? ?? ?? 48 83 C4 ?? 5B C3"},
    };

    Config g_config;
    uintptr_t g_gsc_static_ptr_addr = 0;
    std::atomic<bool> g_initialized{false};
    std::atomic<bool> g_shutting_down{false};

    void Initialize();
    bool ResolveGSCPointer();
    uintptr_t GetCameraManagerAddr();
    WORD GetCameraMode();
    void SetCameraMode(WORD mode);
    void ToggleView();

    uintptr_t GetCameraManagerAddr()
    {
        uintptr_t gsc_instance = DMKMemory::read_ptr_unsafe(g_gsc_static_ptr_addr, 0);
        if (!gsc_instance)
            return 0;

        return DMKMemory::read_ptr_unsafe(gsc_instance, OFFSET_CAM_MANAGER_IN_GSC);
    }

    WORD GetCameraMode()
    {
        uintptr_t cam_mgr = GetCameraManagerAddr();
        if (!cam_mgr)
            return CAMERA_MODE_FPV;

        auto *flag_addr = reinterpret_cast<void *>(
            cam_mgr + static_cast<uintptr_t>(OFFSET_CAMERA_MODE_FLAG));
        if (!DMKMemory::is_readable(flag_addr, sizeof(WORD)))
            return CAMERA_MODE_FPV;

        return *reinterpret_cast<WORD *>(flag_addr);
    }

    void SetCameraMode(WORD mode)
    {
        uintptr_t cam_mgr = GetCameraManagerAddr();
        if (!cam_mgr)
            return;

        auto *flag_addr = reinterpret_cast<void *>(
            cam_mgr + static_cast<uintptr_t>(OFFSET_CAMERA_MODE_FLAG));
        if (!DMKMemory::is_writable(flag_addr, sizeof(WORD)))
            return;

        WORD current = *reinterpret_cast<WORD *>(flag_addr);
        if (current != mode)
        {
            *reinterpret_cast<WORD *>(flag_addr) = mode;
            DMKLogger::get_instance().info("Camera mode set to: {} ({})", mode, get_camera_mode_name(mode));
        }
    }

    void ToggleView()
    {
        WORD currentMode = GetCameraMode();
        WORD newMode = currentMode == CAMERA_MODE_TPV ? CAMERA_MODE_FPV : CAMERA_MODE_TPV;
        DMKLogger::get_instance().debug("Toggling camera mode: {} -> {}",
                                        get_camera_mode_name(currentMode), get_camera_mode_name(newMode));
        SetCameraMode(newMode);
    }

    bool ResolveGSCPointer()
    {
        DMKLogger &logger = DMKLogger::get_instance();

        HMODULE h_module = GetModuleHandleA(TARGET_MODULE);
        if (!h_module)
            return false;

        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), h_module, &mi, sizeof(mi)))
        {
            logger.error("GetModuleInformation failed for {}", TARGET_MODULE);
            return false;
        }

        auto *base = static_cast<const std::byte *>(mi.lpBaseOfDll);
        size_t size = mi.SizeOfImage;

        for (const auto &[name, aob] : PATTERNS)
        {
            auto compiled = DMKScanner::parse_aob(aob);
            if (!compiled)
            {
                logger.warning("Failed to parse AOB pattern: {}", name);
                continue;
            }

            const std::byte *match = DMKScanner::find_pattern(base, size, *compiled);
            if (!match)
            {
                logger.debug("Pattern '{}' not found in {}", name, TARGET_MODULE);
                continue;
            }

            // find_pattern returns raw match start; advance by compiled offset to the MOV instruction
            const std::byte *mov_instr = match + compiled->offset;
            auto resolved = DMKScanner::resolve_rip_relative(mov_instr, 3, 7);
            if (!resolved)
            {
                logger.warning("Pattern '{}' matched but RIP resolution failed", name);
                continue;
            }

            g_gsc_static_ptr_addr = *resolved;
            logger.info("GSC pointer resolved via pattern '{}' at {}",
                        name, DMKFormat::format_address(g_gsc_static_ptr_addr));
            return true;
        }

        logger.error("No AOB pattern matched in {} -- game version may be unsupported", TARGET_MODULE);
        return false;
    }

    void Initialize()
    {
        DMKLogger::configure("KCD1_TPVToggle", "KCD1_TPVToggle.log", "%Y-%m-%d %H:%M:%S");
        DMKLogger &logger = DMKLogger::get_instance();

        // Mod info
        logger.info("{} v{} by {}", MOD_NAME, MOD_VERSION, MOD_AUTHOR);
        logger.info("Source: {}", MOD_SOURCE);
        logger.info("Nexus: {}", MOD_NEXUS);

        DMKConfig::register_key_combo(
            "Settings", "ToggleKey", "Toggle View Keys",
            [](const DMKKeyComboList &combos)
            { g_config.toggle_combos = combos; },
            "F3");
        DMKConfig::register_key_combo(
            "Settings", "FPVKey", "Force FPV Keys",
            [](const DMKKeyComboList &combos)
            { g_config.fpv_combos = combos; },
            "");
        DMKConfig::register_key_combo(
            "Settings", "TPVKey", "Force TPV Keys",
            [](const DMKKeyComboList &combos)
            { g_config.tpv_combos = combos; },
            "");
        DMKConfig::register_string(
            "Settings", "LogLevel", "Log Level",
            [](const std::string &val)
            { g_config.log_level_str = val; },
            "INFO");
        DMKConfig::load(INI_FILENAME);
        DMKConfig::log_all();

        logger.set_log_level(DMKLogger::string_to_log_level(g_config.log_level_str));
        logger.enable_async_mode();

        DMKMemory::init_cache();

        while (!g_shutting_down)
        {
            if (ResolveGSCPointer())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(INIT_RETRY_MS));
        }

        if (g_shutting_down || g_gsc_static_ptr_addr == 0)
            return;

        uintptr_t cam_mgr = GetCameraManagerAddr();
        if (!cam_mgr)
        {
            logger.debug("GSC resolved but CameraManager not yet available; will retry on first input");
        }
        else
        {
            logger.info("CameraManager found at {}", DMKFormat::format_address(cam_mgr));
        }

        auto &input = DMKInputManager::get_instance();

        if (!g_config.toggle_combos.empty())
        {
            input.register_press("toggle_view", g_config.toggle_combos, []()
                                 { ToggleView(); });
        }

        if (!g_config.fpv_combos.empty())
        {
            input.register_press("force_fpv", g_config.fpv_combos, []()
                                 { SetCameraMode(CAMERA_MODE_FPV); });
        }

        if (!g_config.tpv_combos.empty())
        {
            input.register_press("force_tpv", g_config.tpv_combos, []()
                                 { SetCameraMode(CAMERA_MODE_TPV); });
        }

        input.start();
        g_initialized = true;

        logger.info("Initialization complete. {} input binding(s) registered.",
                    input.binding_count());
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, [[maybe_unused]] LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        std::thread(Mod::Initialize).detach();
        break;

    case DLL_PROCESS_DETACH:
        Mod::g_shutting_down = true;
        // DMK_Shutdown() must be called BEFORE DLL_PROCESS_DETACH to avoid
        // loader-lock deadlocks. If we reach here without a prior shutdown,
        // set the flag so any spinning init loop exits promptly.
        // The actual cleanup is driven by the ASI loader calling FreeLibrary
        // after our init thread has finished.
        DMK_Shutdown();
        break;
    }
    return TRUE;
}
