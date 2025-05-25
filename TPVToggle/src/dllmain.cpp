#include <windows.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <algorithm>

#include <DetourModKit.hpp>

namespace Mod
{
    // --- Mod Configuration (Loaded from INI) ---
    struct Config
    {
        std::vector<int> toggle_keys;
        std::vector<int> fpv_keys;
        std::vector<int> tpv_keys;
        std::string log_level_str = "INFO";
    } g_config;

    // --- Game Specific Data & Pointers ---
    const char *TARGET_GAME_MODULE_NAME = "WHGame.dll";
    const uintptr_t RVA_CAMERA_MANAGER_VFTABLE = 0x021C05C8;

    // FUN_1808ba46c
    const uintptr_t RVA_GET_GLOBAL_SYSTEM_CONTEXT = 0x008BA46C;
    const ptrdiff_t OFFSET_CAM_MANAGER_PTR_IN_GSC = 0x38; // Offset within GlobalSystemContext object

    uintptr_t g_camera_manager_instance_addr = 0;   // Will hold the found CameraManager instance address
    const ptrdiff_t OFFSET_CAMERA_MODE_FLAG = 0x18; // Offset of the WORD flag within CameraManager

    // Camera mode flag values (WORD type)
    const WORD CAMERA_MODE_FPV = 0;
    const WORD CAMERA_MODE_TPV = 1;

    // --- Mod State ---
    std::vector<bool> g_toggle_key_was_pressed;
    std::vector<bool> g_fpv_key_was_pressed;
    std::vector<bool> g_tpv_key_was_pressed;

    bool g_mod_shutting_down = false;
    const int INIT_RETRY_MILLISECONDS = 500;

    std::thread g_input_monitoring_thread;

    // --- Function Pointer Types ---
    // For FUN_1808ba46c
    typedef uintptr_t (*GetGlobalSystemContext_t)();

    // --- Forward Declarations ---
    void InitializeModLogic();
    void ShutdownModLogic();
    [[noreturn]] void MonitorInputAndToggle();
    bool FindCameraManagerInstance(HMODULE h_game_module);
    void SetCameraMode(WORD mode);
    WORD GetCurrentCameraMode();
    void ToggleViewAction();

} // namespace Mod

// --- Mod Initialization Logic ---
void Mod::InitializeModLogic()
{
    DMKLogger::configure("KCD1_TPVToggle", "KCD1_TPVToggle.log", "%Y-%m-%d %H:%M:%S");
    DMKLogger &logger = DMKLogger::getInstance();

    DMKConfig::registerKeyList("Settings", "ToggleKey", "Toggle View Keys", Mod::g_config.toggle_keys, "0x72");
    DMKConfig::registerKeyList("Settings", "FPVKey", "Force First-Person View Keys", Mod::g_config.fpv_keys, "");
    DMKConfig::registerKeyList("Settings", "TPVKey", "Force Third-Person View Keys", Mod::g_config.tpv_keys, "");
    DMKConfig::registerString("Settings", "LogLevel", "Log Level (TRACE, DEBUG, INFO, WARNING, ERROR)", Mod::g_config.log_level_str, "INFO");

    std::string ini_path = DMKFilesystem::getRuntimeDirectory() + "\\KCD1_TPVToggle.ini";
    DMKConfig::load(ini_path);

    logger.setLogLevel(DMKLogger::stringToLogLevel(Mod::g_config.log_level_str));
    logger.log(DMK::LOG_INFO, "KCD1_TPVToggle InitializeModLogic started.");
    logger.log(DMK::LOG_INFO, "INI configuration loaded from: " + ini_path);
    DMKConfig::logAll();

    DMKMemory::initMemoryCache();

    logger.log(DMK::LOG_INFO, "Waiting for target game module and C_CameraManager instance...");

    HMODULE h_game_module = nullptr;

    while (!Mod::g_mod_shutting_down)
    {
        h_game_module = GetModuleHandleA(Mod::TARGET_GAME_MODULE_NAME);
        if (h_game_module)
        {
            if (Mod::FindCameraManagerInstance(h_game_module))
            {
                logger.log(DMK::LOG_INFO, "C_CameraManager instance found at: " + DMKString::format_address(Mod::g_camera_manager_instance_addr));
                logger.log(DMK::LOG_DEBUG, "Camera Mode Flag is expected at: " + DMKString::format_address(Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG));
                break;
            }
        }

        if (!Mod::g_mod_shutting_down)
            std::this_thread::sleep_for(std::chrono::milliseconds(INIT_RETRY_MILLISECONDS));
    }

    if (Mod::g_mod_shutting_down)
    {
        logger.log(DMK::LOG_INFO, "Mod shutdown signaled during initialization wait.");
        return;
    }

    if (!Mod::g_camera_manager_instance_addr)
    {
        return;
    }

    Mod::g_toggle_key_was_pressed.assign(Mod::g_config.toggle_keys.size(), false);
    Mod::g_fpv_key_was_pressed.assign(Mod::g_config.fpv_keys.size(), false);
    Mod::g_tpv_key_was_pressed.assign(Mod::g_config.tpv_keys.size(), false);

    Mod::g_input_monitoring_thread = std::thread(Mod::MonitorInputAndToggle);

    logger.log(DMK::LOG_INFO, "KCD1_TPVToggle initialized successfully and input monitoring started.");
}

// --- Game Structure Finding (New Robust Method) ---
bool Mod::FindCameraManagerInstance(HMODULE h_game_module)
{
    DMKLogger &logger = DMKLogger::getInstance();

    uintptr_t get_gsc_func_addr = reinterpret_cast<uintptr_t>(h_game_module) + Mod::RVA_GET_GLOBAL_SYSTEM_CONTEXT;

    static bool get_gsc_func_addr_logged = false;
    if (!get_gsc_func_addr_logged)
    {
        logger.log(DMK::LOG_DEBUG, "Attempting to use GetGlobalSystemContext function at: " + DMKString::format_address(get_gsc_func_addr));
        get_gsc_func_addr_logged = true;
    }

    if (!DMKMemory::isMemoryReadable(reinterpret_cast<void *>(get_gsc_func_addr), 1))
    {
        return false;
    }

    GetGlobalSystemContext_t fnGetGSC = reinterpret_cast<GetGlobalSystemContext_t>(get_gsc_func_addr);
    uintptr_t global_system_context_addr = 0;

    try
    {
        global_system_context_addr = fnGetGSC();
    }
    catch (const std::exception &e)
    {
        logger.log(DMK::LOG_ERROR, std::string("Exception calling GetGlobalSystemContext: ") + e.what());
        return false;
    }
    catch (...)
    {
        return false;
    }

    if (global_system_context_addr == 0)
    {
        return false;
    }

    uintptr_t cam_manager_ptr_location = global_system_context_addr + Mod::OFFSET_CAM_MANAGER_PTR_IN_GSC;
    if (!DMKMemory::isMemoryReadable(reinterpret_cast<void *>(cam_manager_ptr_location), sizeof(uintptr_t)))
    {
        return false;
    }

    Mod::g_camera_manager_instance_addr = *reinterpret_cast<uintptr_t *>(cam_manager_ptr_location);

    if (Mod::g_camera_manager_instance_addr == 0)
    {
        return false;
    }

    uintptr_t absolute_cam_manager_vftable_addr = reinterpret_cast<uintptr_t>(h_game_module) + Mod::RVA_CAMERA_MANAGER_VFTABLE;
    if (DMKMemory::isMemoryReadable(reinterpret_cast<void *>(Mod::g_camera_manager_instance_addr), sizeof(uintptr_t)))
    {
        uintptr_t actual_vftable_ptr = *reinterpret_cast<uintptr_t *>(Mod::g_camera_manager_instance_addr);
        if (actual_vftable_ptr == absolute_cam_manager_vftable_addr)
        {
            // logger.log(DMK::LOG_DEBUG, "C_CameraManager instance vftable matches. Instance confirmed.");
            return true;
        }
        else
        {
            logger.log(DMK::LOG_ERROR, "C_CameraManager instance found, but vftable MISMATCH! Instance: " + DMKString::format_address(Mod::g_camera_manager_instance_addr) +
                                           " Expected vfptr: " + DMKString::format_address(absolute_cam_manager_vftable_addr) +
                                           ", Actual vfptr: " + DMKString::format_address(actual_vftable_ptr));
            Mod::g_camera_manager_instance_addr = 0;
            return false;
        }
    }
    else
    {
        logger.log(DMK::LOG_ERROR, "C_CameraManager instance found (" + DMKString::format_address(Mod::g_camera_manager_instance_addr) + "), but cannot read its vftable for validation.");
        Mod::g_camera_manager_instance_addr = 0;
        return false;
    }
}

// --- Core Toggle Logic ---
void Mod::SetCameraMode(WORD mode)
{
    if (Mod::g_camera_manager_instance_addr == 0)
        return;
    uintptr_t flag_address = Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG;

    if (DMKMemory::isMemoryWritable(reinterpret_cast<void *>(flag_address), sizeof(WORD)))
    {
        WORD current_mode = *reinterpret_cast<WORD *>(flag_address);
        if (current_mode != mode)
        {
            *reinterpret_cast<WORD *>(flag_address) = mode;
            DMKLogger::getInstance().log(DMK::LOG_INFO, "Camera mode flag set to: " + std::to_string(mode) +
                                                            " (Previous: " + std::to_string(current_mode) +
                                                            "). Address: " + DMKString::format_address(flag_address));
        }
    }
    else
    {
        DMKLogger::getInstance().log(DMK::LOG_ERROR, "SetCameraMode: Cannot write to camera mode flag address: " + DMKString::format_address(flag_address));
    }
}

WORD Mod::GetCurrentCameraMode()
{
    if (Mod::g_camera_manager_instance_addr == 0)
        return Mod::CAMERA_MODE_FPV;
    uintptr_t flag_address = Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG;

    if (DMKMemory::isMemoryReadable(reinterpret_cast<const void *>(flag_address), sizeof(WORD)))
    {
        return *reinterpret_cast<WORD *>(flag_address);
    }
    DMKLogger::getInstance().log(DMK::LOG_WARNING, "GetCurrentCameraMode: Cannot read camera mode flag at " + DMKString::format_address(flag_address) + ", returning FPV default.");
    return Mod::CAMERA_MODE_FPV;
}

void Mod::ToggleViewAction()
{
    WORD current_mode = GetCurrentCameraMode();
    if (current_mode == Mod::CAMERA_MODE_TPV)
        Mod::SetCameraMode(Mod::CAMERA_MODE_FPV);
    else
        Mod::SetCameraMode(Mod::CAMERA_MODE_TPV);
}

// --- Input Monitoring ---
[[noreturn]] void Mod::MonitorInputAndToggle()
{
    DMKLogger &logger = DMKLogger::getInstance(); // Get once
    logger.log(DMK::LOG_INFO, "Input monitoring thread started.");

    while (!Mod::g_mod_shutting_down)
    {
        if (Mod::g_camera_manager_instance_addr == 0)
        {
            if (!Mod::g_mod_shutting_down)
                std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        bool action_taken_this_cycle = false;

        if (!action_taken_this_cycle && !Mod::g_config.toggle_keys.empty())
        {
            for (size_t i = 0; i < Mod::g_config.toggle_keys.size(); ++i)
            {
                if (GetAsyncKeyState(Mod::g_config.toggle_keys[i]) & 0x8000)
                {
                    if (!Mod::g_toggle_key_was_pressed[i])
                    {
                        Mod::ToggleViewAction();
                        Mod::g_toggle_key_was_pressed[i] = true;
                        action_taken_this_cycle = true;
                        break;
                    }
                }
                else
                {
                    Mod::g_toggle_key_was_pressed[i] = false;
                }
            }
        }
        if (!action_taken_this_cycle && !Mod::g_config.fpv_keys.empty())
        {
            for (size_t i = 0; i < Mod::g_config.fpv_keys.size(); ++i)
            {
                if (GetAsyncKeyState(Mod::g_config.fpv_keys[i]) & 0x8000)
                {
                    if (!Mod::g_fpv_key_was_pressed[i])
                    {
                        Mod::SetCameraMode(Mod::CAMERA_MODE_FPV);
                        Mod::g_fpv_key_was_pressed[i] = true;
                        action_taken_this_cycle = true;
                        break;
                    }
                }
                else
                {
                    Mod::g_fpv_key_was_pressed[i] = false;
                }
            }
        }
        if (!action_taken_this_cycle && !Mod::g_config.tpv_keys.empty())
        {
            for (size_t i = 0; i < Mod::g_config.tpv_keys.size(); ++i)
            {
                if (GetAsyncKeyState(Mod::g_config.tpv_keys[i]) & 0x8000)
                {
                    if (!Mod::g_tpv_key_was_pressed[i])
                    {
                        Mod::SetCameraMode(Mod::CAMERA_MODE_TPV);
                        Mod::g_tpv_key_was_pressed[i] = true;
                        break;
                    }
                }
                else
                {
                    Mod::g_tpv_key_was_pressed[i] = false;
                }
            }
        }
        if (!Mod::g_mod_shutting_down)
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    logger.log(DMK::LOG_INFO, "Input monitoring thread exiting due to shutdown signal.");
}

// --- Mod Shutdown ---
void Mod::ShutdownModLogic()
{
    DMKLogger &logger = DMKLogger::getInstance();
    logger.log(DMK::LOG_INFO, "KCD1_TPVToggle Shutting Down...");
    Mod::g_mod_shutting_down = true;

    if (Mod::g_input_monitoring_thread.joinable())
    {
        logger.log(DMK::LOG_DEBUG, "Waiting for input monitoring thread to join...");
        Mod::g_input_monitoring_thread.join();
        logger.log(DMK::LOG_DEBUG, "Input monitoring thread joined.");
    }
    DMKConfig::clearRegisteredItems();
    DMKMemory::clearMemoryCache();
    logger.log(DMK::LOG_INFO, "KCD1_TPVToggle Shutdown Complete.");
}

// --- DLL Main Entry Point ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)lpReserved;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);
        std::thread init_thread(Mod::InitializeModLogic);
        init_thread.detach();
    }
    break;
    case DLL_PROCESS_DETACH:
        Mod::ShutdownModLogic();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
