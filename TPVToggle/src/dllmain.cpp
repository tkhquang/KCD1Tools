#include <windows.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>

#include <DetourModKit.hpp>

namespace Mod
{
    // Mod Configuration (Loaded from INI)
    struct Config
    {
        std::vector<int> toggle_keys;
        std::vector<int> fpv_keys;
        std::vector<int> tpv_keys;
        std::string log_level_str = "INFO";
    } g_config;

    // Game Specific Data & Pointers
    const char *TARGET_GAME_MODULE_NAME = "WHGame.dll";

    // AOB for FUN_1808ba46c (GetGlobalSystemContext function)
    // Starts at instruction: mov edx, 4 (WHGame.DLL+8BA481)
    const char *AOB_GET_GLOBAL_SYSTEM_CONTEXT =
        "BA 04 00 00 00 "       // mov edx, 4
        "48 8B 0C C8 "          // mov rcx, [rax+rcx*8]
        "8B 04 0A "             // mov eax, [rdx+rcx]
        "39 05 ?? ?? ?? ?? "    // cmp [rip+imm32_A], eax
        "7F 0D "                // jg $+0D
        "48 8B 05 ?? ?? ?? ?? " // mov rax, [rip+imm32_B] (GSC pointer loaded into RAX)
        "48 83 C4 ?? "          // add rsp, ??
        "5B "                   // pop rbx
        "C3";                   // ret

    // Offset from the start of the AOB match (WHGame.DLL+8BA481) to the actual function entry point (WHGame.DLL+8BA46C).
    // func_start = aob_match_addr - 0x15.
    const ptrdiff_t OFFSET_FROM_AOB_TO_FUNC_START = -0x15;

    // Offset within the GlobalSystemContext object to the C_CameraManager*
    const ptrdiff_t OFFSET_CAM_MANAGER_PTR_IN_GSC = 0x38;

    // Will hold the found CameraManager instance address
    uintptr_t g_camera_manager_instance_addr = 0;
    // Offset of the WORD flag within CameraManager
    const ptrdiff_t OFFSET_CAMERA_MODE_FLAG = 0x18;

    // Camera mode flag values (WORD type)
    const WORD CAMERA_MODE_FPV = 0;
    const WORD CAMERA_MODE_TPV = 1;

    // Mod State
    std::vector<bool> g_toggle_key_was_pressed;
    std::vector<bool> g_fpv_key_was_pressed;
    std::vector<bool> g_tpv_key_was_pressed;

    bool g_mod_shutting_down = false;
    const int INIT_RETRY_MILLISECONDS = 500; // How often to retry finding game systems

    std::thread g_input_monitoring_thread;

    // Function Pointer Type for GetGlobalSystemContext
    typedef uintptr_t (*GetGlobalSystemContext_t)();

    // Forward Declarations
    void InitializeModLogic();
    void ShutdownModLogic();
    [[noreturn]] void MonitorInputAndToggle();
    bool FindAndSetCameraManagerInstance(HMODULE h_game_module);
    void SetCameraMode(WORD mode);
    WORD GetCurrentCameraMode();
    void ToggleViewAction();

} // namespace Mod

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
    unsigned int retry_log_counter = 0;
    const unsigned int log_every_n_retries = 4; // Log "still waiting" every ~2 seconds

    // Loop indefinitely until CameraManager is found or shutdown is signaled
    while (!Mod::g_mod_shutting_down)
    {
        h_game_module = GetModuleHandleA(Mod::TARGET_GAME_MODULE_NAME);
        if (h_game_module)
        {
            if (Mod::FindAndSetCameraManagerInstance(h_game_module))
            {
                logger.log(DMK::LOG_INFO, "C_CameraManager instance found at: " + DMKString::format_address(Mod::g_camera_manager_instance_addr));
                logger.log(DMK::LOG_DEBUG, "Camera Mode Flag is expected at: " + DMKString::format_address(Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG));
                break; // Success, exit loop
            }
        }

        retry_log_counter++;
        if (retry_log_counter % log_every_n_retries == 0)
        {
            logger.log(DMK::LOG_DEBUG, "Still waiting for C_CameraManager...");
        }

        if (!Mod::g_mod_shutting_down)
            std::this_thread::sleep_for(std::chrono::milliseconds(INIT_RETRY_MILLISECONDS));
    }

    if (Mod::g_mod_shutting_down)
    {
        logger.log(DMK::LOG_INFO, "Mod shutdown signaled during initialization wait. Initialization aborted.");
        return;
    }

    // This part is reached only if CameraManager was successfully found or shutdown occurred.
    // If g_camera_manager_instance_addr is still 0 here, it means the loop was exited by shutdown.
    if (!Mod::g_camera_manager_instance_addr)
    {
        logger.log(DMK::LOG_ERROR, "Failed to find C_CameraManager instance. Mod will not function.");
        return;
    }

    Mod::g_toggle_key_was_pressed.assign(Mod::g_config.toggle_keys.size(), false);
    Mod::g_fpv_key_was_pressed.assign(Mod::g_config.fpv_keys.size(), false);
    Mod::g_tpv_key_was_pressed.assign(Mod::g_config.tpv_keys.size(), false);

    Mod::g_input_monitoring_thread = std::thread(Mod::MonitorInputAndToggle);

    logger.log(DMK::LOG_INFO, "KCD1_TPVToggle initialized successfully and input monitoring started.");
}

bool Mod::FindAndSetCameraManagerInstance(HMODULE h_game_module)
{
    DMKLogger &logger = DMKLogger::getInstance();
    // This will hold the address of the GetGlobalSystemContext function once found
    static uintptr_t get_gsc_func_addr = 0;

    // Step 1: Find GetGlobalSystemContext function via AOB scan (only needs to be done once)
    if (get_gsc_func_addr == 0)
    {
        MODULEINFO module_info = {nullptr};
        if (!GetModuleInformation(GetCurrentProcess(), h_game_module, &module_info, sizeof(module_info)))
        {
            // This should ideally not happen if h_game_module is valid from GetModuleHandleA
            logger.log(DMK::LOG_ERROR, "FindAndSetCameraManagerInstance: GetModuleInformation failed for module: " + std::string(Mod::TARGET_GAME_MODULE_NAME));
            return false;
        }

        std::vector<std::byte> pattern_bytes = DMKScanner::parseAOB(Mod::AOB_GET_GLOBAL_SYSTEM_CONTEXT);
        if (pattern_bytes.empty())
        {
            logger.log(DMK::LOG_ERROR, "Failed to parse AOB pattern for GetGlobalSystemContext.");
            return false;
        }

        std::byte *found_pattern_location = DMKScanner::FindPattern(
            reinterpret_cast<std::byte *>(module_info.lpBaseOfDll),
            module_info.SizeOfImage,
            pattern_bytes);

        if (!found_pattern_location)
        {
            // This is a normal condition during early game startup, so not logged as error here.
            // The calling loop in InitializeModLogic will log "Still waiting..."
            return false;
        }

        get_gsc_func_addr = reinterpret_cast<uintptr_t>(found_pattern_location) + Mod::OFFSET_FROM_AOB_TO_FUNC_START;
        logger.log(DMK::LOG_INFO, "GetGlobalSystemContext function found via AOB at: " + DMKString::format_address(get_gsc_func_addr) +
                                      " (AOB matched at: " + DMKString::format_address(reinterpret_cast<uintptr_t>(found_pattern_location)) + ")");
    }

    // Step 2: Call GetGlobalSystemContext
    GetGlobalSystemContext_t fnGetGSC = reinterpret_cast<GetGlobalSystemContext_t>(get_gsc_func_addr);
    uintptr_t global_system_context_addr = 0;

    try
    {
        global_system_context_addr = fnGetGSC();
    }
    catch (const std::exception &e)
    {
        // If this happens after AOB found, it might be a timing issue where the function isn't safe to call.
        // Or the AOB/offset was wrong, leading to a crash.
        logger.log(DMK::LOG_WARNING, std::string("Exception calling GetGlobalSystemContext: ") + e.what());
        get_gsc_func_addr = 0; // Reset to re-scan if AOB was a false positive or if it became invalid
        return false;
    }
    catch (...)
    {
        logger.log(DMK::LOG_WARNING, "Unknown exception calling GetGlobalSystemContext. Function may not be ready or AOB/offset incorrect.");
        get_gsc_func_addr = 0; // Reset
        return false;
    }

    if (global_system_context_addr == 0)
    {
        // Game's global context isn't ready yet, common during startup.
        return false;
    }

    // Step 3: Get C_CameraManager pointer from GlobalSystemContext
    uintptr_t cam_manager_ptr_location = global_system_context_addr + Mod::OFFSET_CAM_MANAGER_PTR_IN_GSC;
    if (!DMKMemory::isMemoryReadable(reinterpret_cast<void *>(cam_manager_ptr_location), sizeof(uintptr_t)))
    {
        logger.log(DMK::LOG_WARNING, "Cannot read C_CameraManager* from GSC + offset. GSC: " + DMKString::format_address(global_system_context_addr));
        return false;
    }

    uintptr_t temp_cam_manager_addr = *reinterpret_cast<uintptr_t *>(cam_manager_ptr_location);

    if (temp_cam_manager_addr == 0)
    {
        // CameraManager itself might not be initialized within GSC yet.
        return false;
    }

    // Step 4: Basic validation of the found C_CameraManager instance address
    // Check if we can at least read the memory where the instance is supposed to be.
    if (!DMKMemory::isMemoryReadable(reinterpret_cast<void *>(temp_cam_manager_addr), sizeof(uintptr_t)))
    {
        logger.log(DMK::LOG_WARNING, "Found C_CameraManager address (" + DMKString::format_address(temp_cam_manager_addr) + "), but it's not readable.");
        return false;
    }

    // Successfully found and validated (basic read check)
    Mod::g_camera_manager_instance_addr = temp_cam_manager_addr;
    return true;
}

void Mod::SetCameraMode(WORD mode)
{
    if (Mod::g_camera_manager_instance_addr == 0)
        return;

    uintptr_t flag_address = Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG;
    DMKLogger &logger = DMKLogger::getInstance();

    if (DMKMemory::isMemoryWritable(reinterpret_cast<void *>(flag_address), sizeof(WORD)))
    {
        WORD current_mode = *reinterpret_cast<WORD *>(flag_address);
        if (current_mode != mode)
        {
            *reinterpret_cast<WORD *>(flag_address) = mode;
            logger.log(DMK::LOG_INFO, "Camera mode flag set to: " + std::to_string(mode) +
                                          " (Previous: " + std::to_string(current_mode) +
                                          "). Address: " + DMKString::format_address(flag_address));
        }
    }
    else
    {
        logger.log(DMK::LOG_ERROR, "SetCameraMode: Cannot write to camera mode flag address: " + DMKString::format_address(flag_address));
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

[[noreturn]] void Mod::MonitorInputAndToggle()
{
    DMKLogger &logger = DMKLogger::getInstance();
    logger.log(DMK::LOG_INFO, "Input monitoring thread started.");

    while (!Mod::g_mod_shutting_down)
    {
        // Ensure CameraManager is available before processing keys
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
