#include <windows.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>

#include <DetourModKit.hpp>

namespace Mod
{
    struct Config
    {
        std::vector<int> toggle_keys;
        std::vector<int> fpv_keys;
        std::vector<int> tpv_keys;
        std::string log_level_str = "INFO";
    } g_config;

    const char *TARGET_GAME_MODULE_NAME = "WHGame.dll";

    // AOB for GlobalSystemContext (GSC) pointer retrieval via logic tail
    const char *AOB_GSC_LOCATION = "39 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B 5C 24 ?? 48 83 C4 ?? 5F C3";

    const ptrdiff_t OFFSET_CAM_MANAGER_PTR_IN_GSC = 0x38;
    const ptrdiff_t OFFSET_CAMERA_MODE_FLAG = 0x18;

    const WORD CAMERA_MODE_FPV = 0;
    const WORD CAMERA_MODE_TPV = 1;

    uintptr_t g_gsc_static_ptr_addr = 0;
    uintptr_t g_camera_manager_instance_addr = 0;

    std::vector<bool> g_toggle_key_was_pressed;
    std::vector<bool> g_fpv_key_was_pressed;
    std::vector<bool> g_tpv_key_was_pressed;

    std::atomic<bool> g_mod_shutting_down{false};
    const int INIT_RETRY_MILLISECONDS = 500;

    std::thread g_input_monitoring_thread;

    void InitializeModLogic();
    void ShutdownModLogic();
    [[noreturn]] void MonitorInputAndToggle();
    bool FindAndSetCameraManagerInstance(HMODULE h_game_module);
    void SetCameraMode(WORD mode);
    WORD GetCurrentCameraMode();
    void ToggleViewAction();
}

bool Mod::FindAndSetCameraManagerInstance(HMODULE h_game_module)
{
    DMKLogger &logger = DMKLogger::getInstance();

    if (g_gsc_static_ptr_addr == 0)
    {
        MODULEINFO module_info = {0};
        if (!GetModuleInformation(GetCurrentProcess(), h_game_module, &module_info, sizeof(module_info)))
            return false;

        std::vector<std::byte> pattern = DMKScanner::parseAOB(Mod::AOB_GSC_LOCATION);
        std::byte *match = DMKScanner::FindPattern((std::byte *)module_info.lpBaseOfDll, module_info.SizeOfImage, pattern);

        if (!match)
            return false;

        // Extract the MOV RAX, [RIP+Imm32] instruction address
        std::byte *mov_instr = nullptr;
        for (int i = 0; i < 20; ++i)
        {
            if (match[i] == (std::byte)0x48 && match[i + 1] == (std::byte)0x8B && match[i + 2] == (std::byte)0x05)
            {
                mov_instr = &match[i];
                break;
            }
        }

        if (!mov_instr)
            return false;

        // Calculate absolute address using RIP relative displacement (Instruction pointer + length (7) + displacement)
        int32_t rel_offset = *reinterpret_cast<int32_t *>(mov_instr + 3);
        g_gsc_static_ptr_addr = reinterpret_cast<uintptr_t>(mov_instr) + 7 + rel_offset;

        logger.log(DMK::LOG_INFO, "GlobalSystemContext static pointer resolved at: " + DMKString::format_address(g_gsc_static_ptr_addr));
    }

    if (!DMKMemory::isMemoryReadable((void *)g_gsc_static_ptr_addr, sizeof(uintptr_t)))
        return false;

    uintptr_t gsc_instance = *reinterpret_cast<uintptr_t *>(g_gsc_static_ptr_addr);
    if (!gsc_instance)
        return false;

    uintptr_t cam_manager_ptr_loc = gsc_instance + Mod::OFFSET_CAM_MANAGER_PTR_IN_GSC;
    if (!DMKMemory::isMemoryReadable((void *)cam_manager_ptr_loc, sizeof(uintptr_t)))
        return false;

    uintptr_t temp_addr = *reinterpret_cast<uintptr_t *>(cam_manager_ptr_loc);
    if (!temp_addr || !DMKMemory::isMemoryReadable((void *)temp_addr, sizeof(uintptr_t)))
        return false;

    Mod::g_camera_manager_instance_addr = temp_addr;
    return true;
}

void Mod::SetCameraMode(WORD mode)
{
    if (Mod::g_camera_manager_instance_addr == 0)
        return;

    uintptr_t flag_address = Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG;
    if (DMKMemory::isMemoryWritable((void *)flag_address, sizeof(WORD)))
    {
        WORD current_mode = *reinterpret_cast<WORD *>(flag_address);
        if (current_mode != mode)
        {
            *reinterpret_cast<WORD *>(flag_address) = mode;
            DMKLogger::getInstance().log(DMK::LOG_INFO, "Camera mode changed to: " + std::to_string(mode));
        }
    }
}

WORD Mod::GetCurrentCameraMode()
{
    if (Mod::g_camera_manager_instance_addr == 0)
        return Mod::CAMERA_MODE_FPV;

    uintptr_t flag_address = Mod::g_camera_manager_instance_addr + Mod::OFFSET_CAMERA_MODE_FLAG;
    if (DMKMemory::isMemoryReadable((void *)flag_address, sizeof(WORD)))
        return *reinterpret_cast<WORD *>(flag_address);

    return Mod::CAMERA_MODE_FPV;
}

void Mod::ToggleViewAction()
{
    SetCameraMode(GetCurrentCameraMode() == Mod::CAMERA_MODE_TPV ? Mod::CAMERA_MODE_FPV : Mod::CAMERA_MODE_TPV);
}

[[noreturn]] void Mod::MonitorInputAndToggle()
{
    while (!Mod::g_mod_shutting_down)
    {
        if (Mod::g_camera_manager_instance_addr != 0)
        {
            for (size_t i = 0; i < Mod::g_config.toggle_keys.size(); ++i)
            {
                if (GetAsyncKeyState(Mod::g_config.toggle_keys[i]) & 0x8000)
                {
                    if (!Mod::g_toggle_key_was_pressed[i])
                    {
                        Mod::ToggleViewAction();
                        Mod::g_toggle_key_was_pressed[i] = true;
                    }
                }
                else
                    Mod::g_toggle_key_was_pressed[i] = false;
            }

            for (size_t i = 0; i < Mod::g_config.fpv_keys.size(); ++i)
            {
                if (GetAsyncKeyState(Mod::g_config.fpv_keys[i]) & 0x8000)
                {
                    if (!Mod::g_fpv_key_was_pressed[i])
                    {
                        Mod::SetCameraMode(Mod::CAMERA_MODE_FPV);
                        Mod::g_fpv_key_was_pressed[i] = true;
                    }
                }
                else
                    Mod::g_fpv_key_was_pressed[i] = false;
            }

            for (size_t i = 0; i < Mod::g_config.tpv_keys.size(); ++i)
            {
                if (GetAsyncKeyState(Mod::g_config.tpv_keys[i]) & 0x8000)
                {
                    if (!Mod::g_tpv_key_was_pressed[i])
                    {
                        Mod::SetCameraMode(Mod::CAMERA_MODE_TPV);
                        Mod::g_tpv_key_was_pressed[i] = true;
                    }
                }
                else
                    Mod::g_tpv_key_was_pressed[i] = false;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}

void Mod::InitializeModLogic()
{
    DMKLogger::configure("KCD1_TPVToggle", "KCD1_TPVToggle.log", "%Y-%m-%d %H:%M:%S");
    DMKLogger &logger = DMKLogger::getInstance();

    DMKConfig::registerKeyList("Settings", "ToggleKey", "Toggle View Keys", Mod::g_config.toggle_keys, "0x72");
    DMKConfig::registerKeyList("Settings", "FPVKey", "Force FPV Keys", Mod::g_config.fpv_keys, "");
    DMKConfig::registerKeyList("Settings", "TPVKey", "Force TPV Keys", Mod::g_config.tpv_keys, "");
    DMKConfig::registerString("Settings", "LogLevel", "Log Level", Mod::g_config.log_level_str, "INFO");

    std::string ini_path = DMKFilesystem::getRuntimeDirectory() + "\\KCD1_TPVToggle.ini";
    DMKConfig::load(ini_path);

    logger.setLogLevel(DMKLogger::stringToLogLevel(Mod::g_config.log_level_str));
    DMKMemory::initMemoryCache();

    while (!Mod::g_mod_shutting_down)
    {
        HMODULE h_game_module = GetModuleHandleA(Mod::TARGET_GAME_MODULE_NAME);
        if (h_game_module && Mod::FindAndSetCameraManagerInstance(h_game_module))
            break;

        std::this_thread::sleep_for(std::chrono::milliseconds(INIT_RETRY_MILLISECONDS));
    }

    if (!Mod::g_mod_shutting_down && Mod::g_camera_manager_instance_addr)
    {
        Mod::g_toggle_key_was_pressed.assign(Mod::g_config.toggle_keys.size(), false);
        Mod::g_fpv_key_was_pressed.assign(Mod::g_config.fpv_keys.size(), false);
        Mod::g_tpv_key_was_pressed.assign(Mod::g_config.tpv_keys.size(), false);
        Mod::g_input_monitoring_thread = std::thread(Mod::MonitorInputAndToggle);
        logger.log(DMK::LOG_INFO, "Initialization complete.");
    }
}

void Mod::ShutdownModLogic()
{
    Mod::g_mod_shutting_down = true;
    if (Mod::g_input_monitoring_thread.joinable())
        Mod::g_input_monitoring_thread.join();

    DMKConfig::clearRegisteredItems();
    DMKMemory::clearMemoryCache();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        std::thread(Mod::InitializeModLogic).detach();
        break;
    case DLL_PROCESS_DETACH:
        Mod::ShutdownModLogic();
        break;
    }
    return TRUE;
}
