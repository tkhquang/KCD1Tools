cmake_minimum_required(VERSION 3.28)

# Derive the project version from src/version.hpp (single source of truth).
set(_version_header "${CMAKE_CURRENT_SOURCE_DIR}/src/version.hpp")
file(STRINGS "${_version_header}" _ver_major REGEX "^#define +VERSION_MAJOR +[0-9]+")
file(STRINGS "${_version_header}" _ver_minor REGEX "^#define +VERSION_MINOR +[0-9]+")
file(STRINGS "${_version_header}" _ver_patch REGEX "^#define +VERSION_PATCH +[0-9]+")
string(REGEX REPLACE ".*VERSION_MAJOR +([0-9]+).*" "\\1" _ver_major "${_ver_major}")
string(REGEX REPLACE ".*VERSION_MINOR +([0-9]+).*" "\\1" _ver_minor "${_ver_minor}")
string(REGEX REPLACE ".*VERSION_PATCH +([0-9]+).*" "\\1" _ver_patch "${_ver_patch}")

project(KCD1_TPVCamera VERSION ${_ver_major}.${_ver_minor}.${_ver_patch} LANGUAGES CXX)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_version_header}")

# --- Standard and Compiler Options ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT MSVC)
  message(FATAL_ERROR "KCD1_TPVCamera requires the MSVC toolchain (Visual Studio 2022+).")
endif()

# --- Windows Definitions ---
if(WIN32)
  add_compile_definitions(
    WINVER=0x0A00
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _XM_SSE_INTRINSICS_ # DirectXMath inline functions (re-exported transitively by DetourModKit)
  )
endif()

# --- LTO for Release Builds ---
include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED OUTPUT IPO_OUTPUT)
if(IPO_SUPPORTED)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
  message(STATUS "LTO enabled for Release builds")
else()
  message(STATUS "LTO not supported: ${IPO_OUTPUT}")
endif()

# --- DetourModKit Dependency ---
# Preferred: a per-mod submodule at external/DetourModKit. Until that is added, the
# build reuses the sibling TPVToggle submodule already present in this repo. Override
# with -DKCD1_DMK_DIR=<path>.
set(KCD1_DMK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/DetourModKit" CACHE PATH
  "Path to a DetourModKit source checkout")

if(NOT EXISTS "${KCD1_DMK_DIR}/CMakeLists.txt")
  # This mod targets the DetourModKit 3.8.x API (same as the KCD2 TPVCamera it was
  # ported from: Anchors cascades, Bootstrap, Memory::seh_read, Rtti). The sibling
  # TPVToggle submodule pins an older 2.0.0 API that is NOT source-compatible, so it
  # is intentionally not used here. Until a per-mod submodule is added at
  # external/DetourModKit, fall back to the on-disk KCD2Tools 3.8.x checkout.
  set(_dmk_candidates
    "${CMAKE_CURRENT_SOURCE_DIR}/../../KCD2Tools/TPVCamera/external/DetourModKit"
  )
  foreach(_cand ${_dmk_candidates})
    if(EXISTS "${_cand}/CMakeLists.txt")
      set(KCD1_DMK_DIR "${_cand}")
      message(STATUS "DetourModKit: using 3.8.x checkout at ${KCD1_DMK_DIR}")
      break()
    endif()
  endforeach()
endif()

if(NOT EXISTS "${KCD1_DMK_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "DetourModKit not found. Initialize submodules "
    "('git submodule update --init --recursive') or pass -DKCD1_DMK_DIR=<path>.")
endif()

if(NOT TARGET DetourModKit)
  add_subdirectory("${KCD1_DMK_DIR}" "${CMAKE_BINARY_DIR}/_deps/DetourModKit-build")
endif()
if(NOT TARGET DetourModKit)
  message(FATAL_ERROR "DetourModKit target not created by subdirectory")
endif()

# DetourModKit brings safetyhook + Zydis + Zycore and re-exports DirectXMath; linking
# it is sufficient.

# --- Dear ImGui (compiled from source, linked directly -- no ReShade) ---
# The self-hosted overlay (src/overlay) renders ImGui through a private WARP
# D3D11 device and composites it over the game window with GDI; it links ImGui
# directly and calls ImGui:: / ImGui_ImplWin32_* / ImGui_ImplDX11_* with no
# function-table indirection. The docking tag is used so the Win32 + DX11
# backends match the v1.92.5 API the overlay was written against.
include(FetchContent)
FetchContent_Declare(
  imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG        v1.92.5-docking
  GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(imgui)

# --- nlohmann/json (header-only) for the preset store ---
if(NOT TARGET nlohmann_json::nlohmann_json)
  FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
  )
  FetchContent_MakeAvailable(nlohmann_json)
endif()

if(NOT TARGET imgui_lib)
  add_library(imgui_lib STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
  )
  target_include_directories(imgui_lib PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
  )
  # ImGui is third-party: do not subject it to /W4.
  target_compile_options(imgui_lib PRIVATE /W0)
endif()

# --- Build Options ---
# OFF (default): one production ASI built from the logic + dllmain.cpp.
# ON: a thin loader ASI plus a logic DLL it hot-reloads on Numpad 0 (see src/dev/).
option(KCD1_TPVCAMERA_DEV_BUILD "Build the two-DLL hot-reload dev configuration (thin loader ASI + logic DLL)" OFF)
set(KCD1_TPVCAMERA_GAME_DIR "" CACHE PATH
  "Game Bin\\Win64 directory to deploy into (used by the dev build for hot-reload staging)")

# --- Common Sources (mod logic; the entry point is added per target) ---
set(COMMON_SOURCES
  src/aob_resolver.cpp
  src/config.cpp
  src/game_interface.cpp
  src/game_state.cpp
  src/global_state.cpp
  src/offset_heal.cpp
  src/physics_raycast.cpp
  src/render_occlusion.cpp
  src/tpv_camera.cpp
  src/version.cpp
  src/hooks/camera_hook.cpp
  src/hooks/ui_menu_hooks.cpp
  src/hooks/ui_overlay_hooks.cpp
  src/hooks/interaction_hook.cpp
  src/hooks/player_onaction_hook.cpp
  src/overlay/overlay.cpp
  src/overlay/dx_overlay.cpp
  src/overlay/overlay_ui.cpp
  src/presets/camera_preset.cpp
  src/presets/camera_preset_fields.cpp
  src/presets/preset_runtime.cpp
  src/presets/preset_store.cpp
)

# Shared include paths, link libraries, and Release flags for any logic-bearing target.
# imgui_lib brings the ImGui + Win32/DX11 backend include paths transitively. d3d11/dxgi
# back the private WARP device; gdi32 backs the layered-window composite; winmm backs
# timeBeginPeriod (also pinned via #pragma comment).
function(configure_logic_target target)
  target_include_directories(${target} PRIVATE src)
  target_link_libraries(${target} PRIVATE
    DetourModKit imgui_lib nlohmann_json::nlohmann_json
    psapi user32 kernel32 d3d11 dxgi gdi32 winmm)
  target_compile_options(${target} PRIVATE
    /W4
    $<$<CONFIG:Release>:/O2>
    $<$<CONFIG:Release>:/Gy>
    $<$<CONFIG:Release>:/Gw>)
  target_link_options(${target} PRIVATE
    $<$<CONFIG:Release>:/OPT:REF>
    $<$<CONFIG:Release>:/OPT:ICF>)
endfunction()

if(NOT KCD1_TPVCAMERA_DEV_BUILD)
  # --- Production Build: a single ASI plugin ---
  add_library(${PROJECT_NAME}-ASI SHARED ${COMMON_SOURCES} src/dllmain.cpp)
  configure_logic_target(${PROJECT_NAME}-ASI)
  set_target_properties(${PROJECT_NAME}-ASI PROPERTIES
    OUTPUT_NAME "KCD1_TPVCamera-temp-asi"
    SUFFIX ".asi"
    PREFIX ""
  )

  # Normalize the artifact to the canonical name at the build-tree root.
  add_custom_command(TARGET ${PROJECT_NAME}-ASI POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
      $<TARGET_FILE:${PROJECT_NAME}-ASI>
      ${CMAKE_CURRENT_BINARY_DIR}/KCD1_TPVCamera.asi
    COMMENT "Renaming ASI output to final name"
  )

  if(KCD1_TPVCAMERA_GAME_DIR)
    add_custom_command(TARGET ${PROJECT_NAME}-ASI POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_BINARY_DIR}/KCD1_TPVCamera.asi
        "${KCD1_TPVCAMERA_GAME_DIR}/KCD1_TPVCamera.asi"
      COMMENT "Deploying ASI to ${KCD1_TPVCAMERA_GAME_DIR}"
    )
  endif()

  message(STATUS "KCD1_TPVCamera (${PROJECT_VERSION}) -- production ASI build -> KCD1_TPVCamera.asi")
else()
  # --- Dev Build: a thin loader ASI plus a logic DLL it hot-reloads in place ---

  # Thin loader ASI: loads the logic DLL and reloads it from staging/ on Numpad 0.
  # Links only Win32 (no DetourModKit) so a rebuild never writes a file it holds open.
  add_library(${PROJECT_NAME}-loader SHARED src/dev/loader.cpp)
  target_link_libraries(${PROJECT_NAME}-loader PRIVATE kernel32 user32)
  set_target_properties(${PROJECT_NAME}-loader PROPERTIES
    OUTPUT_NAME "KCD1_TPVCamera"
    SUFFIX ".asi"
    PREFIX ""
  )

  # Logic DLL: the mod logic plus the exported Init/Shutdown the loader drives.
  add_library(${PROJECT_NAME}-logic SHARED ${COMMON_SOURCES} src/dev/logic_exports.cpp)
  configure_logic_target(${PROJECT_NAME}-logic)
  target_compile_definitions(${PROJECT_NAME}-logic PRIVATE KCD1_TPVCAMERA_DEV_BUILD)
  set_target_properties(${PROJECT_NAME}-logic PROPERTIES
    OUTPUT_NAME "KCD1_TPVCamera_Logic"
    PREFIX ""
  )
  # /Zi emits a PDB; /DEBUG /INCREMENTAL:NO keep each rebuild a clean, reloadable DLL.
  target_compile_options(${PROJECT_NAME}-logic PRIVATE /Zi)
  target_link_options(${PROJECT_NAME}-logic PRIVATE /DEBUG /INCREMENTAL:NO)

  if(KCD1_TPVCAMERA_GAME_DIR)
    # Loader deploys straight into the game directory (changes rarely; land it closed).
    add_custom_command(TARGET ${PROJECT_NAME}-loader POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${PROJECT_NAME}-loader>
        "${KCD1_TPVCAMERA_GAME_DIR}/KCD1_TPVCamera.asi"
      COMMENT "Deploying loader ASI to ${KCD1_TPVCAMERA_GAME_DIR}"
    )

    # Logic DLL (+PDB) deploys into staging/; the loader promotes it on startup and on
    # each Numpad 0 reload, so the build never writes a file the running game holds open.
    add_custom_command(TARGET ${PROJECT_NAME}-logic POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E make_directory "${KCD1_TPVCAMERA_GAME_DIR}/staging"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${PROJECT_NAME}-logic>
        "${KCD1_TPVCAMERA_GAME_DIR}/staging/KCD1_TPVCamera_Logic.dll"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_PDB_FILE:${PROJECT_NAME}-logic>
        "${KCD1_TPVCAMERA_GAME_DIR}/staging/KCD1_TPVCamera_Logic.pdb"
      COMMENT "Deploying logic DLL+PDB to staging (loader promotes on startup / Numpad 0)"
    )
  else()
    message(STATUS "KCD1_TPVCAMERA_GAME_DIR not set: dev build will not auto-deploy. "
                   "Set -DKCD1_TPVCAMERA_GAME_DIR=<game Bin/Win64> to enable hot-reload deploy.")
  endif()

  message(STATUS "KCD1_TPVCamera (${PROJECT_VERSION}) -- DEV (two-DLL hot-reload) build")
  message(STATUS "    - ${PROJECT_NAME}-loader -> KCD1_TPVCamera.asi (thin loader)")
  message(STATUS "    - ${PROJECT_NAME}-logic  -> KCD1_TPVCamera_Logic.dll (mod logic)")
endif()
