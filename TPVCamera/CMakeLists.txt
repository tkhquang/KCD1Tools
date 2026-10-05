cmake_minimum_required(VERSION 3.28)

# Derive the project version from src/version.hpp, the single source of truth
# (scripts/version_updater.py bumps only that header). PROJECT_VERSION currently feeds only the
# configure-time status banner; deriving it here keeps the two from drifting after a version bump.
set(_version_header "${CMAKE_CURRENT_SOURCE_DIR}/src/version.hpp")
file(STRINGS "${_version_header}" _ver_major REGEX "^#define +VERSION_MAJOR +[0-9]+")
file(STRINGS "${_version_header}" _ver_minor REGEX "^#define +VERSION_MINOR +[0-9]+")
file(STRINGS "${_version_header}" _ver_patch REGEX "^#define +VERSION_PATCH +[0-9]+")
string(REGEX REPLACE ".*VERSION_MAJOR +([0-9]+).*" "\\1" _ver_major "${_ver_major}")
string(REGEX REPLACE ".*VERSION_MINOR +([0-9]+).*" "\\1" _ver_minor "${_ver_minor}")
string(REGEX REPLACE ".*VERSION_PATCH +([0-9]+).*" "\\1" _ver_patch "${_ver_patch}")

project(KCD1_TPVCamera VERSION ${_ver_major}.${_ver_minor}.${_ver_patch} LANGUAGES CXX)

# Re-run configure when the version header changes so PROJECT_VERSION stays current.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${_version_header}")

# The one name every artifact derives from: the ASI, the dev loader and logic DLL, the staged
# generation copies, and the logs. The dev pair also receives it as a compile definition.
set(TPVCAMERA_MOD_NAME "KCD1_TPVCamera")

# --- Build Options ---
# TPVCAMERA_DEV_BUILD OFF (default): a single production ASI built from the logic
# plus dllmain.cpp. ON: the DetourModKit staged-reload pair (see src/dev/): a resident
# loader ASI plus a logic DLL it replaces on Numpad 0 by loading a uniquely named copy
# of each rebuild.
option(TPVCAMERA_DEV_BUILD "Build the two-DLL hot-reload dev configuration (resident loader ASI + logic DLL)" OFF)
set(TPVCAMERA_GAME_DIR "" CACHE PATH
  "Game Bin\\Win64 directory to deploy into (the dev build deploys the loader and the logic DLL there)")

# --- Standard and Compiler Options ---
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# This project ships as an MSVC build only.
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
    _XM_SSE_INTRINSICS_ # Required for DirectXMath inline functions
  )
endif()

# --- DetourModKit Dependency (git submodule) ---
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/DetourModKit/CMakeLists.txt")
  message(FATAL_ERROR "DetourModKit not found at 'external/DetourModKit'. "
    "Initialize submodules: 'git submodule update --init --recursive'")
endif()

# Guard against double-definition if a parent project already pulled DetourModKit in.
if(NOT TARGET DetourModKit)
  # Zydis and Zycore declare an older minimum. Limit the policy override to the dependency tree.
  block(SCOPE_FOR VARIABLES)
    if(NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM OR CMAKE_POLICY_VERSION_MINIMUM VERSION_LESS 3.10)
      set(CMAKE_POLICY_VERSION_MINIMUM 3.10)
    endif()
    add_subdirectory(external/DetourModKit)

    # /W0 maps to the Visual Studio warning-level property. /w remains an extra flag and conflicts with /W1.
    foreach(_dependency_target safetyhook Zydis Zycore)
      if(TARGET ${_dependency_target})
        get_target_property(_dependency_alias ${_dependency_target} ALIASED_TARGET)
        get_target_property(_dependency_options ${_dependency_target} COMPILE_OPTIONS)
        if(NOT _dependency_alias AND _dependency_options)
          list(TRANSFORM _dependency_options REPLACE ":/w>$" ":/W0>")
          set_property(TARGET ${_dependency_target} PROPERTY COMPILE_OPTIONS "${_dependency_options}")
        endif()
      endif()
    endforeach()
  endblock()
endif()
if(NOT TARGET DetourModKit)
  message(FATAL_ERROR "DetourModKit target not created by subdirectory")
endif()

# --- Dear ImGui (compiled from source, linked directly - no ReShade) ---
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

# --- Source Files ---
set(COMMON_SOURCES
  src/aob_resolver.cpp
  src/config.cpp
  src/detour_gate.cpp
  src/game_interface.cpp
  src/game_state.cpp
  src/global_state.cpp
  src/offset_heal.cpp
  src/physics_raycast.cpp
  src/render_occlusion.cpp
  src/rtti_types.cpp
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

# Applies the settings shared by the production ASI and the dev logic DLL: include
# paths, link libraries, and the Release speed/opt flags. /O2 favors speed: the
# overlay renders through a software WARP device with a per-pixel premultiply loop
# every frame, so the few KB /O1 would save are not worth deoptimizing that path on
# an .asi where image size is not a real constraint. /Gy + /Gw with /OPT:REF +
# /OPT:ICF still let the linker drop and fold unused functions and data.
function(configure_logic_target target)
  target_compile_options(${target} PRIVATE /W4)
  target_include_directories(${target} PRIVATE src)
  # imgui_lib brings the ImGui + Win32/DX11 backend include paths transitively.
  # d3d11/dxgi back the private WARP device; gdi32 backs the layered-window
  # composite; winmm backs timeBeginPeriod (also pinned via #pragma comment).
  target_link_libraries(${target} PRIVATE
    DetourModKit imgui_lib nlohmann_json::nlohmann_json
    user32 kernel32 d3d11 dxgi gdi32 winmm)
  target_compile_options(${target} PRIVATE $<$<CONFIG:Release>:/O2 /Gy /Gw>)
  target_link_options(${target} PRIVATE $<$<CONFIG:Release>:/OPT:REF /OPT:ICF>)
endfunction()

if(NOT TPVCAMERA_DEV_BUILD)
  # --- Production Build: a single monolithic ASI ---
  add_library(${PROJECT_NAME}-ASI SHARED ${COMMON_SOURCES} src/dllmain.cpp)
  configure_logic_target(${PROJECT_NAME}-ASI)
  set_target_properties(${PROJECT_NAME}-ASI PROPERTIES
    OUTPUT_NAME "${TPVCAMERA_MOD_NAME}-temp-asi"
    SUFFIX ".asi"
    PREFIX ""
  )

  # Link-time optimization on Release (whole-program inlining across the mod).
  include(CheckIPOSupported)
  check_ipo_supported(RESULT _ipo_supported LANGUAGES CXX OUTPUT _ipo_error)
  if(_ipo_supported)
    set_target_properties(${PROJECT_NAME}-ASI PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
    message(STATUS "LTO enabled for ${PROJECT_NAME}-ASI Release builds")
  else()
    message(STATUS "LTO not supported for ${PROJECT_NAME}-ASI: ${_ipo_error}")
  endif()

  # Normalize the artifact to the canonical name at the build-tree root so it is
  # found at the same path under both the Ninja and Visual Studio generators
  # (the release workflow copies build/KCD1_TPVCamera.asi).
  add_custom_command(TARGET ${PROJECT_NAME}-ASI POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
      $<TARGET_FILE:${PROJECT_NAME}-ASI>
      ${CMAKE_CURRENT_BINARY_DIR}/${TPVCAMERA_MOD_NAME}.asi
    COMMENT "Renaming ASI output to final name"
  )

  # Optional deploy of the production ASI to a configured game directory.
  if(TPVCAMERA_GAME_DIR)
    add_custom_command(TARGET ${PROJECT_NAME}-ASI POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_BINARY_DIR}/${TPVCAMERA_MOD_NAME}.asi
        "${TPVCAMERA_GAME_DIR}/${TPVCAMERA_MOD_NAME}.asi"
      COMMENT "Deploying ASI to ${TPVCAMERA_GAME_DIR}"
    )
  endif()

  message(STATUS "${TPVCAMERA_MOD_NAME} (${PROJECT_VERSION}) - production ASI build -> ${TPVCAMERA_MOD_NAME}.asi")
else()
  # --- Dev Build: DetourModKit's staged-reload pair (docs/guides/hot-reload in DetourModKit) ---

  # Resident loader ASI: owns the reload control thread and the process-lifetime wheel host, and maps
  # each logic generation from a uniquely named copy. It links the resident wheel host ONLY, never the
  # full archive: hosting wheel capture in a module that is never unloaded is what lets the logic DLL
  # keep mouse-wheel bindings and still unmap, because the permanent wheel keepalive is booked here.
  add_library(${PROJECT_NAME}-loader SHARED src/dev/mod_loader.cpp)
  target_compile_options(${PROJECT_NAME}-loader PRIVATE /W4)
  target_link_libraries(${PROJECT_NAME}-loader PRIVATE DetourModKit::WheelHost kernel32 user32)
  target_include_directories(${PROJECT_NAME}-loader PRIVATE src)
  target_compile_definitions(${PROJECT_NAME}-loader PRIVATE TPVCAMERA_MOD_NAME="${TPVCAMERA_MOD_NAME}")

  # Guard the property above. Linking the full archive here would give the loader its own DetourModKit
  # instance, which is exactly the arrangement the library's unload proofs exclude.
  get_target_property(_tpv_loader_links ${PROJECT_NAME}-loader LINK_LIBRARIES)
  if(NOT _tpv_loader_links MATCHES "DetourModKit::WheelHost")
    message(FATAL_ERROR "${PROJECT_NAME}-loader must link DetourModKit::WheelHost.")
  endif()
  if(_tpv_loader_links MATCHES "DetourModKit::DetourModKit" OR _tpv_loader_links MATCHES "(^|;)DetourModKit(;|$)")
    message(FATAL_ERROR "${PROJECT_NAME}-loader must not link the full DetourModKit archive.")
  endif()
  set_target_properties(${PROJECT_NAME}-loader PROPERTIES
    OUTPUT_NAME "${TPVCAMERA_MOD_NAME}"
    SUFFIX ".asi"
    PREFIX ""
  )

  # Logic DLL: the mod logic plus the Init / Shutdown / Revision exports the loader drives. It links the
  # full archive exactly like the production ASI, so every reload exercises the production teardown.
  add_library(${PROJECT_NAME}-logic SHARED ${COMMON_SOURCES} src/dev/mod_logic.cpp)
  configure_logic_target(${PROJECT_NAME}-logic)
  target_compile_definitions(${PROJECT_NAME}-logic PRIVATE
    TPVCAMERA_DEV_BUILD
    TPVCAMERA_MOD_NAME="${TPVCAMERA_MOD_NAME}")
  set_target_properties(${PROJECT_NAME}-logic PROPERTIES
    OUTPUT_NAME "${TPVCAMERA_MOD_NAME}.logic"
    PREFIX ""
  )
  # /Zi emits a PDB; /DEBUG /INCREMENTAL:NO keep each rebuild a clean, reloadable DLL.
  target_compile_options(${PROJECT_NAME}-logic PRIVATE /Zi)
  target_link_options(${PROJECT_NAME}-logic PRIVATE /DEBUG /INCREMENTAL:NO)

  if(TPVCAMERA_GAME_DIR)
    # The loader changes rarely and stays mapped for the game session, so it is expected to land while the
    # game is closed.
    add_custom_command(TARGET ${PROJECT_NAME}-loader POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${PROJECT_NAME}-loader>
        "${TPVCAMERA_GAME_DIR}/${TPVCAMERA_MOD_NAME}.asi"
      COMMENT "Deploying loader ASI to ${TPVCAMERA_GAME_DIR}"
    )

    # The logic DLL (+PDB) deploys straight beside the loader. The loader never maps this file: each
    # generation loads a uniquely named copy (<mod>.genNNNN.logic.dll), so a rebuild can replace it while
    # the game runs.
    add_custom_command(TARGET ${PROJECT_NAME}-logic POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${PROJECT_NAME}-logic>
        "${TPVCAMERA_GAME_DIR}/${TPVCAMERA_MOD_NAME}.logic.dll"
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_PDB_FILE:${PROJECT_NAME}-logic>
        "${TPVCAMERA_GAME_DIR}/${TPVCAMERA_MOD_NAME}.logic.pdb"
      COMMENT "Deploying logic DLL+PDB beside the loader (Numpad 0 stages and loads a fresh copy)"
    )
  else()
    message(STATUS "TPVCAMERA_GAME_DIR not set: dev build will not auto-deploy. "
                   "Set -DTPVCAMERA_GAME_DIR=<game Bin/Win64> to enable hot-reload deploy.")
  endif()

  message(STATUS "${TPVCAMERA_MOD_NAME} (${PROJECT_VERSION}) - DEV (staged-reload pair) build")
  message(STATUS "    - ${PROJECT_NAME}-loader -> ${TPVCAMERA_MOD_NAME}.asi (resident loader)")
  message(STATUS "    - ${PROJECT_NAME}-logic  -> ${TPVCAMERA_MOD_NAME}.logic.dll (mod logic)")
endif()
