# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20)
project(dede LANGUAGES CXX
        DESCRIPTION "Transparent time-travel analysis shell")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --- Options for the copyleft / heavy optional backends ----------------------
# Each is OFF by default so the tree builds with only Capstone. See LICENSING.md
# for why the GPL backends (Unicorn/Keystone) belong in the separate emu-host
# process rather than linked into the permissively-licensed main binary.
option(DEDE_WITH_UNICORN  "Build the Unicorn execution backend (GPLv2 — emu-host only)" OFF)
option(DEDE_WITH_ASMJIT   "Use asmjit for assembly instead of the in-tree encoder (Zlib)" OFF)
option(DEDE_WITH_GHIDRA   "Link ghidra-native for decompilation (Apache-2.0)" OFF)
option(DEDE_WITH_LUAU     "Embed the Luau scripting engine (MIT)" OFF)
option(DEDE_WITH_LIBVMI   "Link LibVMI for introspection (LGPLv3 — dynamic)" OFF)
option(DEDE_BUILD_TESTS   "Build the test suite" ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  add_compile_options(-Wall -Wextra)
endif()

# --- Capstone (required, BSD) ------------------------------------------------
find_package(PkgConfig)
if(PkgConfig_FOUND)
  pkg_check_modules(CAPSTONE capstone)
endif()
if(NOT CAPSTONE_FOUND)
  find_path(CAPSTONE_INCLUDE_DIRS capstone/capstone.h)
  find_library(CAPSTONE_LIBRARIES NAMES capstone)
endif()
if(NOT CAPSTONE_LIBRARIES)
  message(FATAL_ERROR "Capstone not found. Install libcapstone-dev (or via vcpkg/conan).")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

# Helper: one static library per subsystem, so the dependency edges stay honest.
function(dede_library name)
  cmake_parse_arguments(A "" "" "SRCS;DEPS" ${ARGN})
  add_library(${name} STATIC ${A_SRCS})
  target_include_directories(${name} PUBLIC ${CMAKE_SOURCE_DIR}/include)
  if(A_DEPS)
    target_link_libraries(${name} PUBLIC ${A_DEPS})
  endif()
endfunction()

dede_library(dede_common SRCS src/common/types.cpp src/common/memory.cpp)

dede_library(dede_disasm
  SRCS src/disasm/capstone_disassembler.cpp src/disasm/assembler.cpp
  DEPS dede_common)
target_include_directories(dede_disasm PUBLIC ${CAPSTONE_INCLUDE_DIRS})
target_link_libraries(dede_disasm PUBLIC ${CAPSTONE_LIBRARIES})

dede_library(dede_core
  SRCS src/core/event.cpp src/core/memory_proxy.cpp
       src/core/execution_core.cpp src/core/builtin_backend.cpp
  DEPS dede_disasm dede_common)

dede_library(dede_replay SRCS src/replay/timeline.cpp DEPS dede_core)

dede_library(dede_transparency SRCS src/transparency/chain.cpp DEPS dede_core)

dede_library(dede_macro
  SRCS src/macro/condition.cpp src/macro/macro_engine.cpp
  DEPS dede_core)

dede_library(dede_decompiler
  SRCS src/decompiler/linear_pseudocode.cpp src/decompiler/ghidra_adapter.cpp src/decompiler/native.cpp
  DEPS dede_ir dede_types)
if(DEDE_WITH_GHIDRA)
  target_compile_definitions(dede_decompiler PUBLIC DEDE_WITH_GHIDRA)
endif()

dede_library(dede_analysis SRCS src/analysis/cfg.cpp src/analysis/arch_view.cpp src/analysis/scan.cpp DEPS dede_disasm)

# Decompiler IR: lifter + reference evaluator (see docs/DECOMPILER.md, M1+).
dede_library(dede_ir SRCS src/ir/ir.cpp src/ir/lifter.cpp src/ir/eval.cpp DEPS dede_analysis)

# Constraint-based type inference (docs/DECOMPILER.md, M6).
dede_library(dede_types SRCS src/types/infer.cpp DEPS dede_analysis)

dede_library(dede_samples SRCS src/samples/tiers.cpp DEPS dede_common)

dede_library(dede_introspection SRCS src/introspection/introspector.cpp DEPS dede_common)

dede_library(dede_loader SRCS src/loader/loader.cpp DEPS dede_common)
if(DEDE_WITH_LIBVMI)
  target_compile_definitions(dede_introspection PUBLIC DEDE_WITH_LIBVMI)
endif()

dede_library(dede_session
  SRCS src/session/session_state.cpp src/session/analysis_session.cpp src/session/capture.cpp
  DEPS dede_core dede_replay dede_transparency dede_macro dede_decompiler dede_introspection dede_analysis dede_loader)

dede_library(dede_script
  SRCS src/script/null_engine.cpp src/script/luau_engine.cpp
  DEPS dede_session)
if(DEDE_WITH_LUAU)
  target_compile_definitions(dede_script PUBLIC DEDE_WITH_LUAU)
endif()

dede_library(dede_shell SRCS src/shell/shell.cpp DEPS dede_session dede_script dede_analysis dede_loader)

# --- modular UI kernel (headless, backend-agnostic) --------------------------
# git-tool-style architecture: a contribution Registry + reactive Context +
# CommandBus + IPainter, with feature modules that register manifests and two
# painter backends (SVG for headless render/tests, ImGui for the desktop GUI).
dede_library(dede_ui
  SRCS src/ui/context.cpp src/ui/registry.cpp src/ui/commands.cpp
       src/ui/shell.cpp src/ui/backends/svg_painter.cpp
  DEPS dede_common)

# Feature modules (need the engine): each registers a Manifest into the Registry.
dede_library(dede_ui_modules
  SRCS src/ui/modules/modules.cpp src/ui/modules/exec.cpp src/ui/modules/disasm.cpp
       src/ui/modules/cfg.cpp src/ui/modules/decompiler.cpp src/ui/modules/timeline.cpp
       src/ui/modules/console.cpp src/ui/modules/inspector.cpp
  DEPS dede_ui dede_session dede_analysis)
target_include_directories(dede_ui_modules PRIVATE ${CMAKE_SOURCE_DIR})

# --- Vulkan + Dear ImGui GUI (optional) --------------------------------------
option(DEDE_WITH_GUI "Build the Vulkan/ImGui desktop GUI (needs libvulkan-dev, libglfw3-dev, and third_party/imgui)" OFF)
if(DEDE_WITH_GUI)
  set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/third_party/imgui)
  if(NOT EXISTS ${IMGUI_DIR}/imgui.cpp)
    message(FATAL_ERROR "DEDE_WITH_GUI=ON but ${IMGUI_DIR} is missing. Run ./build.sh --with-gui (it fetches Dear ImGui) or clone it there.")
  endif()
  find_package(Vulkan REQUIRED)
  if(PkgConfig_FOUND)
    pkg_check_modules(GLFW3 REQUIRED glfw3)
  endif()

  add_library(dede_imgui STATIC
    ${IMGUI_DIR}/imgui.cpp ${IMGUI_DIR}/imgui_draw.cpp ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp ${IMGUI_DIR}/backends/imgui_impl_vulkan.cpp)
  target_include_directories(dede_imgui PUBLIC ${IMGUI_DIR} ${IMGUI_DIR}/backends ${GLFW3_INCLUDE_DIRS})
  target_link_libraries(dede_imgui PUBLIC Vulkan::Vulkan ${GLFW3_LIBRARIES})
  # Vendored third-party code is not held to our -Wall -Wextra -Werror.
  target_compile_options(dede_imgui PRIVATE -w)

  # The GUI is now a thin host over the modular UI kernel + feature modules; the
  # ImGui painter is the only GUI-specific rendering code.
  dede_library(dede_gui
    SRCS src/gui/shell_app.cpp src/ui/backends/imgui_painter.cpp
    DEPS dede_ui dede_ui_modules dede_session dede_script dede_imgui)

  add_executable(dede-gui apps/dede_gui.cpp)
  target_link_libraries(dede-gui PRIVATE dede_gui dede_imgui dede_ui dede_ui_modules
                                         dede_session dede_script Vulkan::Vulkan ${GLFW3_LIBRARIES})
endif()

# --- executables -------------------------------------------------------------
add_executable(dede apps/dede_main.cpp)
target_link_libraries(dede PRIVATE dede_shell dede_session dede_script)

add_executable(dede-decrypt-demo apps/decrypt_demo.cpp)
target_link_libraries(dede-decrypt-demo PRIVATE dede_session)

add_executable(dede-bench apps/bench.cpp)
target_link_libraries(dede-bench PRIVATE dede_session)

add_executable(dede-eval apps/eval.cpp)
target_link_libraries(dede-eval PRIVATE dede_session dede_analysis dede_loader)

add_executable(dede-forge apps/forge.cpp)
target_link_libraries(dede-forge PRIVATE dede_samples)

# Renders the GUI workspace to SVG from live engine data (the GUI itself needs a
# display/GPU; this gives headless, honest "screenshots").
add_executable(dede-shot apps/shot.cpp)
target_link_libraries(dede-shot PRIVATE dede_ui dede_ui_modules dede_session dede_analysis dede_samples)

# --- tests -------------------------------------------------------------------
if(DEDE_BUILD_TESTS)
  enable_testing()
  foreach(t test_memory test_disasm test_core test_timeline test_macro test_transparency test_integration test_antidetect test_qol test_cfg test_regress test_capture test_tiers test_loader test_ui test_ir test_decompiler test_types)
    add_executable(${t} tests/${t}.cpp)
    target_include_directories(${t} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
    target_link_libraries(${t} PRIVATE dede_session)
    add_test(NAME ${t} COMMAND ${t})
  endforeach()
  # Guard the effectiveness harness and its hot-path checks: it must run all
  # dynamic engine checks without crashing and exit 0.
  target_link_libraries(test_tiers PRIVATE dede_samples)
  target_link_libraries(test_ui PRIVATE dede_ui)
  target_link_libraries(test_ir PRIVATE dede_ir)
  target_link_libraries(test_decompiler PRIVATE dede_samples)
  target_link_libraries(test_types PRIVATE dede_types)
  add_test(NAME effectiveness COMMAND dede-eval ${CMAKE_BINARY_DIR}/effectiveness-report.md)
endif()
