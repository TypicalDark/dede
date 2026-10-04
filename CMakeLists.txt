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
  SRCS src/decompiler/linear_pseudocode.cpp src/decompiler/ghidra_adapter.cpp
  DEPS dede_disasm)
if(DEDE_WITH_GHIDRA)
  target_compile_definitions(dede_decompiler PUBLIC DEDE_WITH_GHIDRA)
endif()

dede_library(dede_introspection SRCS src/introspection/introspector.cpp DEPS dede_common)
if(DEDE_WITH_LIBVMI)
  target_compile_definitions(dede_introspection PUBLIC DEDE_WITH_LIBVMI)
endif()

dede_library(dede_session
  SRCS src/session/session_state.cpp src/session/analysis_session.cpp
  DEPS dede_core dede_replay dede_transparency dede_macro dede_decompiler dede_introspection)

dede_library(dede_script
  SRCS src/script/null_engine.cpp src/script/luau_engine.cpp
  DEPS dede_session)
if(DEDE_WITH_LUAU)
  target_compile_definitions(dede_script PUBLIC DEDE_WITH_LUAU)
endif()

dede_library(dede_shell SRCS src/shell/shell.cpp DEPS dede_session dede_script)

# --- executables -------------------------------------------------------------
add_executable(dede apps/dede_main.cpp)
target_link_libraries(dede PRIVATE dede_shell dede_session dede_script)

add_executable(dede-decrypt-demo apps/decrypt_demo.cpp)
target_link_libraries(dede-decrypt-demo PRIVATE dede_session)

# --- tests -------------------------------------------------------------------
if(DEDE_BUILD_TESTS)
  enable_testing()
  foreach(t test_memory test_disasm test_core test_timeline test_macro test_transparency test_integration test_antidetect test_qol)
    add_executable(${t} tests/${t}.cpp)
    target_include_directories(${t} PRIVATE ${CMAKE_SOURCE_DIR}/tests)
    target_link_libraries(${t} PRIVATE dede_session)
    add_test(NAME ${t} COMMAND ${t})
  endforeach()
endif()
