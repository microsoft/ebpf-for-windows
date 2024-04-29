# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set (output_dir PUBLIC ${CMAKE_BINARY_DIR}/x64/$<$<CONFIG:Debug>:Debug>$<$<CONFIG:Release>:Release>)

# Some targets do not play well with the default definitions (such
# as bpftool and /DWIN32). Remove them from the variables for now
set(settings_variable_list
  "CMAKE_C_FLAGS_RELEASE"
  "CMAKE_C_FLAGS_DEBUG"
  "CMAKE_C_FLAGS_RELWITHDEBINFO"

  "CMAKE_CXX_FLAGS_RELEASE"
  "CMAKE_CXX_FLAGS_DEBUG"
  "CMAKE_CXX_FLAGS_RELWITHDEBINFO"

  "CMAKE_C_FLAGS"
  "CMAKE_CXX_FLAGS"
)

foreach(settings_variable ${settings_variable_list})
  string(REPLACE "/D_WINDOWS" "" "${settings_variable}" ${${settings_variable}})
  string(REPLACE "/DWIN32" "" "${settings_variable}" ${${settings_variable}})
endforeach()

add_library("ebpf_for_windows_base_definitions" INTERFACE)
target_compile_definitions("ebpf_for_windows_base_definitions" INTERFACE
  $<$<CONFIG:Debug>:_DEBUG>
  $<$<CONFIG:FuzzerDebug>:_DEBUG>
  $<$<CONFIG:NativeOnlyDebug>:_DEBUG>
  $<$<CONFIG:NativeOnlyRelease>:NDEBUG>
  $<$<CONFIG:Release>:NDEBUG>
  $<$<CONFIG:RelWithDebInfo>:NDEBUG>
)

add_library("ebpf_for_windows_common_settings" INTERFACE)
target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
  UNICODE
  _UNICODE
)

target_link_libraries("ebpf_for_windows_common_settings" INTERFACE
  "ebpf_for_windows_base_definitions"
)


target_link_options("ebpf_for_windows_common_settings" INTERFACE
  /DEBUG:Full
)

if(EBPFFORWINDOWS_DISABLE_JIT)
  target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
    CONFIG_BPF_JIT_DISABLED=1
  )
endif()

if(EBPFFORWINDOWS_DISABLE_INTERPRETER)
  target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
    CONFIG_BPF_INTERPRETER_DISABLED=1
  )
endif()

add_library("ebpf_for_windows_cpp_settings" INTERFACE)
target_link_libraries("ebpf_for_windows_cpp_settings" INTERFACE
  "ebpf_for_windows_common_settings"
)

set(CMAKE_CXX_STANDARD 20)

# Rationalize TARGET_PLATFORM
if("${CMAKE_GENERATOR_PLATFORM}" STREQUAL "arm64" OR "${TARGET_PLATFORM}" STREQUAL "arm64")
    set(TARGET_PLATFORM "arm64")
elseif("${CMAKE_GENERATOR_PLATFORM}" MATCHES "x64|amd64|" OR "${TARGET_PLATFORM}" MATCHES "x64|amd64|")
    set(TARGET_PLATFORM "x64")
else()
    message(FATAL_ERROR "Unsupported platform: ${CMAKE_GENERATOR_PLATFORM}")
endif()


# Configure output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/${TARGET_PLATFORM})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/Debug)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/Release)
