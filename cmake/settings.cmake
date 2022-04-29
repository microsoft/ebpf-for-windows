# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

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


if(EBPFFORWINDOWS_ENABLE_DISABLE_EBPF_INTERPRETER)
  target_compile_definitions("ebpf_for_windows_common_settings" INTERFACE
    CONFIG_BPF_JIT_ALWAYS_ON=1
  )
endif()

add_library("ebpf_for_windows_cpp_settings" INTERFACE)
target_link_libraries("ebpf_for_windows_cpp_settings" INTERFACE
  "ebpf_for_windows_common_settings"
)

set(CMAKE_CXX_STANDARD 20)
