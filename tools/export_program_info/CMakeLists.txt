# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("export_program_info"
  export_program_info.cpp
  main.cpp
  ${CMAKE_SOURCE_DIR}/libs/api_common/registry_helper.cpp
  ${CMAKE_SOURCE_DIR}/libs/api_common/store_helper_internal.cpp
  ${CMAKE_SOURCE_DIR}/libs/api_common/utilities.cpp
)

target_include_directories("export_program_info" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/include/user"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
)

target_link_libraries("export_program_info" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "execution_context_user"
  "platform_user"
  "api_common_headers"
  "external::ebpfverifier"
  "external::boost"
  "usersim"
  "Kernel32.lib"
  "Mincore.lib"
)

target_compile_definitions("export_program_info" PRIVATE
  _CONSOLE
)

# Use export_program_info to populate the ebpf store.
set(export_program_info_log "${CMAKE_CURRENT_BINARY_DIR}/log.txt")

add_custom_command(TARGET "export_program_info"
POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
          ${CMAKE_BINARY_DIR}/x64/bin/$<CONFIG>/usersim.dll
          ${CMAKE_BINARY_DIR}/x64/$<CONFIG>
  COMMAND "$<TARGET_FILE:export_program_info>" --clear >> "${export_program_info_log}"
  COMMAND "$<TARGET_FILE:export_program_info>" >> "${export_program_info_log}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
  COMMENT "ebpf-for-windows - Running: export_program_info"
  VERBATIM
)

# Create a target that will export the eBPF store configuration when linked against.
add_library("export_program_info_runner" INTERFACE)
add_dependencies("export_program_info_runner"
  "export_program_info"
)
