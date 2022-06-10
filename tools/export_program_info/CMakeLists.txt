# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("export_program_info"
  export_program_info.cpp
)

target_include_directories("export_program_info" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
)

target_link_libraries("export_program_info" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "execution_context_user"
  "platform_user"
  "api_common_headers"
  "external::ebpfverifier"
  "external::boost"
  "Kernel32.lib"
  "Mincore.lib"
)

target_compile_definitions("export_program_info" PRIVATE
  _CONSOLE
)

# Use export_program_info to populate the ebpf store.
set(export_program_info_log "${CMAKE_CURRENT_BINARY_DIR}/log.txt")

add_custom_command(
  OUTPUT "${export_program_info_log}"
  COMMAND "$<TARGET_FILE:export_program_info>" > "${export_program_info_log}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
  COMMENT "ebpf-for-windows - Running: export_program_info"
  VERBATIM
)

add_custom_target(export_program_info_runner
  DEPENDS "${export_program_info_log}"
)

# Create a target that will export the include path for the generated
# headers when linked against
add_library("export_program_info_headers" INTERFACE)
add_dependencies("export_program_info_headers"
  "export_program_info_runner"
)

target_include_directories("export_program_info_headers" INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)
