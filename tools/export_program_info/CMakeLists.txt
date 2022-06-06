# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("encode_program_info"
  encode_program_info.cpp
)

target_include_directories("encode_program_info" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
)

target_link_libraries("encode_program_info" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "execution_context_user"
  "platform_user"
  "api_common_headers"
  "external::ebpfverifier"
  "external::boost"
  "Kernel32.lib"
  "Mincore.lib"
)

target_compile_definitions("encode_program_info" PRIVATE
  _CONSOLE
)

# Use encode_program_info to generate the headers
set(encode_program_info_log "${CMAKE_CURRENT_BINARY_DIR}/log.txt")

add_custom_command(
  OUTPUT "${encode_program_info_log}"
  COMMAND "$<TARGET_FILE:encode_program_info>" > "${encode_program_info_log}"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
  COMMENT "ebpf-for-windows - Running: encode_program_info"
  VERBATIM
)

add_custom_target(encode_program_info_runner
  DEPENDS "${encode_program_info_log}"
)

# Create a target that will export the include path for the generated
# headers when linked against
add_library("encode_program_info_headers" INTERFACE)
add_dependencies("encode_program_info_headers"
  "encode_program_info_runner"
)

target_include_directories("encode_program_info_headers" INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)
