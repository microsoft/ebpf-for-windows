# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

find_program(git_path "git")
if(NOT git_path)
  set(git_commit_id "0")
else()
  execute_process(
    COMMAND "${git_path}" rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE "git_commit_id"
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

set(git_commit_id_file_name "git_commit_id.h")
set(git_commit_id_file_path "${CMAKE_CURRENT_BINARY_DIR}/${git_commit_id_file_name}")

add_custom_command(
  OUTPUT "${git_commit_id_file_path}"
  COMMAND "${CMAKE_COMMAND}" -E echo "#define GIT_COMMIT_ID \"${git_commit_id}\"" > "${git_commit_id_file_path}.temp"
  COMMAND "${CMAKE_COMMAND}" -E rename "${git_commit_id_file_path}.temp" "${git_commit_id_file_path}"
  VERBATIM
  COMMENT "ebpf-for-windows - Generating git_commit_id.h"
)

add_custom_target(git_commit_id_builder
  DEPENDS "${git_commit_id_file_path}"
)

add_library("git_commit_id" INTERFACE)
add_dependencies("git_commit_id"
  "git_commit_id_builder"
)

target_include_directories("git_commit_id" INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)
