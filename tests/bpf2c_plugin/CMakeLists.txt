# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("bpf2c_plugin"
  bpf2c_plugin.cpp
  ../../tools/bpf2c/bpf_code_generator.h
  ../../tools/bpf2c/bpf_code_generator.cpp
)

target_include_directories("bpf2c_plugin" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/resource"
  "${CMAKE_SOURCE_DIR}/tools/bpf2c"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/external/libbtf"
)

target_link_libraries("bpf2c_plugin" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "common_tests"
  "EbpfApi"
  "rpc_interface"
  "test_util"
  "Catch2::Catch2WithMain"
  "ws2_32.lib"
)

target_compile_definitions("bpf2c_plugin" PRIVATE
  _WINSOCK_DEPRECATED_NO_WARNINGS
  _CONSOLE
)

function(generateTemplate source_file_name)
  find_program(powershell_path "powershell" REQUIRED)

  set(template_name "${source_file_name}.template")
  set(template_path "${CMAKE_CURRENT_BINARY_DIR}/${template_name}")

  add_custom_command(
    OUTPUT
      "${template_path}"

    COMMAND
      "${powershell_path}" -NonInteractive -ExecutionPolicy Unrestricted "${CMAKE_SOURCE_DIR}/scripts/escape_text.ps1" "${CMAKE_CURRENT_SOURCE_DIR}/${source_file_name}.cpp" "${template_path}"

    VERBATIM

    COMMENT
      "ebpf-for-windows - Generating: ${source_file_name}"

    WORKING_DIRECTORY
      "${CMAKE_CURRENT_BINARY_DIR}"
  )

  add_custom_target("${source_file_name}_builder"
    DEPENDS "${template_path}"
  )

  add_library("${source_file_name}" INTERFACE)
  target_include_directories("${source_file_name}" INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}"
  )

  add_dependencies("${source_file_name}"
    "${source_file_name}_builder"
  )
endfunction()

generateTemplate("bpf2c_test")
target_link_libraries("bpf2c_plugin" PRIVATE
  "bpf2c_test"
)
