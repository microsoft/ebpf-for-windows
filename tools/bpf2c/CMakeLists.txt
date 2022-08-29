# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("bpf2c"
  ../../include/bpf2c.h
  ../../external/ebpf-verifier/src/btf_parser.h

  bpf_code_generator.h
  bpf_code_generator.cpp

  bpf2c.cpp
)

target_include_directories("bpf2c" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
)

target_link_libraries("bpf2c" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "elf_spec"
  "EbpfApi"
  "external::ebpfverifier"
  "export_program_info_runner"
)

target_compile_definitions("bpf2c" PRIVATE
  $<$<CONFIG:DEBUG>:ENABLE_SKIP_VERIFY>
  _CONSOLE
)

codeSign("bpf2c")

function(generateTemplate source_file_name)
  find_program(powershell_path "powershell" REQUIRED)

  set(template_name "${source_file_name}.template")
  set(template_path "${CMAKE_CURRENT_BINARY_DIR}/${template_name}")

  add_custom_command(
    OUTPUT
      "${template_path}"

    COMMAND
      "${powershell_path}" -NonInteractive -ExecutionPolicy Unrestricted "${CMAKE_SOURCE_DIR}/scripts/escape_text.ps1" "${CMAKE_CURRENT_SOURCE_DIR}/${source_file_name}.c" "${template_path}"

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

function(processFile source_file_name config_file)
  find_program(powershell_path "powershell" REQUIRED)

  set(input_file_name "${CMAKE_CURRENT_LIST_DIR}/${source_file_name}.ps1.template")
  set(output_file_name "${output_dir}/${source_file_name}.ps1")
  set(config_file_name "${CMAKE_CURRENT_LIST_DIR}/${config_file}")

  add_custom_command(
    OUTPUT
      "${output_file_name}"

    COMMAND
      "${powershell_path}" powershell -NonInteractive -ExecutionPolicy Unrestricted "${CMAKE_SOURCE_DIR}/scripts/Process-File.ps1" -InputFile "${input_file_name}" -OutputFile "${output_file_name}" -ConfigFile "${config_file_name}"

    VERBATIM

    COMMENT
      "ebpf-for-windows - Generating: ${source_file_name}.ps1"

    WORKING_DIRECTORY
      "${CMAKE_CURRENT_LIST_DIR}"

  )

  add_custom_target("${source_file_name}_builder"
    DEPENDS "${output_file_name}"
  )

  add_library("${source_file_name}" INTERFACE)
  target_include_directories("${source_file_name}" INTERFACE
    "${CMAKE_CURRENT_BINARY_DIR}"
  )

  add_dependencies("${source_file_name}"
    "${source_file_name}_builder"
  )
endfunction()

generateTemplate("bpf2c_driver")
target_link_libraries("bpf2c" PRIVATE
  "bpf2c_driver"
)

generateTemplate("bpf2c_dll")
target_link_libraries("bpf2c" PRIVATE
  "bpf2c_dll"
)

processFile("Convert-BpfToNative" "replacements.json")
target_link_libraries("bpf2c" PRIVATE
  "Convert-BpfToNative"
)

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "bpf2c" "Convert-BpfToNative"
    DESTINATION "."
  )
endif()
