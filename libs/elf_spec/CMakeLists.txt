# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(elf_spec_file Elf.3d)

set(elf_spec_generated_c_files
    "${CMAKE_CURRENT_BINARY_DIR}/Elf.c"
    "${CMAKE_CURRENT_BINARY_DIR}/ElfWrapper.c"
)

set(elf_spec_generated_h_files
    "${CMAKE_CURRENT_BINARY_DIR}/Elf.h"
    "${CMAKE_CURRENT_BINARY_DIR}/ElfWrapper.h"
    "${CMAKE_CURRENT_BINARY_DIR}/EverParse.h"
    "${CMAKE_CURRENT_BINARY_DIR}/EverParseEndianness.h"
)

set(elf_spec_generated_files
    ${elf_spec_generated_c_files}
    ${elf_spec_generated_h_files}
)

find_program(NUGET nuget)

if(NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
else()
    exec_program(${NUGET} ARGS install "EverParse" -Version 2022.6.13 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
endif()

set(EverParse_DIR ${CMAKE_BINARY_DIR}/packages/everparse/lib/native/win-x86_64)

set_source_files_properties(${elf_spec_generated_c_files} PROPERTIES GENERATED TRUE)

add_custom_command(
    OUTPUT ${elf_spec_generated_c_files}
    COMMAND ${EverParse_DIR}/everparse.cmd ${CMAKE_CURRENT_SOURCE_DIR}/${elf_spec_file}
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "ebpf-for-windows - Generating Elf.c and Elf.h"
)

add_custom_target(elf_spec_generated_files DEPENDS ${elf_spec_generated_c_files})

add_definitions(-D_AMD64_=1)

add_library(elf_spec STATIC ${elf_spec_generated_c_files})
add_dependencies(elf_spec elf_spec_generated_files)

target_include_directories("elf_spec" PUBLIC "${CMAKE_CURRENT_BINARY_DIR}")
target_compile_options("elf_spec" PRIVATE  /wd"4456" /wd"4100" /wd"26451")
