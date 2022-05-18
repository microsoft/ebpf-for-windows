# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_subdirectory("ext")
add_subdirectory("unsafe")

set(bad_elf_file_list
  bad1.o
  bad2.o
)

foreach(file ${bad_elf_file_list})
  set( input_bad_elf_files ${input_bad_elf_files} ${CMAKE_CURRENT_SOURCE_DIR}/${file})
  set( output_bad_elf_files ${output_bad_elf_files} ${output_dir}/bad/${file})
endforeach()

add_custom_target(copy_bad_bpf_files ALL DEPENDS ${output_bad_elf_files} SOURCES ${input_bad_elf_files})

add_custom_command(
  OUTPUT
    "${output_bad_elf_files}"
  COMMAND
    ${CMAKE_COMMAND} -E make_directory "${output_dir}/bad"
  COMMAND
    ${CMAKE_COMMAND} -E copy ${input_bad_elf_files} ${output_dir}/bad
  DEPENDS
    ${input_bad_elf_files}
)

# build eBPF Samples.
build_bpf_samples(0)