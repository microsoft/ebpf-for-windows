# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("bpf2c_tests"
  ../../tools/bpf2c/bpf_code_generator.h
  ../../tools/bpf2c/bpf_code_generator.cpp

  ../../external/ubpf/external/bpf_conformance/src/bpf_assembler.h
  ../../external/ubpf/external/bpf_conformance/src/bpf_assembler.cc

  raw_bpf.cpp
  elf_bpf.cpp
)

target_include_directories("bpf2c_tests" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/resource"
  "${CMAKE_SOURCE_DIR}/tools/bpf2c"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
)

target_link_libraries("bpf2c_tests" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "EbpfApi"
  "elf_spec"
  "external::ebpfverifier"
  "test_util"
  "Catch2::Catch2WithMain"

  # Generated in the bpf2c directory. Required because elf_bpf.cpp
  # is including bpf2c.cpp
  #
  # It would be better not to include the .cpp file like that and instead
  # make a library
  "bpf2c_driver"
  "bpf2c_dll"
  "ubpf_user"
  "Mincore.lib"
)

target_compile_definitions("bpf2c_tests" PRIVATE
  _CONSOLE
  BPF2C_VERBOSE
)

target_compile_options("bpf2c_tests" PRIVATE
  "/WX-"
)

add_test(
  NAME "bpf2c_tests"
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:bpf2c_tests>"
)

set(expected_file_list
  bindmonitor_dll.c
  bindmonitor_raw.c
  bindmonitor_ringbuf_dll.c
  bindmonitor_ringbuf_raw.c
  bindmonitor_ringbuf_sys.c
  bindmonitor_sys.c
  bindmonitor_tailcall_dll.c
  bindmonitor_tailcall_raw.c
  bindmonitor_tailcall_sys.c
  bpf_call_dll.c
  bpf_call_raw.c
  bpf_call_sys.c
  bpf_dll.c
  bpf_raw.c
  bpf_sys.c
  cgroup_sock_addr_dll.c
  cgroup_sock_addr_raw.c
  cgroup_sock_addr_sys.c
  decap_permit_packet_dll.c
  decap_permit_packet_raw.c
  decap_permit_packet_sys.c
  divide_by_zero_dll.c
  divide_by_zero_raw.c
  divide_by_zero_sys.c
  droppacket_dll.c
  droppacket_raw.c
  droppacket_sys.c
  droppacket_unsafe_dll.c
  droppacket_unsafe_raw.c
  droppacket_unsafe_sys.c
  encap_reflect_packet_dll.c
  encap_reflect_packet_raw.c
  encap_reflect_packet_sys.c
  sockops_dll.c
  sockops_raw.c
  sockops_sys.c
  map_dll.c
  map_in_map_dll.c
  map_in_map_raw.c
  map_in_map_sys.c
  map_in_map_v2_dll.c
  map_in_map_v2_raw.c
  map_in_map_v2_sys.c
  map_raw.c
  map_reuse_2_dll.c
  map_reuse_2_raw.c
  map_reuse_2_sys.c
  map_reuse_dll.c
  map_reuse_raw.c
  map_reuse_sys.c
  map_sys.c
  printk_dll.c
  printk_legacy_dll.c
  printk_legacy_raw.c
  printk_legacy_sys.c
  printk_raw.c
  printk_sys.c
  printk_unsafe_dll.c
  printk_unsafe_raw.c
  printk_unsafe_sys.c
  reflect_packet_dll.c
  reflect_packet_raw.c
  reflect_packet_sys.c
  tail_call_bad_dll.c
  tail_call_bad_raw.c
  tail_call_bad_sys.c
  tail_call_dll.c
  tail_call_map_dll.c
  tail_call_map_raw.c
  tail_call_map_sys.c
  tail_call_multiple_dll.c
  tail_call_multiple_raw.c
  tail_call_multiple_sys.c
  tail_call_raw.c
  tail_call_sys.c
  test_sample_ebpf_dll.c
  test_sample_ebpf_raw.c
  test_sample_ebpf_sys.c
  test_utility_helpers_dll.c
  test_utility_helpers_raw.c
  test_utility_helpers_sys.c
)

set (input_bpf_test_cpp ${CMAKE_CURRENT_SOURCE_DIR}/bpf_test.cpp)
set (output_bpf_test_cpp ${output_dir}/bpf_test.cpp)

foreach(file ${expected_file_list})
  set( input_expected_files ${input_expected_files} ${CMAKE_CURRENT_SOURCE_DIR}/expected/${file})
  set( output_expected_files ${output_expected_files} ${output_dir}/${file})
endforeach()

add_custom_target(bpf2c_tests_expected_files ALL DEPENDS ${output_bpf_test_cpp} ${output_expected_files} SOURCES ${input_bpf_test_cpp} ${input_expected_files})

add_custom_command(
  OUTPUT
    "${output_expected_files}"
  COMMAND
    ${CMAKE_COMMAND} -E make_directory "${output_dir}/expected"
  COMMAND
    ${CMAKE_COMMAND} -E copy ${input_bpf_test_cpp} ${output_bpf_test_cpp}
  COMMAND
    ${CMAKE_COMMAND} -E copy ${input_expected_files} ${output_dir}/expected
  DEPENDS
    ${input_bpf_test_cpp} ${input_expected_files}
)
