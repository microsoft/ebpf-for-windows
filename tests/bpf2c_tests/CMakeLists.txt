# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("bpf2c_tests"
  ../../tools/bpf2c/bpf_code_generator.h
  ../../tools/bpf2c/bpf_code_generator.cpp

  bpf_assembler.h
  bpf_assembler.cpp

  raw_bpf.cpp
  elf_bpf.cpp
)

target_include_directories("bpf2c_tests" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/tools/bpf2c"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
)

target_link_libraries("bpf2c_tests" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "EbpfApi"
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
)

target_compile_definitions("bpf2c_tests" PRIVATE
  _CONSOLE
  BPF2C_VERBOSE
)

target_compile_options("bpf2c_tests" PRIVATE
  "/WX-"
)

configure_file(
  bpf_test.cpp
  "${CMAKE_CURRENT_BINARY_DIR}/bpf_test.cpp"
  COPYONLY
)

add_test(
  NAME "bpf2c_tests"
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:bpf2c_tests>"
)

set(expected_file_list
  bindmonitor_dll.txt
  bindmonitor_raw.txt
  bindmonitor_ringbuf_dll.txt
  bindmonitor_ringbuf_raw.txt
  bindmonitor_ringbuf_sys.txt
  bindmonitor_sys.txt
  bindmonitor_tailcall_dll.txt
  bindmonitor_tailcall_raw.txt
  bindmonitor_tailcall_sys.txt
  bpf_call_dll.txt
  bpf_call_raw.txt
  bpf_call_sys.txt
  bpf_dll.txt
  bpf_raw.txt
  bpf_sys.txt
  cgroup_sock_addr_dll.txt
  cgroup_sock_addr_raw.txt
  cgroup_sock_addr_sys.txt
  decap_permit_packet_dll.txt
  decap_permit_packet_raw.txt
  decap_permit_packet_sys.txt
  divide_by_zero_dll.txt
  divide_by_zero_raw.txt
  divide_by_zero_sys.txt
  droppacket_dll.txt
  droppacket_raw.txt
  droppacket_sys.txt
  droppacket_unsafe_dll.txt
  droppacket_unsafe_raw.txt
  droppacket_unsafe_sys.txt
  encap_reflect_packet_dll.txt
  encap_reflect_packet_raw.txt
  encap_reflect_packet_sys.txt
  sockops_dll.txt
  sockops_raw.txt
  sockops_sys.txt
  map_dll.txt
  map_in_map_dll.txt
  map_in_map_raw.txt
  map_in_map_sys.txt
  map_in_map_v2_dll.txt
  map_in_map_v2_raw.txt
  map_in_map_v2_sys.txt
  map_raw.txt
  map_reuse_2_dll.txt
  map_reuse_2_raw.txt
  map_reuse_2_sys.txt
  map_reuse_dll.txt
  map_reuse_raw.txt
  map_reuse_sys.txt
  map_sys.txt
  printk_dll.txt
  printk_legacy_dll.txt
  printk_legacy_raw.txt
  printk_legacy_sys.txt
  printk_raw.txt
  printk_sys.txt
  printk_unsafe_dll.txt
  printk_unsafe_raw.txt
  printk_unsafe_sys.txt
  reflect_packet_dll.txt
  reflect_packet_raw.txt
  reflect_packet_sys.txt
  tail_call_bad_dll.txt
  tail_call_bad_raw.txt
  tail_call_bad_sys.txt
  tail_call_dll.txt
  tail_call_map_dll.txt
  tail_call_map_raw.txt
  tail_call_map_sys.txt
  tail_call_multiple_dll.txt
  tail_call_multiple_raw.txt
  tail_call_multiple_sys.txt
  tail_call_raw.txt
  tail_call_sys.txt
  test_sample_ebpf_dll.txt
  test_sample_ebpf_raw.txt
  test_sample_ebpf_sys.txt
  test_utility_helpers_dll.txt
  test_utility_helpers_raw.txt
  test_utility_helpers_sys.txt
)

foreach(expected_file ${expected_file_list})
  configure_file(
    "expected/${expected_file}"
    "${CMAKE_CURRENT_BINARY_DIR}/${expected_file}"
    COPYONLY
  )
endforeach()
