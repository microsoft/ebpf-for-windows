# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("cilium_tests"
  cilium_tests.cpp
)

target_include_directories("cilium_tests" PRIVATE
  "${CMAKE_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/external/catch2/src"
  "${CMAKE_SOURCE_DIR}/external/catch2/build/generated-includes"
  "${CMAKE_SOURCE_DIR}/external/bpftool"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
)


target_link_libraries("cilium_tests" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "Catch2::Catch2WithMain"
  "EbpfApi"
  "ws2_32"
)

target_compile_definitions("cilium_tests" PRIVATE
  _CONSOLE
  $<$<CONFIG:DEBUG>:SKIP_VERIFICATION>
)