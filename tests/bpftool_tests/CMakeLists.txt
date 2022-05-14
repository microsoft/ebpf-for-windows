# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("bpftooltests"
    bpftool_tests.cpp
)

target_include_directories("bpftooltests" PRIVATE
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/external/catch2/src"
  "${CMAKE_SOURCE_DIR}/external/catch2/build/generated-includes"
)

target_link_libraries("bpftooltests" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "Catch2::Catch2WithMain"
  "EbpfApi"
  "test_util"
)

target_compile_definitions("bpftooltests" PRIVATE
  _CONSOLE
)

