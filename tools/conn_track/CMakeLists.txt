# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("conn_tracker"
  conn_tracker.cpp
)

target_link_libraries("conn_tracker" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "EbpfApi"
  "external::libbpf"
)

target_include_directories("conn_tracker" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
)

target_compile_definitions("conn_tracker" PRIVATE
  _CONSOLE
)
