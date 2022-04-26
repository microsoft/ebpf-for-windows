# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("port_quota"
  port_quota.cpp
)

target_link_libraries("port_quota" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "EbpfApi"
  "external::libbpf"
)

target_include_directories("port_quota" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
)

target_compile_definitions("port_quota" PRIVATE
  _CONSOLE
)
