# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("port_leak"
  port_leak.cpp
)

target_link_libraries("port_leak" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "ws2_32.lib"
)

target_compile_definitions("port_leak" PRIVATE
  _CONSOLE
)
