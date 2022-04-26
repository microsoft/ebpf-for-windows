# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("dnsflood"
  dns_flood.cpp
)

target_link_libraries("dnsflood" PRIVATE
  "ebpf_for_windows_cpp_settings"
)

target_compile_definitions("dnsflood" PRIVATE
  _WINSOCK_DEPRECATED_NO_WARNINGS
  _CONSOLE
)
