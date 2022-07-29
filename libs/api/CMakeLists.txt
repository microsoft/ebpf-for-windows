# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("api" STATIC
  ../thunk/platform.h

  api_internal.h
  pch.h
  rpc_client.h

  bpf_syscall.cpp
  ebpf_api.cpp
  libbpf_errno.cpp
  libbpf_link.cpp
  libbpf_map.cpp
  libbpf_object.cpp
  libbpf_program.cpp
  libbpf_system.cpp

  Verifier.h
  Verifier.cpp

  windows_platform.hpp
  windows_platform.cpp
)

target_include_directories("api" PRIVATE
  "${CMAKE_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/rpc_interface"
  "${CMAKE_SOURCE_DIR}/libs/service"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/include/bpf"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/external/pe-parse/pe-parser-library/include"
)

target_link_libraries("api" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "rpc_interface"
  "elf_spec"
  "export_program_info_runner"
  "external::ebpfverifier"
  "external::boost"
  "external::libbpf"
)

target_compile_definitions("api" PRIVATE
  _WINDOWS
  _USRDLL
)
