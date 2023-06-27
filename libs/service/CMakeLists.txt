# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("service" STATIC
  api_service.h
  api_service.cpp

  verifier_service.h
  verifier_service.cpp

  windows_platform_service.hpp
  windows_platform_service.cpp
)

target_include_directories("service" PRIVATE
  "${CMAKE_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/rpc_interface"
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
)

target_link_libraries("service" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "rpc_interface"
  "external::boost"
  "external::ebpfverifier"
)

target_compile_definitions("service" PRIVATE
  _WINDOWS
  _USRDLL
)
