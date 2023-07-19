# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("ebpf_store_helper_um" STATIC
  ebpf_registry_helper_um.cpp
  ebpf_store_helper.cpp
)

target_include_directories("ebpf_store_helper_um" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/store_helper/user"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
)

target_compile_definitions("ebpf_store_helper_um" PRIVATE
  _WINDOWS
  _LIB
  UNICODE
  _UNICODE
  USER_MODE
)
