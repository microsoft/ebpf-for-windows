# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("ebpf_store_helper_km" STATIC
  ebpf_registry_helper_km.c
  ../ebpf_store_helper.c
)

target_include_directories("ebpf_store_helper_km" PRIVATE
"${CMAKE_SOURCE_DIR}/include"
"${CMAKE_SOURCE_DIR}/libs/platform"
"${CMAKE_SOURCE_DIR}/libs/platform/kernel"
"${CMAKE_SOURCE_DIR}/libs/store_helper/kernel"
"${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
)

target_compile_definitions("ebpf_store_helper_km" PRIVATE
  _WINDOWS
  _LIB
)