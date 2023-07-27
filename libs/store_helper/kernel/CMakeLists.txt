# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/usersim/external/FindWDK/cmake"
)
find_package(WDK REQUIRED)

wdk_add_library("ebpf_store_helper_km" STATIC WINVER "${EBPFFORWINDOWS_WDK_WINVER}"
  ebpf_registry_helper.c
  ebpf_store_helper.c
)

target_link_directories("ebpf_store_helper_km" PRIVATE
  "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64"
)

target_include_directories("ebpf_store_helper_km" PRIVATE
"${CMAKE_SOURCE_DIR}/include"
"${CMAKE_SOURCE_DIR}/libs/platform"
"${CMAKE_SOURCE_DIR}/libs/platform/kernel"
"${CMAKE_SOURCE_DIR}/libs/store_helper"
"${CMAKE_SOURCE_DIR}/libs/store_helper/kernel"
"${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
)

target_compile_definitions("ebpf_store_helper_km" PRIVATE
  WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP
  WINAPI_PARTITION_DESKTOP=1
  WINAPI_PARTITION_SYSTEM=1
  WINAPI_PARTITION_APP=1
  WINAPI_PARTITION_PC_APP=1
  _KRPCENV_
  _NO_CRT_STDIO_INLINE=1
)