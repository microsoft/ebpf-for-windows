# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/usersim/external/FindWDK/cmake"
)

find_package(WDK REQUIRED)

set(ubpf_sources
  ../../external/ubpf/vm/ebpf.h
  ../../external/ubpf/vm/ubpf_int.h
)

#
# ubpf_user
#

add_library("ubpf_user" STATIC
  ${ubpf_sources}

  ../../external/ubpf/vm/ubpf_jit_x86_64.h
  user/ubpf_user.c
)

target_include_directories("ubpf_user" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/ubpf"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
)

target_link_libraries("ubpf_user" PRIVATE
  "ebpf_for_windows_common_settings"
  "rpc_interface"
  "external::boost"
)

target_compile_options("ubpf_user" PRIVATE
  /w
)

target_compile_definitions("ubpf_user" PRIVATE
  _LIB
  __x86_64__
)

#
# ubpf_kernel
#

wdk_add_library("ubpf_kernel" STATIC WINVER "${EBPFFORWINDOWS_WDK_WINVER}"
  ${ubpf_sources}
  kernel/ubpf_kernel.c
)

target_compile_options("ubpf_kernel" PRIVATE
  "/WX-"
)

target_include_directories("ubpf_kernel" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
  "${CMAKE_SOURCE_DIR}/libs/ubpf"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
)

target_compile_definitions("ubpf_kernel" PRIVATE
  WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP
  WINAPI_PARTITION_DESKTOP=1
  WINAPI_PARTITION_SYSTEM=1
  WINAPI_PARTITION_APP=1
  WINAPI_PARTITION_PC_APP=1
  _NO_CRT_STDIO_INLINE=1
)
