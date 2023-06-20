# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/usersim/external/FindWDK/cmake"
)

find_package(WDK REQUIRED)

set(execution_context_sources
  ebpf_core.h
  ebpf_core.c

  ebpf_link.h
  ebpf_link.c

  ebpf_maps.h
  ebpf_maps.c

  ebpf_native.h
  ebpf_native.c

  ebpf_program.h
  ebpf_program.c

  ebpf_protocol.h
  ebpf_general_helpers.c
)

#
# execution_context_user
#

add_library("execution_context_user" STATIC
  ${execution_context_sources}
)

target_include_directories("execution_context_user" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
)

target_link_libraries("execution_context_user" PRIVATE
  "ebpf_for_windows_common_settings"
  "external::ebpfverifier_headers"
)

target_compile_definitions("execution_context_user" PRIVATE
  _LIB
)

#
# execution_context_kernel
#

wdk_add_library("execution_context_kernel" STATIC WINVER "${EBPFFORWINDOWS_WDK_WINVER}"
  ${execution_context_sources}
)

target_include_directories("execution_context_kernel" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
)

target_link_libraries("execution_context_kernel" PRIVATE
  "ebpf_for_windows_base_definitions"
  "external::ebpfverifier_headers"
)

target_compile_definitions("execution_context_kernel" PRIVATE
  $<$<CONFIG:Release>:_DEBUG>
  $<$<CONFIG:Debug>:NDEBUG>
  WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP
  WINAPI_PARTITION_DESKTOP=1
  WINAPI_PARTITION_SYSTEM=1
  WINAPI_PARTITION_APP=1
  WINAPI_PARTITION_PC_APP=1
  _NO_CRT_STDIO_INLINE=1
)
