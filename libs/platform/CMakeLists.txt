# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

#
# platform_{user,kernel}
#

set(platform_user_sources
  ebpf_async.h
  ebpf_async.c

  ebpf_bitmap.h
  ebpf_bitmap.c

  ebpf_crypto_hash.c

  ebpf_epoch.h
  ebpf_epoch.c

  ebpf_object.h
  ebpf_object.c

  ebpf_pinning_table.h
  ebpf_pinning_table.c

  ebpf_ring_buffer.h
  ebpf_ring_buffer.c

  ebpf_state.h
  ebpf_state.c

  ebpf_handle.h
  ebpf_platform.h

  ebpf_error.c
  ebpf_etw.c
  ebpf_hash_table.c
  ebpf_interlocked.c
  ebpf_serialize.c
  ebpf_trampoline.c
)

set(platform_kernel_include_dirs
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
)

#
# platform_user
#

add_library("platform_user" STATIC
  ${platform_user_sources}
  user/framework.h
  user/ebpf_handle_user.c
  user/ebpf_leak_detector.cpp
  user/ebpf_fault_injection.cpp
  user/ebpf_platform_user.cpp
  user/ebpf_native_user.c
  user/kernel_um.cpp
  user/nmr_impl.cpp
  user/nmr_um.cpp
)

target_include_directories("platform_user" PRIVATE
  ${platform_kernel_include_dirs}
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/include/user"
)

target_link_libraries("platform_user" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "ebpfverifier_headers"
)

target_compile_definitions("platform_user" PRIVATE
  _LIB
)

#
# platform_kernel
#

wdk_add_library("platform_kernel" STATIC WINVER "${EBPFFORWINDOWS_WDK_WINVER}"
  ${platform_user_sources}
  kernel/ebpf_handle_kernel.c
  kernel/ebpf_platform_kernel.c
  kernel/ebpf_native_kernel.c
)

target_include_directories("platform_kernel" PRIVATE
  ${platform_kernel_include_dirs}
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
  "${CMAKE_SOURCE_DIR}/libs/epoch"
  "${CMAKE_SOURCE_DIR}/include/kernel"
)

target_link_libraries("platform_kernel" PRIVATE
  "ebpf_for_windows_common_settings"
  "external::ebpfverifier_headers"
)

target_compile_definitions("platform_kernel" PRIVATE
  WINAPI_FAMILY=WINAPI_FAMILY_DESKTOP_APP
  WINAPI_PARTITION_DESKTOP=1
  WINAPI_PARTITION_SYSTEM=1
  WINAPI_PARTITION_APP=1
  WINAPI_PARTITION_PC_APP=1
  _KRPCENV_
  _NO_CRT_STDIO_INLINE=1
)
