# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

#
# ebpf_program_types_interface
#

set(ebpf_program_types_h_name "ebpf_program_types_h.h")
set(ebpf_program_types_h_path "${CMAKE_CURRENT_BINARY_DIR}/${ebpf_program_types_h_name}")

set(ebpf_program_types_c_name "ebpf_program_types_c.c")
set(ebpf_program_types_c_path "${CMAKE_CURRENT_BINARY_DIR}/${ebpf_program_types_c_name}")

add_custom_command(
  OUTPUT
    "${ebpf_program_types_h_path}"
    "${ebpf_program_types_c_path}"

  COMMAND
    "${MIDL_COMPILER_PATH}" "/I${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src" "/I${CMAKE_SOURCE_DIR}/include" /W1 /nologo /char signed /env x64 /h "ebpf_program_types_h.h" /notlb /client stub /server none /target NT60 /acf ../ebpf_program_types.acf /protocol dce ../ebpf_program_types.idl

  COMMAND
    "${CMAKE_COMMAND}" -E rename "${ebpf_program_types_h_name}" "${ebpf_program_types_h_path}"

  COMMAND
    "${CMAKE_COMMAND}" -E rename "${ebpf_program_types_c_name}" "${ebpf_program_types_c_path}"

  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}/user"

  DEPENDS
    "ebpf_program_types.idl"

  COMMENT
    "ebpf-for-windows - Building: ebpf_program_types.idl"

  VERBATIM
)

add_custom_target("ebpf_program_types_interface_builder"
  DEPENDS "${ebpf_program_types_h_path}"
)

add_library("ebpf_program_types_interface" OBJECT
  "${ebpf_program_types_c_path}"
)

add_dependencies("ebpf_program_types_interface"
  "ebpf_program_types_interface_builder"
)

target_include_directories("ebpf_program_types_interface" INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)

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

  ebpf_program_types.c
  ebpf_error.c
  ebpf_etw.c
  ebpf_extension.c
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
  user/ebpf_low_memory_test.cpp
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
  "ebpf_program_types_interface"
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
  "ebpf_program_types_interface"
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
