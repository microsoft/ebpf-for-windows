# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/usersim/external/FindWDK/cmake"
)
find_package(WDK REQUIRED)

wdk_add_driver("sample_ebpf_ext" WINVER "${EBPFFORWINDOWS_WDK_WINVER}" KMDF "${EBPFFORWINDOWS_WDK_KMDF_VERSION}"
  sample_ext.h
  sample_ext.c

  sample_ext_drv.c
)

target_include_directories("sample_ebpf_ext" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/include/kernel"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
  "${CMAKE_SOURCE_DIR}/tests/sample"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
)

target_link_directories("sample_ebpf_ext" PRIVATE
  "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64"
)

target_link_libraries("sample_ebpf_ext"
  "ebpf_for_windows_common_settings"
  "ebpf_store_helper_km"
  "external::ebpfverifier_headers"
  "platform_kernel"
  "netio.lib"
  "wdmsec.lib"
)

target_compile_definitions("sample_ebpf_ext" PRIVATE
  KERNEL_MODE
  BINARY_COMPATIBLE=0
  NT
  POOL_NX_OPTIN_AUTO
)

# api_common includes sample_ebpf_ext's headers. Since this is a driver
# and it does not make sense to link against it, for now create
# an interface target that just exports the include directory.
add_library("sample_ebpf_ext_headers" INTERFACE)
target_include_directories("sample_ebpf_ext_headers" SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

codeSign("sample_ebpf_ext")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "sample_ebpf_ext"
    DESTINATION "drivers"
  )

  install(
    FILES "sample_ebpf_ext.inf"
    DESTINATION "drivers"
  )
endif()