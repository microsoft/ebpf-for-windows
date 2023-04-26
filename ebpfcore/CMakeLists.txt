# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

wdk_add_driver("EbpfCore" WINVER "${EBPFFORWINDOWS_WDK_WINVER}" KMDF "${EBPFFORWINDOWS_WDK_KMDF_VERSION}"
  resource.h
  ebpf_drv.c

  ../resource/ebpf_resource.rc
)

target_include_directories("EbpfCore" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/resource"
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_directories("EbpfCore" PRIVATE
  "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64"
)

target_link_libraries("EbpfCore"
  "ebpf_for_windows_common_settings"
  "execution_context_kernel"
  "platform_kernel"
  "external::ebpfverifier_headers"
  "ubpf_kernel"
  "git_commit_id"
  "Netio.lib"
  "ksecdd.lib"
)

target_compile_definitions("EbpfCore" PRIVATE
  BINARY_COMPATIBLE=0
  NT
  NDIS60
  POOL_NX_OPTIN_AUTO
)

codeSign("EbpfCore")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "EbpfCore"
    DESTINATION "drivers"
  )

  install(
    FILES "EbpfCore.inf"
    DESTINATION "drivers"
  )
endif()
