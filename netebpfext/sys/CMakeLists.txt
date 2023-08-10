# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/usersim/external/FindWDK/cmake"
)
find_package(WDK REQUIRED)

wdk_add_driver("NetEbpfExt" WINVER "${EBPFFORWINDOWS_WDK_WINVER}" KMDF "${EBPFFORWINDOWS_WDK_KMDF_VERSION}"
  ../guid.c

  ../net_ebpf_ext.h
  ../net_ebpf_ext.c

  ../net_ebpf_ext_bind.h
  ../net_ebpf_ext_bind.c

  ../net_ebpf_ext_hook_provider.h
  ../net_ebpf_ext_hook_provider.c

  ../net_ebpf_ext_prog_info_provider.h
  ../net_ebpf_ext_prog_info_provider.c

  ../net_ebpf_ext_sock_addr.h
  ../net_ebpf_ext_sock_addr.c

  ../net_ebpf_ext_xdp.h
  ../net_ebpf_ext_xdp.c

  ../net_ebpf_ext_sock_ops.h
  ../net_ebpf_ext_sock_ops.c

  ../net_ebpf_ext_program_info.h
  resource.h

  ../net_ebpf_ext_tracelog.c
  ../net_ebpf_ext_tracelog.h

  net_ebpf_ext_drv.c
)

target_include_directories("NetEbpfExt" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/include/kernel"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/kernel"
  "${CMAKE_SOURCE_DIR}/libs/store_helper"
  "${CMAKE_SOURCE_DIR}/libs/store_helper/kernel"
  "${CMAKE_SOURCE_DIR}/netebpfext/sys"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/resource"
)

target_link_directories("NetEbpfExt" PRIVATE
  "${WDK_ROOT}/Lib/${WDK_VERSION}/km/x64"
)

target_link_libraries("NetEbpfExt"
  "ebpf_for_windows_common_settings"
  "ebpf_store_helper_km"
  "external::ebpfverifier_headers"
  "Ndis.lib"
  "Netio.lib"
  "Fwpkclnt.lib"
  "wdmsec.lib"
)

target_compile_definitions("NetEbpfExt" PRIVATE
  BINARY_COMPATIBLE=0
  NT
  NDIS60
  POOL_NX_OPTIN_AUTO
)

# api_common includes NetEbpfExt's headers. Since this is a driver
# and it does not make sense to link against it, for now create
# an interface target that just exports the include directory.
add_library("NetEbpfExt_headers" INTERFACE)
target_include_directories("NetEbpfExt_headers" SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/.."
)

codeSign("NetEbpfExt")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "NetEbpfExt"
    DESTINATION "drivers"
  )

  install(
    FILES "netebpfext.inf"
    DESTINATION "drivers"
  )
endif()