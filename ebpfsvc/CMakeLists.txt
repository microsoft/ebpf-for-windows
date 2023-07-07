# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("ebpfsvc"
  ../resource/ebpf_resource.rc

  resource.h
  svc_common.h

  ../libs/thunk/windows/platform.cpp
  rpc_api.cpp
  svcmain.cpp

  rpc_util.h
  rpc_util.cpp
)

target_include_directories("ebpfsvc" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/service"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/rpc_interface"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries("ebpfsvc" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "api_common"
  "platform_user"
  "rpc_interface"
  "service"
  "ubpf_user"
  "git_commit_id"
  "external::ebpfverifier"
  "usersim"
  "Mincore.lib"
)

target_compile_definitions("ebpfsvc" PRIVATE
  EBPFSVC_EXPORTS
  _WINDOWS
  _USRDLL
)

codeSign("ebpfsvc")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "ebpfsvc"
    DESTINATION "."
  )
endif()
