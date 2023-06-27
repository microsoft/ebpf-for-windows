# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("ebpf_performance"
  performance_measure.h

  ExecutionContext.cpp
  platform.cpp

  performance.h
  performance.cpp
)

target_include_directories("ebpf_performance" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/ebpfnetsh"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_SOURCE_DIR}/libs/service"
  "${CMAKE_SOURCE_DIR}/rpc_interface"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/libs/thunk/mock"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${WDK_ROOT}/include/${WDK_VERSION}/km"
  "${WDK_ROOT}/include/${WDK_VERSION}/shared"
)

target_link_libraries("ebpf_performance" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "execution_context_user"
  "platform_user"
  "ubpf_user"
  "usersim"
  "Catch2::Catch2WithMain"
  "Mincore.lib"
  "external::libbpf"
)

target_compile_definitions("ebpf_performance" PRIVATE
  _CONSOLE
)

add_test(
  NAME "ebpf_performance"
  COMMAND "ebpf_performance"
)
