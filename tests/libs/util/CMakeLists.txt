# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("test_util" STATIC
  capture_helper.cpp

  hash.cpp
  hash.h

  ioctl_helper.h
  ioctl_helper.cpp

  native_helper.hpp
  native_helper.cpp

  netsh_helper.cpp

  program_helper.h
  program_helper.cpp

  service_helper.h
  service_helper.cpp

  socket_helper.h
  socket_helper.cpp
)

target_include_directories("test_util" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/ebpfnetsh"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${WDK_ROOT}/include/${WDK_VERSION}/km"
  "${WDK_ROOT}/include/${WDK_VERSION}/shared"
)

target_include_directories("test_util" SYSTEM INTERFACE
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
)

target_link_libraries("test_util"
  PRIVATE
    "ebpf_for_windows_cpp_settings"

  PUBLIC
    "external::libbpf"
    "Catch2::Catch2"
)

target_compile_definitions("test_util" PRIVATE
  _LIB
)
