# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("api_test"
  api_test.cpp
)

target_include_directories("api_test" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/Platform"
  "${CMAKE_SOURCE_DIR}/libs/Platform/user"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${WDK_ROOT}/include/10.0.22000.0/km"
  "${WDK_ROOT}/include/10.0.22000.0/shared"
)

target_link_libraries("api_test" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "common_tests"
  "EbpfApi"
  "rpc_interface"
  "test_util"
  "Catch2::Catch2WithMain"
  "ws2_32.lib"
)

target_compile_definitions("api_test" PRIVATE
  _WINSOCK_DEPRECATED_NO_WARNINGS
  _CONSOLE
)

add_test(
  NAME "api_test"
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:api_test>"
)
