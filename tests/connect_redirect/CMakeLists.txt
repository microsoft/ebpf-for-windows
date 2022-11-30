# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("connect_redirect_tests"
  connect_redirect_tests.cpp
)

target_include_directories("connect_redirect_tests" PRIVATE
  "${CMAKE_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tests/sample"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
)

target_link_libraries("connect_redirect_tests" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "common_tests"
  "EbpfApi"
  "test_util"
  "ws2_32.lib"
  "Catch2::Catch2"
)

target_compile_definitions("connect_redirect_tests" PRIVATE
  _CONSOLE
  _WINSOCK_DEPRECATED_NO_WARNINGS
)

add_test(
  NAME "connect_redirect_tests"
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:connect_redirect_tests>"
)
