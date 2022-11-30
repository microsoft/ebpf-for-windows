# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("socket_tests"
  socket_tests.cpp
)

target_include_directories("socket_tests" PRIVATE
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
)

target_link_libraries("socket_tests" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "common_tests"
  "EbpfApi"
  "test_util"
  "ws2_32.lib"
  "Catch2::Catch2"
)

target_compile_definitions("socket_tests" PRIVATE
  _CONSOLE
)

add_test(
  NAME "socket_tests"
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:socket_tests>"
)
