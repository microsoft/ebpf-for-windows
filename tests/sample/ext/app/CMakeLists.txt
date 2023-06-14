# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("sample_ext_app"
  sample_ext_app.cpp
)

target_include_directories("sample_ext_app" PRIVATE
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/ebpfnetsh"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tests/sample"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
  "${WDK_ROOT}/include/${WDK_VERSION}/km"
  "${WDK_ROOT}/include/${WDK_VERSION}/shared"
)

target_link_libraries("sample_ext_app" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "common_tests"
  "iphlpapi"
  "EbpfApi"
  "netsh_static"
  "test_util"
  "Catch2::Catch2WithMain"
)

target_compile_definitions("sample_ext_app" PRIVATE
  _CONSOLE
  _WINSOCK_DEPRECATED_NO_WARNINGS
)

add_test(
  NAME "sample_ext_app"
  COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:sample_ext_app>"
)
