# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("ebpf_stress_tests_um"

    ../../../libs/thunk/mock/mock.h
    ../../../libs/thunk/mock/mock.cpp

    ../../end_to_end/helpers.h

    ../../end_to_end/test_helper.hpp
    ../../end_to_end/test_helper.cpp

    ../ebpf_stress_tests.cpp
)

target_include_directories("ebpf_stress_tests_um" PRIVATE
    "${CMAKE_BINARY_DIR}"
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
    "${CMAKE_SOURCE_DIR}/tests/sample"
    "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
    "${CMAKE_SOURCE_DIR}//tests/xdp"
    "${CMAKE_SOURCE_DIR}/tools/export_program_info"
    "${CMAKE_SOURCE_DIR}/libs/thunk"
    "${CMAKE_SOURCE_DIR}/libs/thunk/mock"
    "${CMAKE_SOURCE_DIR}//netebpfext"
    "${WDK_ROOT}/include/${WDK_VERSION}/km"
    "${WDK_ROOT}/include/${WDK_VERSION}/shared"
)

target_link_libraries("ebpf_stress_tests_um" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "api"
  "api_common"
  "Catch2::Catch2WithMain"
  "common_tests"
  "netsh_static"
  "external::ebpfverifier"
  "execution_context_user"
  "pe_parse"
  "platform_user"
  "rpc_interface"
  "service"
  "test_util"
  "ubpf_user"
  "Mincore.lib"
  "external::boost"
)

add_test(
  NAME "ebpf_stress_tests_um"
  COMMAND "ebpf_stress_tests_um"
)
