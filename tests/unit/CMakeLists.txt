# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("unit_tests"
  ../../libs/execution_context/unit/execution_context_unit_test.cpp
  libbpf_test.cpp

  ../../libs/platform/unit/platform_unit_test.cpp

  ../end_to_end/netsh_test.cpp
  ../end_to_end/end_to_end.cpp

  ../../libs/thunk/mock/mock.h
  ../../libs/thunk/mock/mock.cpp

  ../end_to_end/helpers.h

  ../end_to_end/test_helper.hpp
  ../end_to_end/test_helper.cpp

  wer_report_test_wrapper.cpp
)

target_include_directories("unit_tests" PRIVATE
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
)

target_link_libraries("unit_tests" PRIVATE
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
  NAME "unit_tests"
  COMMAND "unit_tests"
)
