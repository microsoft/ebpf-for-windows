# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("fuzz"
    ../../libs/thunk/mock/mock.cpp
    ../../libs/thunk/mock/mock.h

    ../end_to_end/test_helper.cpp
    ../end_to_end/test_helper.hpp

    execution_context.cpp
)

target_include_directories("fuzz" PRIVATE
  "${CMAKE_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/external/catch2/src"
  "${CMAKE_SOURCE_DIR}/external/catch2/build/generated-includes"
  "${CMAKE_SOURCE_DIR}/external/bpftool"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/libs/api_common"
  "${CMAKE_SOURCE_DIR}/libs/ebpfnetsh"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/service"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/libs/thunk/mock"
  "${CMAKE_SOURCE_DIR}/netebpfext"
  "${CMAKE_SOURCE_DIR}/rpc_interface"
  "${CMAKE_SOURCE_DIR}/tests/end_to_end"
  "${CMAKE_SOURCE_DIR}/tests/libs/common"
  "${CMAKE_SOURCE_DIR}/tests/libs/util"
  "${CMAKE_SOURCE_DIR}/tests/sample"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/tests/xdp"
  "${CMAKE_SOURCE_DIR}/tools/export_program_info"
  "${WDK_ROOT}/include/10.0.22000.0/km"
  "${WDK_ROOT}/include/10.0.22000.0/shared"
)

target_link_libraries("fuzz" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "api"
  "api_common"
  "Catch2::Catch2"
  "Catch2::Catch2WithMain"
  "common_tests"
  "EbpfApi"
  "execution_context_user"
  "external::ebpfverifier"
  "mincore.lib"
  "pe_parse"
  "platform_user"
  "service"
  "test_util"
  "ubpf_user"
)

target_compile_definitions("fuzz" PRIVATE
  _CONSOLE
)

