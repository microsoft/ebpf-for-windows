# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_executable("ebpf_stress_tests_km"

    ../ebpf_stress_tests.cpp
    stress_tests_km.cpp
)

target_include_directories("ebpf_stress_tests_km" PRIVATE
    "${CMAKE_SOURCE_DIR}/tests/stress"
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/libs/api"
    "${CMAKE_SOURCE_DIR}/tests/end_to_end"
    "${CMAKE_SOURCE_DIR}/tests/libs/util"
    "${CMAKE_SOURCE_DIR}/tests/libs/common"
    "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
    "${CMAKE_SOURCE_DIR}/tests/socket"
    "${CMAKE_SOURCE_DIR}/libs/execution_context"
    "${CMAKE_SOURCE_DIR}/libs/Platform"
    "${CMAKE_SOURCE_DIR}/libs/Platform/user"
    "${CMAKE_SOURCE_DIR}/libs/thunk"
    "${CMAKE_SOURCE_DIR}/netebpfext"
    "${CMAKE_SOURCE_DIR}/libs/api_common"
    "${WDK_ROOT}/include/${WDK_VERSION}/km"
    "${WDK_ROOT}/include/${WDK_VERSION}/um"
    "${WDK_ROOT}/include/${WDK_VERSION}/shared"
)

target_link_libraries("ebpf_stress_tests_km" PRIVATE
    "ebpf_for_windows_cpp_settings"
    "common_tests"
    "EbpfApi"
    "rpc_interface"
    "test_util"
    "Catch2::Catch2"
    "ws2_32.lib"
    "Secur32.lib"
)

target_compile_definitions("ebpf_stress_tests_km" PRIVATE
    _CONSOLE
)

add_test(
    NAME "ebpf_stress_tests_km"
    COMMAND "${CMAKE_COMMAND}" -E env "PATH=$<TARGET_FILE_DIR:EbpfApi>;$ENV{PATH}" "$<TARGET_FILE:ebpf_stress_tests_km>"
)
