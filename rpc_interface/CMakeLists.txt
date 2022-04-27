# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(rpc_interface_h_name "rpc_interface_h.h")
set(rpc_interface_c_name "rpc_interface_c.c")
set(rpc_interface_s_name "rpc_interface_s.c")

set(rpc_interface_h_path "${CMAKE_CURRENT_BINARY_DIR}/${rpc_interface_h_name}")
set(rpc_interface_c_path "${CMAKE_CURRENT_BINARY_DIR}/${rpc_interface_c_name}")
set(rpc_interface_s_path "${CMAKE_CURRENT_BINARY_DIR}/${rpc_interface_s_name}")

add_custom_command(
  OUTPUT
    "${rpc_interface_h_path}"
    "${rpc_interface_c_path}"
    "${rpc_interface_s_path}"

  COMMAND
    "${MIDL_COMPILER_PATH}" "/I${CMAKE_SOURCE_DIR}/include" "/I${CMAKE_SOURCE_DIR}/libs/api" /W1 /nologo /char unsigned /env x64 /h "${rpc_interface_h_name}" /tlb "x64/$<$<CONFIG:Debug>:Debug>$<$<CONFIG:Release>:Release>/rpc_interface.tlb" /target NT100 /prefix server ebpf_server_ /prefix client ebpf_client_ rpc_interface.idl

  COMMAND
    "${CMAKE_COMMAND}" -E rename "${rpc_interface_h_name}" "${rpc_interface_h_path}"

  COMMAND
    "${CMAKE_COMMAND}" -E rename "${rpc_interface_c_name}" "${rpc_interface_c_path}"

  COMMAND
    "${CMAKE_COMMAND}" -E rename "${rpc_interface_s_name}" "${rpc_interface_s_path}"

  WORKING_DIRECTORY
    "${CMAKE_CURRENT_SOURCE_DIR}"

  DEPENDS
    "rpc_interface.idl"

  COMMENT
    "ebpf-for-windows - Building: rpc_interface.idl"

  VERBATIM
)

add_custom_target("rpc_interface_builder"
  DEPENDS "${rpc_interface_h_path}"
)

add_library("rpc_interface" INTERFACE)
add_dependencies("rpc_interface"
  "rpc_interface_builder"
)

target_include_directories("rpc_interface" INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)
