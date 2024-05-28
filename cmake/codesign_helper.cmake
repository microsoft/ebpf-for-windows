# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

find_program(signtool_path "SignTool")
if(NOT signtool_path)
  message(FATAL_ERROR "ebpf-for-windows: Code signing was enabled but the SignTool binary was not found")
endif()

if(NOT password_env_var STREQUAL "")
  set(optional_cert_password
    "/p"
    "$ENV{${password_env_var}}"
  )
endif()

execute_process(
  COMMAND "${signtool_path}" sign /f "${certificate_path}" ${optional_cert_password} /tr "http://timestamp.digicert.com" /td sha256 /fd sha256 "${binary_path}"
  RESULT_VARIABLE signtool_output
)

if(NOT ${signtool_output} EQUAL 0)
  message(FATAL_ERROR "ebpf-for-windows - Failed to codesign the following binary: ${binary_path}")
endif()
