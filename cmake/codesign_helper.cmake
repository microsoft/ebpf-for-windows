# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

find_program(signtool_path "SignTool")
if(NOT signtool_path)
  message(FATAL_ERROR "ebpf-for-windows: Code signing was enabled but the SignTool binary was not found")
endif()

if(NOT certificate_path STREQUAL "")
  set(optional_certificate_path "/f ${certificate_path}")
else()
  set(optional_certificate_path "/a")
endif()

if(NOT $ENV{${password_env_var}} STREQUAL "")
  set(optional_cert_password
    "/p"
    "$ENV{${password_env_var}}"
  )
endif()

message(STATUS "signtool_path ${signtool_path}")
message(STATUS "certificate_path ${certificate_path}")
message(STATUS "password_env_var ${password_env_var}")
message(STATUS "optional_certificate_path ${optional_certificate_path}")
message(STATUS "optional_cert_password ${optional_cert_password}")
message(STATUS "signing ${binary_path}")

execute_process(
  COMMAND "${signtool_path}" sign ${optional_certificate_path} ${optional_cert_password} /tr "http://timestamp.digicert.com" /td sha256 /fd sha256 "${binary_path}"
  RESULT_VARIABLE signtool_output
)

if(NOT ${signtool_output} EQUAL 0)
  message(FATAL_ERROR "ebpf-for-windows - Failed to codesign the following binary: ${binary_path}")
endif()
