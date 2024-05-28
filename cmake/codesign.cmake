# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

function(codeSign target_name)
  if(NOT EXISTS "${EBPFFORWINDOWS_CODESIGN_CERTIFICATE_PATH}")
    return()
  endif()

  if(NOT EBPFFORWINDOWS_CODESIGN_PASSWORD_ENV_VAR STREQUAL "")
    set(optional_cert_password
      "-Dpassword_env_var:STRING=${EBPFFORWINDOWS_CODESIGN_PASSWORD_ENV_VAR}"
    )
  endif()

  add_custom_command(
    TARGET
      "${target_name}"

    POST_BUILD

    COMMAND
      "${CMAKE_COMMAND}" "-Dcertificate_path:PATH=${EBPFFORWINDOWS_CODESIGN_CERTIFICATE_PATH}" ${optional_cert_password} "-Dbinary_path:PATH=$<TARGET_FILE:${target_name}>" -P "${CMAKE_SOURCE_DIR}/cmake/codesign_helper.cmake"

    COMMENT
      "ebpf-for-windows - Code signing: ${target_name}"
  )
endfunction()
