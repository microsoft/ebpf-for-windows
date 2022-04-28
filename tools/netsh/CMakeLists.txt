# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("ebpfnetsh" SHARED
  ../../libs/ebpfnetsh/elf.h
  ../../libs/ebpfnetsh/programs.h
  ../../libs/ebpfnetsh/tokens.h

  ../../resource/ebpf_resource.rc
  ../../libs/thunk/windows/platform.cpp

  resource.h
  ebpfnetsh.rc
  dllmain.c
)

target_include_directories("ebpfnetsh" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/ebpfnetsh"
  "${CMAKE_SOURCE_DIR}/external/ebpf-verifier/src"
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries("ebpfnetsh" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "netsh_static"
  "EbpfApi"
  "git_commit_id"
  "Iphlpapi.lib"
  "Netsh.lib"
)

target_compile_definitions("ebpfnetsh" PRIVATE
  EBPFNETSH_EXPORTS
  _WINDOWS
  _USRDLL
)

codeSign("ebpfnetsh")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  # Only install the .dll file, without the .lib
  install(
    TARGETS "ebpfnetsh"

    RUNTIME
      DESTINATION "."
      COMPONENT Runtime
  )
endif()