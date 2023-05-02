# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("netsh_static" STATIC
  tokens.h

  elf.h
  elf.cpp

  links.h
  links.cpp

  pins.h
  pins.cpp

  processes.h
  processes.cpp

  programs.h
  programs.cpp

  utilities.h
  utilities.cpp

  maps.h
  maps.cpp
)

target_include_directories("netsh_static" PRIVATE
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
)

target_link_libraries("netsh_static"
  PRIVATE
    "ebpf_for_windows_cpp_settings"

  PUBLIC
    "external::libbpf"
)

target_compile_definitions("netsh_static" PRIVATE
  _LIB
)
