# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20)
# It is necessary to set this before the first project directive.
# Use the CMAKE_SYSTEM_VERSION directive to select the SDK version.
# The docs/GettingStarted.md guide points developers to the 2004 version of the
# SDK which corresponds to 19041.
set(CMAKE_SYSTEM_VERSION 10.0.19041.0)

project("ebpf-for-windows")

include("cmake/options.cmake")
include("cmake/settings.cmake")
include("cmake/git_commit.cmake")
include("cmake/codesign.cmake")
include("cmake/midl_compiler_finder.cmake")

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/FindWDK/cmake"
)

locateMidlCompiler()
find_package(WDK REQUIRED)

add_subdirectory("external")
add_subdirectory("rpc_interface")
add_subdirectory("ebpfapi")
add_subdirectory("libs")
add_subdirectory("tools")
add_subdirectory("ebpfsvc")
add_subdirectory("netebpfext")
add_subdirectory("ebpfcore")
add_subdirectory("scripts")

if(EBPFFORWINDOWS_ENABLE_TESTS)
  include("CTest")
  enable_testing()

  add_subdirectory("tests")
endif()

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    DIRECTORY "include"
    DESTINATION "."
  )

  install(
    FILES "LICENSE.txt"
    DESTINATION "."
  )
endif()