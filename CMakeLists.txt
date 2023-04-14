# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20)
# It is necessary to set this before the first project directive.
# Use the CMAKE_SYSTEM_VERSION directive to select the SDK version.
# The docs/GettingStarted.md guide points developers to the 2004 version of the
# SDK which corresponds to 22621.
set(CMAKE_SYSTEM_VERSION 10.0.22621.0)

# Uncomment the following line for debugging project dependencies.
# set_property(GLOBAL PROPERTY GLOBAL_DEPENDS_DEBUG_MODE 1)

project("ebpf-for-windows")

include("cmake/options.cmake")
include("cmake/settings.cmake")
include("cmake/git_commit.cmake")
include("cmake/codesign.cmake")
include("cmake/midl_compiler_finder.cmake")
include("cmake/process_bpf_source_file.cmake")

list(APPEND CMAKE_MODULE_PATH
  "${CMAKE_SOURCE_DIR}/external/FindWDK/cmake"
)

locateMidlCompiler()
find_package(WDK REQUIRED)

add_subdirectory("ebpfapi")
add_subdirectory("ebpfcore")
add_subdirectory("ebpfsvc")
add_subdirectory("external")
add_subdirectory("libs")
add_subdirectory("netebpfext")
add_subdirectory("rpc_interface")
add_subdirectory("scripts")
add_subdirectory("tools")

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