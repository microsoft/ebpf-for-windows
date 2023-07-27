# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_library("api_common" STATIC
  windows_helpers.cpp
  windows_program_type.h

  map_descriptors.hpp
  map_descriptors.cpp

  windows_platform_common.hpp
  windows_platform_common.cpp

  api_common.hpp
  api_common.cpp

  device_helper.hpp
  device_helper.cpp

  store_helper_internal.h
  store_helper_internal.cpp

  utilities.hpp
  utilities.cpp
)

target_include_directories("api_common" PRIVATE
  "${CMAKE_SOURCE_DIR}/libs/api"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_SOURCE_DIR}/include/user"
  "${CMAKE_SOURCE_DIR}/libs/execution_context"
  "${CMAKE_SOURCE_DIR}/libs/platform"
  "${CMAKE_SOURCE_DIR}/libs/platform/user"
  "${CMAKE_SOURCE_DIR}/libs/store_helper"
  "${CMAKE_SOURCE_DIR}/libs/store_helper/user"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/external/ubpf/vm/inc"
  "${CMAKE_BINARY_DIR}/external/ubpf/vm"
  "${CMAKE_SOURCE_DIR}/tests/sample/ext/inc"
  "${CMAKE_SOURCE_DIR}/libs/thunk"
  "${CMAKE_SOURCE_DIR}/external/usersim/inc"
)

target_link_libraries("api_common" PRIVATE
  "ebpf_for_windows_cpp_settings"
  "ebpf_store_helper_um"
  "NetEbpfExt_headers"
  "external::boost"
  "external::ebpfverifier"
)

target_compile_definitions("api_common" PRIVATE
  _WINDOWS
  _USRDLL
  USER_MODE
)

# In order to get around cyclic dependency issues, create an interface
# target that just exports the header files.
#
# This property can later be added back into "api_common" when the
# dependency graph is fixed
add_library("api_common_headers" INTERFACE)
target_include_directories("api_common_headers" SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_link_libraries("api_common" INTERFACE
  "api_common_headers"
)
