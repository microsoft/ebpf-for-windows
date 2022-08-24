# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

add_subdirectory("ebpf-verifier" EXCLUDE_FROM_ALL)
add_subdirectory("Catch2" EXCLUDE_FROM_ALL)
add_subdirectory("ubpf" EXCLUDE_FROM_ALL)

# Special target that we can link to external dependencies
# to override build settings
add_library("ebpf_for_windows_external_settings" INTERFACE)
target_compile_options("ebpf_for_windows_external_settings" INTERFACE
  "/w"
)

target_compile_definitions("ebpf_for_windows_external_settings" INTERFACE
  "_CRT_SECURE_NO_WARNINGS"
  "_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS"
)

#
# Catch2
#

target_link_libraries("Catch2" PRIVATE
  "ebpf_for_windows_external_settings"
)

#
# ebpfverifier
#

target_link_libraries("ebpfverifier" PRIVATE
  "ebpf_for_windows_external_settings"
)

# Fix missing INTERFACE include directories
target_include_directories("ebpfverifier" INTERFACE
  ebpf-verifier/src
  ebpf-verifier/external/elfio
)

# Fix missing dependency between ebpfverifier and yaml-cpp
add_dependencies("ebpfverifier"
  "yaml-cpp"
)

add_library("external::ebpfverifier" ALIAS "ebpfverifier")

# Some targets end up requiring ebpfverifier by mistake due to
# the ebpf_program_types.h header. For now, create an interface
# target just to export the include directory
add_library("ebpfverifier_headers" INTERFACE)
target_include_directories("ebpfverifier_headers" INTERFACE
  ebpf-verifier/src
)

add_library("external::ebpfverifier_headers" ALIAS "ebpfverifier_headers")

#
# boost (downloaded by ebpfverifier)
#

add_library("boost" INTERFACE)
target_include_directories("boost" INTERFACE
  "${CMAKE_BINARY_DIR}/packages/boost/lib/native/include"
)

add_library("external::boost" ALIAS "boost")

#
# libbpf
#

# This target has been split from bpftool, since its headers
# are also referenced by the 'api' target
add_library("libbpf"
  bpftool/libbpf/src/hashmap.c
  bpftool/libbpf/src/libbpf.c
)

target_include_directories("libbpf" PUBLIC
  "${CMAKE_SOURCE_DIR}/external/bpftool"
  "${CMAKE_SOURCE_DIR}/external/bpftool/libbpf/src"
  "${CMAKE_SOURCE_DIR}/external/bpftool/libbpf/include"
  "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries("libbpf"
  PRIVATE
    "ebpf_for_windows_external_settings"
    "ebpf_for_windows_common_settings"

  PUBLIC
    "external::ebpfverifier"
)

target_compile_definitions("libbpf" PUBLIC
  BPFTOOL_VERSION="0.1"
  _CONSOLE
)

add_library("external::libbpf" ALIAS "libbpf")

#
# bpftool
#

add_executable("bpftool"
  win-c/source/getopt.c

  bpftool/src/common.c
  bpftool/src/json_writer.c
  bpftool/src/link.c
  bpftool/src/main.c
  bpftool/src/map.c
  bpftool/src/net.c
  bpftool/src/prog.c
  bpftool/src/windows/platform.c
)

target_include_directories("bpftool" PRIVATE
  "${CMAKE_SOURCE_DIR}/external/win-c/include"
)

target_link_libraries("bpftool" PRIVATE
  "ebpf_for_windows_external_settings"
  "ebpf_for_windows_common_settings"
  "EbpfApi"
  "external::libbpf"

  iphlpapi.lib
  kernel32.lib
  user32.lib
  gdi32.lib
  winspool.lib
  comdlg32.lib
  advapi32.lib
  shell32.lib
  ole32.lib
  oleaut32.lib
  uuid.lib
  odbc32.lib
  odbccp32.lib
)

add_executable("external::bpftool" ALIAS "bpftool")

codeSign("bpftool")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    TARGETS "bpftool"
    DESTINATION "."
  )

  set(include_dir_list
    "asm"
    "linux"
    "uapi"
  )

  foreach(include_dir ${include_dir_list})
    install(
      DIRECTORY "bpftool/libbpf/include/${include_dir}"
      DESTINATION "include/libbpf"
    )
  endforeach()
endif()
