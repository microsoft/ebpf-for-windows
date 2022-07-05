# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.20)
project("ebpf-for-windows")

set(EBPFFORWINDOWS_PROGRAM_DATA "" CACHE PATH "Path containing program data")
if(EBPFFORWINDOWS_PROGRAM_DATA STREQUAL "")
  message(FATAL_ERROR "ebpf-for-windows Invalid program data path")
endif()

if(NOT CPACK_GENERATOR)
  message(FATAL_ERROR "ebpf-for-windows - No generator selected")
endif()

set(EBPFFORWINDOWS_VERSION "" CACHE STRING "Package version")
if(EBPFFORWINDOWS_VERSION STREQUAL "")
  message(FATAL_ERROR "ebpf-for-windows - No version has been set")
endif()

set(CPACK_PACKAGE_VERSION "${EBPFFORWINDOWS_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "eBPF implementation that runs on top of Windows.")
set(CPACK_PACKAGE_NAME "${CMAKE_PROJECT_NAME}")
set(CPACK_PACKAGE_VENDOR "Microsoft")
set(CPACK_PACKAGE_CONTACT "opencode@microsoft.com")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/microsoft/ebpf-for-windows")
set(CPACK_PACKAGE_RELOCATABLE ON)
set(CPACK_RESOURCE_FILE_LICENSE "${EBPFFORWINDOWS_PROGRAM_DATA}/LICENSE.txt")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")

#
# Runtime
#

install(
  FILES
    "${EBPFFORWINDOWS_PROGRAM_DATA}/bpftool.exe"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/bpf2c.exe"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpfsvc.exe"

    "${EBPFFORWINDOWS_PROGRAM_DATA}/EbpfApi.dll"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpfnetsh.dll"

    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpf-all.guid"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpf-printk.guid"
    "${EBPFFORWINDOWS_PROGRAM_DATA}/ebpfforwindows.wprp"

    "${EBPFFORWINDOWS_PROGRAM_DATA}/LICENSE.txt"

  DESTINATION
    "."

  COMPONENT
    "Runtime"
)

install(
  DIRECTORY
    "${EBPFFORWINDOWS_PROGRAM_DATA}/drivers"

  DESTINATION
    "."

  COMPONENT
    "Runtime"
)

install(
  DIRECTORY
    "${EBPFFORWINDOWS_PROGRAM_DATA}/scripts"

  DESTINATION
    "."

  COMPONENT
    "Runtime"
)

#
# Development
#

install(
  DIRECTORY
    "${EBPFFORWINDOWS_PROGRAM_DATA}/include"

  DESTINATION
    "."

  COMPONENT
    "Development"
)

install(
  DIRECTORY
    "${EBPFFORWINDOWS_PROGRAM_DATA}/lib"

  DESTINATION
    "."

  COMPONENT
    "Development"
)

#
# Testing and debugging
#

install(
  DIRECTORY
    "${EBPFFORWINDOWS_PROGRAM_DATA}/testing"

  DESTINATION
    "testing"

  COMPONENT
    "Testing"
)

if(CPACK_GENERATOR STREQUAL "WIX")
  set(CPACK_WIX_UPGRADE_GUID "b6bcacb1-c872-4159-abcb-43a50668056c")
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "${CMAKE_PROJECT_NAME}")
  set(CPACK_WIX_EXTENSIONS "WixUtilExtension")
  set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/patch.xml")

elseif(CPACK_GENERATOR STREQUAL "NuGet")
  set(CPACK_NUGET_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
  set(CPACK_NUGET_PACKAGE_AUTHORS "${CPACK_PACKAGE_NAME}")
  set(CPACK_NUGET_PACKAGE_TITLE "${CPACK_PACKAGE_NAME}")
  set(CPACK_NUGET_PACKAGE_OWNERS "${CPACK_PACKAGE_NAME}")
  set(CPACK_NUGET_PACKAGE_COPYRIGHT "Copyright (c) Microsoft Corporation")
  set(CPACK_NUGET_PACKAGE_LICENSEURL "https://raw.githubusercontent.com/microsoft/ebpf-for-windows/main/LICENSE.txt")
  set(CPACK_NUGET_PACKAGE_DESCRIPTION_SUMMARY "${CPACK_NUGET_PACKAGE_DESCRIPTION}")
  set(CPACK_NUGET_PACKAGE_RELEASE_NOTES "${CPACK_PACKAGE_HOMEPAGE_URL}/releases/tag/${CPACK_PACKAGE_VERSION}")
  set(CPACK_NUGET_PACKAGE_TAGS "ebpf bpf windows")

elseif(CPACK_GENERATOR STREQUAL "NSIS")
  set(CPACK_NSIS_DISPLAY_NAME "eBPF for Windows")
  set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/microsoft/ebpf-for-windows#readme")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait 'sc create EbpfCore type=kernel start=demand binpath=%windir%\\system32\\drivers\\ebpfcore.sys'")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait 'sc create NetEbpfExt type=kernel start=demand binpath=%windir%\\system32\\drivers\\netebpfext.sys'")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait '%windir%\\system32\\ebpfsvc.exe install'")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait 'netsh add helper ebpfnetsh.dll'")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait 'sc start EbpfCore'")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait 'sc start NetEbpfExt'")
  list (APPEND CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait 'sc start ebpfsvc'")
  string (REPLACE ";" "\n" CPACK_NSIS_EXTRA_INSTALL_COMMANDS "${CPACK_NSIS_EXTRA_INSTALL_COMMANDS}")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'netsh del helper ebpfnetsh.dll'")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'sc stop ebpfsvc'")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'sc stop NetEbpfExt'")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'sc stop EbpfCore'")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'sc delete ebpfsvc'")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'sc delete NetEbpfExt'")
  list (APPEND CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait 'sc delete EbpfCore'")
  string (REPLACE ";" "\n" CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "${CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS}")

endif()

include(CPack)

cpack_add_component("Runtime"
  DISPLAY_NAME "Runtime components"
  REQUIRED
)

cpack_add_component("Testing"
  DISPLAY_NAME "Testing components"
  DISABLED
)

cpack_add_component("Development"
  DISPLAY_NAME "Development components"
  DISABLED
)
