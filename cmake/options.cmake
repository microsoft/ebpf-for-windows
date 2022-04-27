# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

set(CMAKE_SYSTEM_VERSION 10.0.19041.0)
set(CMAKE_CXX_STANDARD 20)

option(EBPFFORWINDOWS_ENABLE_TESTS "Set to true to enable tests" true)
option(EBPFFORWINDOWS_ENABLE_INSTALL "Set to true to enable the install target")
option(EBPFFORWINDOWS_ENABLE_DISABLE_EBPF_INTERPRETER "Set to true to compile with the interpreter always disabled")

set(EBPFFORWINDOWS_CODESIGN_CERTIFICATE_PATH "" CACHE STRING "Path to the certificate used for signing")
set(EBPFFORWINDOWS_CODESIGN_PASSWORD_ENV_VAR "" CACHE STRING "Name of the environment variable containing the certificate password")

set(EBPFFORWINDOWS_WDK_WINVER "0x0A00" CACHE STRING "WINVER value passed to the Windows Driver Kit. Defaults to Windows 10 (0x0A00)")
set(EBPFFORWINDOWS_WDK_KMDF_VERSION "1.15" CACHE STRING "KMDF version used for drivers. Defaults to 1.15")

if(EXISTS "${EBPFFORWINDOWS_CODESIGN_CERTIFICATE_PATH}")
  set(codesign_enabled true)
else()
  set(codesign_enabled false)
endif()

message(STATUS "ebpf-for-windows - Tests: ${EBPFFORWINDOWS_ENABLE_TESTS}")
message(STATUS "ebpf-for-windows - Install targets: ${EBPFFORWINDOWS_ENABLE_INSTALL}")
message(STATUS "ebpf-for-windows - eBPF interpreter disabled: ${EBPFFORWINDOWS_ENABLE_DISABLE_EBPF_INTERPRETER}")
message(STATUS "ebpf-for-windows - Code signing enabled: ${codesign_enabled}")
message(STATUS "ebpf-for-windows - WDK_WINVER: ${EBPFFORWINDOWS_WDK_WINVER}")
message(STATUS "ebpf-for-windows - KMDF version: ${EBPFFORWINDOWS_WDK_KMDF_VERSION}")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/Program Files/${CMAKE_PROJECT_NAME}" CACHE PATH "" FORCE)
  endif()

  message(STATUS "ebpf-for-windows - CMAKE_INSTALL_PREFIX set to ${CMAKE_INSTALL_PREFIX}")
endif()
