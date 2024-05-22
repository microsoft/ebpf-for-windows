# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

add_subdirectory("setup_build")

if(EBPFFORWINDOWS_ENABLE_INSTALL)
  install(
    FILES
      "install-ebpf.bat"
      "uninstall-ebpf.bat"

    DESTINATION
      "scripts"
  )
endif()
