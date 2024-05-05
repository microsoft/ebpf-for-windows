# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

function(locateMidlCompiler)
  file(GLOB_RECURSE midl_path_list
    "C:/Program Files (x86)/Windows Kits/10/bin/*/x64/midl.exe"
  )

  list(SORT midl_path_list)

  foreach(midl_path ${midl_path_list})
    get_filename_component(parent_midl_path "${midl_path}" DIRECTORY)
    list(APPEND midl_path_hints "${parent_midl_path}")
  endforeach()

  message(STATUS "ebpf-for-windows: Attempting to locate midl.exe using the following hints: ${midl_path_hints}")

  find_program(MIDL_COMPILER_PATH "midl.exe"
    HINTS ${midl_path_hints}
    REQUIRED
  )
endfunction()
