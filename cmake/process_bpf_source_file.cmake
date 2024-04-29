# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set (output_dir ${CMAKE_BINARY_DIR}/x64/$<$<CONFIG:Debug>:Debug>$<$<CONFIG:Release>:Release>)

function(add_bpftonative_command file_name kernel_mode unsafe_program)
  find_program(powershell_path "powershell" REQUIRED)
  if (${kernel_mode} STREQUAL "$true")
    set (output_file ${output_dir}/${file_name}.sys)
  else()
    set (output_file ${output_dir}/${file_name}_um.dll)
  endif()

  set(command_line ${powershell_path} -NonInteractive -ExecutionPolicy Unrestricted ${output_dir}/Convert-BpfToNative.ps1 -IncludeDir ${CMAKE_SOURCE_DIR}/include -FileName ${file_name} -OutDir ${output_dir} -Platform x64 -Configuration $(Configuration) -KernelMode ${kernel_mode})

  set (input_file ${output_dir}/${file_name}.o)
  if (${unsafe_program})
    set(output_file $<$<CONFIG:Debug>:${output_file}>$<$<CONFIG:Release>:${dummy}>)
    string(JOIN " " command_line_string ${command_line})
    set(command_line ${command_line} -SkipVerification $true)
    set(input_file $<$<CONFIG:Debug>:${input_file}>$<$<CONFIG:Release>:${dummy}>)
  endif()

  add_custom_command(
    OUTPUT
      ${output_file}
    COMMAND
      ${command_line}
    DEPENDS
      ${input_file}
  )
endfunction()

function(build_bpf_samples unsafe_program)

    find_program(clang_path "clang" NO_CACHE)
    if (${clang_path} STREQUAL "clang_path-NOTFOUND")
      message(WARNING "Could not find clang on the system -- not building bpf samples from high-level source code.")
      return()
    endif()

    file(GLOB files *.c)

    get_filename_component(target_name ${CMAKE_CURRENT_SOURCE_DIR} NAME)

    foreach(file ${files})
      get_filename_component(file_name ${file} NAME_WE)
      set (sources_list ${sources_list}; ${file})
      set (elf_list ${elf_list};${output_dir}/${file_name}.o)
      set (native_driver_list ${native_driver_list}; ${output_dir}/${file_name}.sys; ${output_dir}/${file_name}_um.dll)
      if (${unsafe_program})
        set (native_driver_list $<$<CONFIG:Debug>:${native_driver_list}>$<$<CONFIG:Release>:${dummy}>)
      endif()
    endforeach()

    add_custom_target(${target_name}_elf DEPENDS ${elf_list} SOURCES ${sources_list})

    add_custom_target(${target_name}_native ALL DEPENDS "${native_driver_list}" SOURCES ${elf_list})
    add_dependencies(${target_name}_native ${target_name}_elf "bpf2c")

    set_target_properties(${target_name}_elf PROPERTIES VS_GLOBAL_ClangFlags "-g -target bpf -O2 -Werror")
    set_target_properties(${target_name}_elf PROPERTIES VS_GLOBAL_IncludePath
      "-I${CMAKE_SOURCE_DIR}/include -I${CMAKE_SOURCE_DIR}/external/bpftool -I${CMAKE_SOURCE_DIR}/tests/xdp -I${CMAKE_SOURCE_DIR}/tests/socket -I${CMAKE_SOURCE_DIR}/tests/sample/ext/inc")

    foreach(file ${files})
      get_filename_component(file_name ${file} NAME_WE)
      add_custom_command(
        OUTPUT
          ${output_dir}/${file_name}.o
        COMMAND
          ${clang_path} "$(ClangFlags)" "$(IncludePath)" -c ${CMAKE_CURRENT_SOURCE_DIR}/${file_name}.c -o ${output_dir}/${file_name}.o
        DEPENDS
          ${CMAKE_CURRENT_SOURCE_DIR}/${file_name}.c
      )
      add_bpftonative_command(${file_name} "$true" ${unsafe_program})
      add_bpftonative_command(${file_name} "$false" ${unsafe_program})
    endforeach()
  endfunction()
