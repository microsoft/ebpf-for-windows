# Copyright (c) eBPF for Windows contributors
# SPDX-License-Identifier: MIT

set (output_dir ${CMAKE_BINARY_DIR}/x64/$<$<CONFIG:Debug>:Debug>$<$<CONFIG:Release>:Release>)

set (ucrtbased_dll $<$<CONFIG:Debug>:${output_dir}/ucrtbased.dll>)

set (output_ucrtbased_dll $<$<CONFIG:Debug>:${ucrtbased_dll}>)

set (misc_files "setup-ebpf.ps1"
    "run_tests.bat"
    "common.psm1"
    "config_test_vm.psm1"
    "setup_ebpf_cicd_tests.ps1"
    "execute_ebpf_cicd_tests.ps1"
    "cleanup_ebpf_cicd_tests.ps1"
    "install_ebpf.psm1"
    "run_driver_tests.psm1"
    "test_execution.json"
    "vm_run_tests.psm1"
    "ebpfforwindows.wprp"
    "ebpf-all.guid"
    "ebpf-printk.guid"
    "net-ebpf-ext.guid"
)

foreach(file ${misc_files})
    set( input_misc_files ${input_misc_files} "${CMAKE_SOURCE_DIR}/scripts/${file}")
    set( output_misc_files ${output_misc_files} "${output_dir}/${file}")
endforeach()

set (dependency_list ${CMAKE_SOURCE_DIR}/scripts/pre-commit;
        ${CMAKE_SOURCE_DIR}/include/git_commit_id.h;
        "${output_ucrtbased_dll}"
        "${output_misc_files}")

add_custom_target(setup_build ALL DEPENDS "${dependency_list}")

find_program(powershell_path "powershell" REQUIRED)

add_custom_command(
    OUTPUT
        ${CMAKE_SOURCE_DIR}/scripts/pre-commit
    COMMAND
        ${powershell_path} -NonInteractive -ExecutionPolicy Unrestricted ${CMAKE_SOURCE_DIR}/scripts/copy_pre_commit.ps1 ${CMAKE_SOURCE_DIR}/scripts/pre-commit
)

add_custom_command(
    OUTPUT
        ${CMAKE_SOURCE_DIR}/include/git_commit_id.h
    COMMAND
        ${powershell_path} -NonInteractive -ExecutionPolicy Unrestricted ${CMAKE_SOURCE_DIR}/scripts/generate-commitid.ps1 ${CMAKE_SOURCE_DIR}/include
)

add_custom_command(
    OUTPUT
        "${output_redist_bins}"
    COMMAND
        ${CMAKE_COMMAND} -E copy_directory \"${input_redist_bins}\" ${output_dir}
)

add_custom_command(
    OUTPUT
        "${output_ucrtbased_dll}"
    COMMAND
        ${CMAKE_COMMAND} -E copy \"$(UniversalDebugCRT_ExecutablePath_x64)/ucrtbased.dll\" ${output_dir}
)

add_custom_command (
    OUTPUT
        "${output_misc_files}"
    COMMAND
        ${CMAKE_COMMAND} -E copy ${input_misc_files} ${output_dir}
)
