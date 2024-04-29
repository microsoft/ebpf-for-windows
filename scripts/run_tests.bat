@echo off
rem Copyright (c) eBPF for Windows contributors
rem SPDX-License-Identifier: MIT

@echo ==============================
@echo Clean up & Populate eBPF Store.
@echo ==============================
export_program_info.exe --clear
export_program_info.exe
export_program_info_sample.exe --clear
export_program_info_sample.exe
@echo =====================
@echo Executing Unit Tests.
@echo =====================
.\unit_tests.exe
@if ERRORLEVEL 1 goto EOF
@echo ====================
@echo Executing API Tests.
@echo ====================
.\api_test.exe
@if ERRORLEVEL 1 goto EOF
@echo =================================
@echo Executing Sample Extension Tests.
@echo =================================
.\sample_ext_app.exe
@if ERRORLEVEL 1 goto EOF
@echo ====================
@echo Executing Bpftool Tests.
@echo ====================
.\bpftool_tests.exe
@if ERRORLEVEL 1 goto EOF
goto EOF

:SUCCESS
@echo TESTS PASSED!
:EOF
