@echo off
rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT

@echo ==============================
@echo Cleanup & Populate eBPF Store.
@echo ==============================
export_program_info.exe --clear
export_program_info.exe
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