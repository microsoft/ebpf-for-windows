@echo off
rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT
if [%1]==[] (
    set /A install=1
    goto :INSTALL
)
if "%1" == "/noinstall" (
    set /A install=0
) else (
    goto :USAGE
)
:INSTALL
if %install% == 1 (
    @echo Installing eBPF components.
    call .\install-ebpf.bat
)
@echo =====================
@echo Executing Unit Tests.
@echo =====================
.\unit_tests.exe
@echo ===========================
@echo Executing RPC Client Tests.
@echo ===========================
.\ebpf_client.exe
@echo ====================
@echo Executing API Tests.
@echo ====================
.\api_test.exe
@echo =================================
@echo Executing Sample Extension Tests.
@echo =================================
.\sample_ext_app.exe
goto EOF
:USAGE
@echo Usage: run_tests /noinstall
:EOF
