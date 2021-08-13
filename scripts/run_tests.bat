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
@echo Executing Unit Tests.
.\unit_tests.exe
@echo Executing RPC Client Tests.
.\ebpf_client.exe
@echo Executing API Tests.
.\api_test.exe
goto EOF
:USAGE
@echo Usage: run_tests /noinstall