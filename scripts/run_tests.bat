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
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
@echo ===========================
@echo Executing RPC Client Tests.
@echo ===========================
.\ebpf_client.exe
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
@echo ====================
@echo Executing API Tests.
@echo ====================
.\api_test.exe
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
@echo =================================
@echo Executing Sample Extension Tests.
@echo =================================
.\sample_ext_app.exe
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
goto EOF
:USAGE
@echo Usage: run_tests /noinstall
:EOF
