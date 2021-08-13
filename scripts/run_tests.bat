rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT
@echo The script assumes install-ebpf.bat has already been run.
@echo Executing Unit Tests.
.\unit_tests.exe
@echo Executing RPC Client Tests.
.\ebpf_client.exe
@echo Executing API Tests.
.\api_test.exe