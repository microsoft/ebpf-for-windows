@echo off
rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT
rem
rem Usage: create_bpf2c_corpus.bat <output_directory>

set OUTPUTPATH=%1
xcopy /d /i /y "%OUTPUTPATH%\*.o" "%OUTPUTPATH%\bpf2c_fuzzer_corpus"
