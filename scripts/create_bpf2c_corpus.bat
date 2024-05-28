@echo off
rem Copyright (c) eBPF for Windows contributors
rem SPDX-License-Identifier: MIT
rem
rem Usage: create_bpf2c_corpus.bat <output_directory>
echo set OUTPUTPATH=%1
set OUTPUTPATH=%1
rem Strip the \ from the end of the path if present.
if %OUTPUTPATH:~-1% EQU \ set OUTPUTPATH=%OUTPUTPATH:~0,-1%
xcopy /d /i /y "%OUTPUTPATH%\*.o" "%OUTPUTPATH%\bpf2c_fuzzer_corpus"
