@echo off
rem Copyright (c) eBPF for Windows contributors
rem SPDX-License-Identifier: MIT
rem
rem Usage: create_verifier_corpus.bat <solution_path> <output_directory>

set SOLUTIONPATH=%1
set OUTPUTPATH=%2
xcopy /d /i /y "%SOLUTIONPATH%\external\ebpf-verifier\ebpf-samples\build" "%OUTPUTPATH%"
xcopy /d /i /y "%SOLUTIONPATH%\external\ebpf-verifier\ebpf-samples\invalid" "%OUTPUTPATH%"
xcopy /d /i /y "%SOLUTIONPATH%\external\ebpf-verifier\ebpf-samples\linux" "%OUTPUTPATH%"
xcopy /d /i /y "%SOLUTIONPATH%\external\ebpf-verifier\ebpf-samples\prototype-kernel" "%OUTPUTPATH%"
xcopy /d /i /y "%SOLUTIONPATH%\external\ebpf-verifier\ebpf-samples\suricata" "%OUTPUTPATH%"
