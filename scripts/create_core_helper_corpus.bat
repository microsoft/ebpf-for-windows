@echo off
rem Copyright (c) eBPF for Windows contributors
rem SPDX-License-Identifier: MIT
rem
rem Usage: create_core_helper_corpus.bat <solution_path> <output_directory>

set SOLUTIONPATH=%1
set OUTPUTPATH=%2
xcopy /d /i /y "%SOLUTIONPATH%\tests\libfuzzer\core_helper_fuzzer\corpus" "%OUTPUTPATH%"
