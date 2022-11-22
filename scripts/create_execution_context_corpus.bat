@echo off
rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT
rem
rem Usage: create_core_helper_corpus.bat <solution_path> <output_directory>

set SOLUTIONPATH=%1
set OUTPUTPATH=%2
powershell Expand-Archive -Path "%SOLUTIONPATH%\tests\libfuzzer\execution_context\corpus.zip" -DestinationPath "%OUTPUTPATH%" -Force
