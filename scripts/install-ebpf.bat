rem Copyright (c) Microsoft Corporation 
rem SPDX-License-Identifier: MIT
rem Run "install-ebpf.bat" to install runtime services only.
rem Run "install-ebpf.bat /t" to install runtime services and SampleEbpfExt service.

set option=%1
Set WithSampleExt=false

IF "%option%"=="" (
   rem Do nothing.
) ELSE (
  IF "%option%"=="/t" (
    SET WithSampleExt=true
  ) ELSE (
    rem Parameter %* is not a valid option.
    GOTO:EOF
  )
)

rem Stop any eBPF binaries already loaded
sc stop ebpfsvc
sc stop NetEbpfExt
IF "%WithSampleExt%"=="true" (
  sc stop SampleEbpfExt
)
sc stop EbpfCore

rem Deregister the old binaries
sc delete ebpfsvc
sc delete NetEbpfExt
IF "%WithSampleExt%"=="true" (
  sc delete SampleEbpfExt
)
sc delete EbpfCore

rem Copy the new binaries to the appropriate system location
copy *.sys %windir%\system32\drivers
copy *.exe %windir%\system32
copy *.dll %windir%\system32

rem Register the binaries
sc create EbpfCore type=kernel start=demand binpath=%windir%\system32\drivers\ebpfcore.sys
@if ERRORLEVEL 1 goto EOF
sc create NetEbpfExt type=kernel start=demand binpath=%windir%\system32\drivers\netebpfext.sys
@if ERRORLEVEL 1 goto EOF
IF "%WithSampleExt%"=="true" (
  sc create SampleEbpfExt type=kernel start=demand binpath=%windir%\system32\drivers\sample_ebpf_ext.sys
  @if ERRORLEVEL 1 goto EOF
)
%windir%\system32\ebpfsvc.exe install
@if ERRORLEVEL 1 goto EOF
netsh add helper %windir%\system32\ebpfnetsh.dll
@if ERRORLEVEL 1 goto EOF

rem Start the binaries
sc start EbpfCore
@if ERRORLEVEL 1 goto EOF
sc start NetEbpfExt
@if ERRORLEVEL 1 goto EOF
IF "%WithSampleExt%"=="true" (
  sc start SampleEbpfExt
  @if ERRORLEVEL 1 goto EOF
)
sc start ebpfsvc
@if ERRORLEVEL 1 goto EOF
:EOF
