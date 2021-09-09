rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT

rem Stop any eBPF binaries already loaded
sc stop ebpfsvc
sc stop NetEbpfExt
sc stop SampleEbpfExt
sc stop EbpfCore

rem Deregister the old binaries
sc delete ebpfsvc
sc delete NetEbpfExt
sc delete SampleEbpfExt
sc delete EbpfCore

rem Copy the new binaries to the appropriate system location
copy *.sys %windir%\system32\drivers
copy *.exe %windir%\system32
copy *.dll %windir%\system32

rem Register the binaries
sc create EbpfCore type=kernel start=demand binpath=%windir%\system32\drivers\ebpfcore.sys
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
sc create NetEbpfExt type=kernel start=demand binpath=%windir%\system32\drivers\netebpfext.sys
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
sc create SampleEbpfExt type=kernel start=demand binpath=%windir%\system32\drivers\sample_ebpf_ext.sys
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
%windir%\system32\ebpfsvc.exe install
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
netsh add helper %windir%\system32\ebpfnetsh.dll
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%

rem Start the binaries
sc start EbpfCore
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
sc start NetEbpfExt
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
sc start SampleEbpfExt
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
sc start ebpfsvc
if NOT ERRORLEVEL 0 exit %ERRORLEVEL%
