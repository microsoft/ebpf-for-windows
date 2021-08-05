rem Copyright (c) Microsoft Corporation
rem SPDX-License-Identifier: MIT

rem Stop any eBPF binaries already loaded
sc stop ebpfsvc
sc stop NetEbpfExt
sc stop TestEbpfExt
sc stop EbpfCore

rem Deregister the old binaries
sc delete ebpfsvc
sc delete NetEbpfExt
sc delete TestEbpfExt
sc delete EbpfCore

rem Copy the new binaries to the appropriate system location
copy *.sys %windir%\system32\drivers
copy *.exe %windir%\system32
copy *.dll %windir%\system32

rem Register the binaries
sc create EbpfCore type=kernel start=boot binpath=%windir%\system32\drivers\ebpfcore.sys
sc create NetEbpfExt type=kernel start=boot binpath=%windir%\system32\drivers\netebpfext.sys
sc create TestEbpfExt type=kernel start=demand binpath=%windir%\system32\drivers\test_ebpf_ext.sys
%windir%\system32\ebpfsvc.exe install
netsh add helper %windir%\system32\ebpfnetsh.dll

rem Start the binaries
sc start EbpfCore
sc start NetEbpfExt
sc start TestEbpfExt
sc start ebpfsvc
