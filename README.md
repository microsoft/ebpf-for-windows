# eBPF on Windows

## Prerequisites

The following must be installed in order to build this project:

1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. [Visual Studio 2019](https://visualstudio.microsoft.com/vs/), including
   the "MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (v14.28)"
   which must be selected as an Individual component in the VS installer
3. [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)
4. [WDK for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854)
5. [Clang/LLVM for Windows 64-bit](https://github.com/llvm/llvm-project/releases/download/llvmorg-8.0.1/LLVM-8.0.1-win64.exe)

## How to build the demo project

1. ```git clone -b demo --recurse-submodules https://msazure.visualstudio.com/DefaultCollection/One/_git/EdgeOS-CoreNetworking-WindowsEbpf```
2. ```cd EdgeOS-CoreNetworking-WindowsEbpf```
2. ```cd external\ebpf-verifier```
3. ```cmake -B build```
4. ```cd ..\..```
5. Open ebpf-demo.sln
6. Switch to debug / x64
7. Build solution

## Demo script

### Prep 
1. Setup 2 VMs, attacker and defender
2. On defender, install and setup DNS
3. On defender, make sure KD is attached and running.
1. Install Debug VS 2019 VC redist from TBD (or switch everything to Multi-threaded Debug (/MTd) and rebuild)
2. Copy ebpfcore.sys to %windir%\system32
3. Copy ebpfapi.dll and ebpfnetsh.dll to %windir%\system32
4. sc create EbpfCore type=kernel start=boot binpath=%windir%\system32\drivers\ebpfcore.sys
5. sc start EbpfCore
6. netsh add helper %windir%\system32\ebpfnetsh.dll
7. Install [clang](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/LLVM-11.0.0-win64.exe)
8. Copy droppacket.c and ebpf.h to a folder (like c:\test)


### Demo
#### On attacker machine
1. Copy DnsFlood.exe to attacker machine
2. Run ```for /L %i in (1,1,4) do start /min DnsFlood <ip of defender>```

#### On defender machine
1. Start perfomance monitor and add UDPv4 Datagrams/sec
2. Show that 200K packets per second are being received
3. Show & explain code of droppacket.c 
4. Compile droppacket.c ```clang -target bpf -O2 -Wall -c droppacket.c -o droppacket.o```
5. Show eBPF byte code for droppacket.o ```netsh ebpf show disassembly droppacket.o xdp```
6. Show that the verifier checks the code ```netsh ebpf show verification droppacket.o xdp```
7. Launch netsh ```netsh```
8. Switch to ebpf context ```ebpf```
9. Load eBPF program ```add program droppacket.o xdp```
10. Show UDP datagrams received drop to under 10 per second
11. Unload program ```delete program droppacket.o xdp```
12. Show UDP datagrams received drop to back up to ~200K per second
13. Modify droppacket.c to be unsafe - Comment out line 20 & 21
14. Compile droppacket.c ```clang -target bpf -O2 -Wall -c droppacket.c -o droppacket.o```
15. Show that the verifier rejects the code ```netsh ebpf show verification droppacket.o xdp```
16. Show that loading the program fails ```netsh ebpf add program droppacket.o xdp```
