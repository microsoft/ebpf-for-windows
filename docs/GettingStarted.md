# Getting Started

## Prerequisites

The following must be installed in order to build this project:

1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. [Visual Studio 2019](https://visualstudio.microsoft.com/vs/), including
   the "MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (v14.28)"
   which must be selected as an Individual component in the VS installer
3. [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)
4. [WDK for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854)
5. [Clang/LLVM for Windows 64-bit](https://github.com/llvm/llvm-project/releases/download/llvmorg-8.0.1/LLVM-8.0.1-win64.exe)

## How to clone and build the project

1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows.git```
2. ```cd ebpf-for-windows```
3. ```cmake -S external\ebpf-verifier -B external\ebpf-verifier\build```
4. ```msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-demo.sln```
   or to build from within Visual Studio:
   - Open ebpf-demo.sln
   - Switch to debug / x64
   - Build solution

This will build the following binaries:

* ebpfcore.sys: The kernel-mode execution context in which eBPF programs run.
* ebpfapi.dll: A user-mode shared library exposing APIs for apps to call to perform operations such as
               loading eBPF programs.
* ebpfnetsh.dll: A plugin for the Windows netsh.exe command line tool that provides eBPF command line
                 utility functionality.
* end_to_end.exe: A collection of tests using the Catch framework.  These tests are also run as part
                  of the Github CI/CD so should always pass.

and a few binaries just used for demo'ing eBPF functionality, as in the demo walkthrough discussed below:

* dnsflood.exe: A utility to send 0-byte DNS packets, to illustrate a case that the sample walkthrough uses eBPF
                to defend against.
* port_leak.exe: A "buggy" utility to illustrate the effect of an app that leaks ports.
* port_quota.exe: A sample utility to illustrate using eBPF to manage port quotas to defend against port_leak.exe
                  and similar "buggy" apps.

## Using eBPF for Windows

If you're not already familiar with eBPF, or want a detailed walkthrough, see our [eBPF tutorial](tutorial.md).

This section shows how to use eBPF for Windows in a demo that defends against a 0-byte UDP attack on a DNS server.

### Prep
Set up 2 VMs, which we will refer to as the "attacker" machine and the "defender" machine

On the defender machine, do the following:
1. Install and set up a DNS server
2. Make sure that either the kernel debugger (KD) is attached and running, or one of the [alternatives to running with kernel debugger attached](#alternative-to-running-with-kernel-debugger-attached) is in place
3. Install Debug VS 2019 VC redist from TBD (or switch everything to Multi-threaded Debug (/MTd) and rebuild)
4. Copy ebpfcore.sys to %windir%\system32\drivers
5. Copy ebpfapi.dll and ebpfnetsh.dll to %windir%\system32
6. Do `sc create EbpfCore type=kernel start=boot binpath=%windir%\system32\drivers\ebpfcore.sys`
7. Do `sc start EbpfCore`
8. Do `netsh add helper %windir%\system32\ebpfnetsh.dll`
9. Install [clang](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/LLVM-11.0.0-win64.exe)
10. Copy droppacket.c and ebpf.h to a folder (such as c:\test)

On the attacker machine, do the following:
1. Copy DnsFlood.exe to attacker machine

### Demo
#### On the attacker machine
1. Run ```for /L %i in (1,1,4) do start /min DnsFlood <ip of defender>```

#### On the defender machine
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

## Alternative to running with kernel debugger attached
Windows requires that one of the following criteria be met prior to loading a driver:
1. Driver is signed using a certificate that chains up to the Microsoft code signing root (aka a production signed driver).
2. The OS is booted with a kernel debugger attached.
3. The OS is running in [test-signing mode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option), the [driver is test signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-a-driver-through-an-embedded-signature) and the [test certificate is installed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates).

Official releases of eBPF for Windows will be production signed.
