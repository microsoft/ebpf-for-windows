# eBPF on Windows

eBPF is a well-known technology for providing programmability and agility, especially for extending an
OS kernel, for use cases such as DoS protection and observability. This project allows using existing eBPF
toolchains and APIs familiar in the Linux ecosystem to be used on top of Windows.  That is, this project
takes existing eBPF projects (as submodules) and adds the layer in between to make them run on top of Windows.

## New to eBPF?

See our [eBPF tutorial](docs/tutorial.md).

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
4. ```msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln```
   or to build from within Visual Studio:
   - Open ebpf-for-windows.sln
   - Switch to debug / x64
   - Build solution

## Using eBPF for Windows

This section shows how to use eBPF for Windows in a demo that defends against a 0-byte UDP attack on a DNS server.

### Prep 
Set up 2 VMs, which we will refer to as the "attacker" machine and the "defender" machine

On the defender machine, do the following:
1. Install and set up a DNS server
2. Make sure the kernel debugger (KD) is attached and running.
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

## Frequently Asked Questions

### 1. Is this a fork of eBPF?

The Linux kernel contains an eBPF execution environment, hooks, helpers, a JIT compiler, verifier, interpreter, etc.
That code is GPL licensed and so cannot be used for purposes that require a more permissive license.

For that reason, there are various projects in the eBPF community that have permissive licenses, such as
the [IOVisor uBPF project](https://github.com/iovisor/ubpf),
the [Prevail verifier](https://github.com/vbpf/ebpf-verifier),
and the [generic-ebpf project](https://github.com/generic-ebpf/generic-ebpf), among others.

The eBPF for Windows project leverages existing permissive licensed projects, including uBPF and the Prevail
verifier, running them on top of Windows by adding the Windows-specific hosting environment for that code.
Similarly, it provides Windows-specific hooks and helpers, along with non-GPL'ed hooks/helpers that are
common across Linux, Windows, and other platforms.

### 2. Does this provide app compatibility with eBPF programs written for Linux?

Linux provides *many* hooks and helpers, most of which are GPL-licensed but some are more permissively
licensed.  The intent is to provide source code compatibility for code that only uses permissively
licensed hooks and helpers.  The GPL-licensed hooks and helpers tend to be very Linux specific (e.g., using
Linux internal data structs) that would not be applicable to other platforms anyway, including other
platforms supported by the [generic-ebpf project](https://github.com/generic-ebpf/generic-ebpf).

### 3. Will eBPF work with HyperVisor-enforced Code Integrity (HVCI)?

eBPF programs can be run either in an interpreter or natively using a JIT compiler.

[HyperVisor-enforced Code Integrity (HVCI)](https://techcommunity.microsoft.com/t5/windows-insider-program/virtualization-based-security-vbs-and-hypervisor-enforced-code/m-p/240571)
whereby a hybervisor, such as Hyper-V, uses hardware virtualization to protect kernel-mode processes against
the injection and execution of malicious or unverified code. Code integrity validation is performed in a secure
environment that is resistant to attack from malicious software, and page permissions for kernel mode are set and
maintained by the hypervisor.

Since a hypervisor doing such code integrity checks will refuse to accept code pages that aren't signed by
a key that the hypervisor trusts, this does impact eBPF programs running natively.  As such, currently
eBPF programs work fine in interpreted mode, but not when using JIT compilation, regardless of whether
one is using Linux or Windows.
