# Getting Started

## Prerequisites

The following must be installed in order to build this project:

1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. [Visual Studio 2019](https://visualstudio.microsoft.com/vs/), including
   the "MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (v14.28)"
   which must be selected as an Individual component in the VS installer
3. [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)
4. [WDK for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854)
5. [Clang for Windows 64-bit version 10.0.0](https://github.com/llvm/llvm-project/releases/download/llvmorg-10.0.0/LLVM-10.0.0-win64.exe) or [The latest release of Clang for Windows 64-bit](https://github.com/llvm/llvm-project/releases/latest)
6. [nuget.exe](https://www.nuget.org/downloads)

## How to clone and build the project

1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows.git```
2. ```cd ebpf-for-windows```
3. ```cmake -S external\ebpf-verifier -B external\ebpf-verifier\build```
4. ```msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln```
   or to build from within Visual Studio:
   - Open ebpf-for-windows.sln
   - Switch to debug / x64
   - Build solution

This will build the following binaries:

* ebpfcore.sys: The kernel-mode execution context in which eBPF programs run.
* netebpfext.sys: The kernel-mode extension for WFP hooks.
* ebpfapi.dll: A user-mode shared library exposing APIs for apps to call to perform operations such as
               loading eBPF programs.
* ebpfnetsh.dll: A plugin for the Windows netsh.exe command line tool that provides eBPF command line
                 utility functionality.
* ebpfsvc.exe: A user-mode service that verifies and loads an eBPF program in the execution context.
* unit_tests.exe: A collection of tests using the Catch framework.  These tests are also run as part
                  of the Github CI/CD so should always pass.
* ebpf_client.exe: A collection of program verification tests that exercises the RPC channel from client to ebpfsvc.
                   These tests are also run as part of the Github CI/CD so should always pass.
* api_test.exe: A collection of tests that exercises eBPF user mode APIs. This requires EbpSvc service to be running,
                and EbpCore and NetEbpfExt drivers to be loaded.
* sample_ebpf_ext.sys: A sample eBPF extension driver that implements a test hook (for a test program type) and test helper functions.
* sample_ext_app.exe : A sample application for testing the sample extension driver.
* xdp_tests.exe : Application for testing various XDP functionalities.  This requires the EbpSvc service to be running,
                and the EbpCore and NetEbpfExt drivers to be loaded on a remote system to test.

and a few binaries just used for demo'ing eBPF functionality, as in the demo walkthrough discussed below:

* dnsflood.exe: A utility to send 0-byte DNS packets, to illustrate a case that the sample walkthrough uses eBPF
                to defend against.
* port_leak.exe: A "buggy" utility to illustrate the effect of an app that leaks ports.
* port_quota.exe: A sample utility to illustrate using eBPF to manage port quotas to defend against port_leak.exe
                  and similar "buggy" apps.

## Installing eBPF for Windows

Windows requires that one of the following criteria be met prior to loading a driver:
a. Driver is signed using a certificate that chains up to the Microsoft code signing root (aka a production signed driver).
b. The OS is booted with a kernel debugger attached.
c. The OS is running in [test-signing mode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option), the [driver is test signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-a-driver-through-an-embedded-signature) and the [test certificate is installed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates).

Since the binaries built above are not signed by Microsoft, they will only work on a machine with
a kernel debugger (KD) attached and running, or test signing is enabled. (It is expected that official
releases of eBPF for Windows will eventually be production signed at some point in the future after
security hardening is completed.)

Ensure that the matching versions of the Microsoft C Runtime are installed on the machine. Versions of the Microsoft C Runtime are available on the developer machine, located in %ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Redist\MSVC\version, where version is updated with each patch of Visual Studio.

With version 14.29.30133, the full path is:
1) Release - ```%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Redist\MSVC\14.29.30133\vc_redist.x64.exe```
2) Debug - ```%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Redist\MSVC\14.29.30133\debug_nonredist\x64\Microsoft.VC142.DebugCRT```

For basic testing, the simplest way to install eBPF for Windows is into a Windows VM with test signing enabled.
Follow the [VM Installation Instructions](vm-setup.md) to do so.

## Using eBPF for Windows

If you're not already familiar with eBPF, or want a detailed walkthrough, see our [eBPF tutorial](tutorial.md).

For API documentation, see https://microsoft.github.io/ebpf-for-windows/

This section shows how to use eBPF for Windows in a demo that defends against a 0-byte UDP attack on a DNS server.

### Prep
Set up 2 VMs, which we will refer to as the "attacker" machine and the "defender" machine.

On a defender machine with [eBPF installed](#installing-ebpf-for-windows), do the following:

1. Install and set up a DNS server.
2. Make sure that either test signing was enabled as discussed in
   [Installing eBPF for Windows](#installing-ebpf-for-windows), or the kernel debugger (KD) is attached and running.
3. Install [clang](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.0/LLVM-11.0.0-win64.exe)
   if not already installed on the defender machine.
4. Copy droppacket.c and ebpf.h to a folder (such as c:\test).

On the attacker machine, do the following:
1. Copy DnsFlood.exe to attacker machine

### Demo
#### On the attacker machine
1. Run ```for /L %i in (1,1,4) do start /min DnsFlood <ip of defender>```

#### On the defender machine
1. Start performance monitor and add UDPv4 Datagrams/sec
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

## Tests in Ebpf-For-Windows

The tests in Ebpf-For-Windows are written using the [Catch2](https://github.com/catchorg/Catch2) test framework.

### unit_tests.exe
This test uses a mocking layer to bind the user mode components to the kernel mode
components via a Mock IOCTL interface. The tests initialize the user mode and kernel
mode components, load an eBPF program from an ELF file, and then run the eBPF program
by having the mocked extensions emit events.

### ebpf_client.exe
This test does verification for different sample programs by parsing the ELF file and
sending the verification request to ebpfsvc. For the cases when the verification fails,
the test receives and prints the verifier failure message.
If ebpfsvc is not already installed, this test tries to install and start the service before
executing the tests, hence this test should be run as admin if ebpfsvc is not already installed
and running.

### api_test.exe
This test exercises various eBPF user mode eBPF APIs, including those to load programs,
enumerate maps and programs etc. This test requires the eBPF user mode service (EbpfSvc), and the
kernel execution context (EbpfCore.sys) and the Network Extension (NetEbpfExt.sys) to be running.
This test is currently *not* part of the CI pipeline. Developers must run this test manually before
checking in changes.

### sample_ext_app.exe
This is a test application for the sample eBPF extension. This application loads a test eBPF program
and attaches it to the test hook implemented by the sample extension and validates if the eBPF program
executed as expected.

### Running the tests
1.	Set the build output folder as the current working directory.
2.	Invoke the appropriate exe.

The Catch2 exes have various command line options to control behavior. Default
behavior is to run all the tests and only print information about failing test
cases.

Other useful options include:
1.	-s to list both passing and failing test cases
2.	-b to break into the debugger on test failure
3.	-l to list test cases
4.	Test_name to run a single test

### xdp_tests.exe
This application tests various XDP functionalities. It has the following tests:
1. Reflection Test: This tests the XDP_TX functionality. The following steps show how to run the test:
   1. On the system under test, install eBPF binaries (install-ebpf.bat).
   2. Load the test eBPF program by running the following commands: `netsh`, `ebpf`, `add program reflect_packet.o xdp`.
   3. From a remote host, run xdp_tests.exe and in `--remote-ip` parameter pass an IPv4 or IPv6 address of an Ethernet-like interface on the system under test in string format.
   4. Unload the program from system under test by running `delete program reflect_packet.o xdp` on the netsh prompt.