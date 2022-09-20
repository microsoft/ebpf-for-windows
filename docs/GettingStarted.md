# Getting Started

If you just want to install eBPF for Windows on a machine to experiment with,
jump down to [Installing eBPF for Windows](#installing-ebpf-for-windows).

If you just want to compile, but not run, eBPF programs and applications that interact with them,
jump down to [Using eBPF in development](#using-ebpf-in-development).

## Building eBPF for Windows

### Prerequisites

The following must be installed in order to build this project:
1. Git (e.g., [Git for Windows 64-bit](https://git-scm.com/download/win))
2. [Visual Studio 2019 version 16.11.7 or later](https://www.techspot.com/downloads/downloadnow/7241/?evp=70f51271955e6392571f575e301cd9a3&file=9642), including
   the "Desktop development with C++" workload, and
   the "MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (latest)"
   which must be selected as an Individual component in the VS installer
3. [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)
4. [WDK for Windows 10, version 2004](https://go.microsoft.com/fwlink/?linkid=2128854), including the "Windows Driver Kit Visual Studio extension" (make sure the check box is checked before completing the installer)
5. [Clang for Windows 64-bit version 11.0.1](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/LLVM-11.0.1-win64.exe).  Note: clang versions 12 and higher are NOT yet supported, as they perform program optimizations that are incompatible with the PREVAIL verifier.
6. [nuget.exe](https://www.nuget.org/downloads) installed to a location such as "C:\Program Files (x86)\NuGet\"

You should add the paths to `git.exe`, `cmake.exe` and `nuget.exe` to the Windows PATH environment variable after the software packages above have been installed.

Alternative install steps:
1. Launch an elevated PowerShell session.
2. Run:
```
Set-ExecutionPolicy Bypass -Scope Process -Force
Invoke-WebRequest 'https://raw.githubusercontent.com/microsoft/ebpf-for-windows/main/scripts/Setup-DevEnv.ps1' -OutFile $env:TEMP\Setup-DeveEnv.ps1
if ((get-filehash $env:TEMP\Setup-DeveEnv.ps1).Hash -eq '4000D4B2478A5CE9A779140DEDAEF99E422D9A8706B4ECE596CF0F69DB667055') { &"$env:TEMP\Setup-DeveEnv.ps1" }
```
3. Launch Visual Studio Installer and select "MSVC v142 - VS 2019 C++ x64/x86 Spectre-mitigated libs (latest)"

### How to clone and build the project using Visual Studio
This section outlines the steps to build, prepare and build the eBPF-For-Windows project.

#### Cloning the project
1. ```git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows.git```.
By default this will clone the project under the `ebpf-for-windows` directory.

#### Prepare for first build
The following steps need to be executed _once_ before the first build on a new clone.
1. Launch `Developer Command Prompt for VS 2019` by running `"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\Tools\VsDevCmd.bat"`.
2. Change directory to where the project is cloned, e.g. ```cd ebpf-for-windows```.
3. ```cmake -G "Visual Studio 16 2019" -S external\ebpf-verifier -B external\ebpf-verifier\build```
4. ```cmake -G "Visual Studio 16 2019" -S external\catch2 -B external\catch2\build -DBUILD_TESTING=OFF```
5. ```cmake -G "Visual Studio 16 2019" -S external\ubpf -B external\ubpf\build```
6. ```nuget restore ebpf-for-windows.sln```
7. ```del external\ebpf-verifier\build\obj\project.assets.json```

#### Building using Developer Command Prompt for VS 2019
1. Launch `Developer Command Prompt for VS 2019`.
2. Change directory to where the project is cloned, e.g. ```cd ebpf-for-windows```.
3. ```msbuild /m /p:Configuration=Debug /p:Platform=x64 ebpf-for-windows.sln```

##### Setting compile time options when building from Developer Command Prompt
To build with specific compile time options, append ```/p:DefineConstants=<option_name>```. Options available include:
1. ```CONFIG_BPF_JIT_ALWAYS_ON``` - Compile eBPF Execution Context without support for eBPF interpreter.

#### Building using Visual Studio IDE
1. Open `ebpf-for-windows.sln`
2. Switch to debug / x64
3. Build solution

##### Setting compile time options when building from Visual Studio IDE
To build with specific compile time options:
1. Select the project to modify from the Solution Explorer.
2. Navigate to "C/C++" -> "Preprocessor" -> "Preprocessor Definitions"
3. Add the option to the list of preprocessor options.

Options available include:
1. ```CONFIG_BPF_JIT_ALWAYS_ON``` - Compile eBPF Execution Context without support for eBPF interpreter.


This will build the following binaries:

* `ebpfcore.sys`: The kernel-mode execution context in which eBPF programs run.
* `netebpfext.sys`: The kernel-mode extension for WFP hooks.
* `ebpfapi.dll`: A user-mode shared library exposing APIs for apps to call to perform operations such as
               loading eBPF programs.
* `ebpfnetsh.dll`: A plugin for the Windows netsh.exe command line tool that provides eBPF command line
                 utility functionality.
* `ebpfsvc.exe`: A user-mode service that verifies and loads an eBPF program in the execution context.
* `unit_tests.exe`: A collection of tests using the Catch framework.  These tests are also run as part
                  of the Github CI/CD so should always pass.
* `api_test.exe`: A collection of tests that exercises eBPF user mode APIs. This requires EbpfSvc service to be running,
                and EbpfCore and NetEbpfExt drivers to be loaded.
* `sample_ebpf_ext.sys`: A sample eBPF extension driver that implements a test hook (for a test program type) and test helper functions.
* `sample_ext_app.exe`: A sample application for testing the sample extension driver.
* `xdp_tests.exe`: Application for testing various XDP functionalities.  This requires the EbpfSvc service to be running,
                and the EbpfCore and NetEbpfExt drivers to be loaded on a remote system to test.
* `socket_tests.exe`: Application for testing the eBPF extension that implements the BPF_CGROUP_SOCK_ADDR program type and related attach types.

and a few binaries just used for demo'ing eBPF functionality, as in the demo walkthrough discussed below:

* `dnsflood.exe`: A utility to send 0-byte DNS packets, to illustrate a case that the sample walkthrough uses eBPF
                to defend against.
* `port_leak.exe`: A "buggy" utility to illustrate the effect of an app that leaks ports.
* `port_quota.exe`: A sample utility to illustrate using eBPF to manage port quotas to defend against `port_leak.exe`
                  and similar "buggy" apps.

### How to clone and build the project using CMake

#### Cloning the project
```bash
git clone --recurse-submodules https://github.com/microsoft/ebpf-for-windows.git
```

#### Configuring the project

```bash
cmake -S ebpf-for-windows -B build
```

#### Building the project

Configuration: It is advised to use the Debug configuration for now.

```bash
cmake --build build --config <Configuration>
```

#### Running the tests

Configure with the `EBPFFORWINDOWS_ENABLE_TESTS` option (enabled by default)

```bash
cmake -S ebpf-for-windows -B build -DEBPFFORWINDOWS_ENABLE_TESTS=true
```

Then build the tests

```bash
cmake -S ebpf-for-windows -B build
```

Finally, invoke CTest:

```
cd build
ctest -V -C Debug
```

## Installing eBPF for Windows

Windows requires that one of the following criteria be met prior to loading a driver:
1. Driver is signed using a certificate that chains up to the Microsoft code signing root (aka a production signed driver).
2. The OS is booted with a kernel debugger attached.
3. The OS is running in [test-signing mode](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option), the [driver is test signed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-a-driver-through-an-embedded-signature) and the [test certificate is installed](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-test-certificates).

Since the eBPF for Wndows binaries are not yet signed by Microsoft, they will only work on a machine with
a kernel debugger (KD) attached and running, or test signing is enabled. (It is expected that official
releases of eBPF for Windows will eventually be production signed at some point in the future after
security hardening is completed.)

For basic testing, the simplest way to install eBPF for Windows is into a Windows VM with test signing enabled.
Follow the [VM Installation Instructions](vm-setup.md) and [eBPF Installation Instructions](InstallEbpf.md) to do so.

## Using eBPF for Windows

If you're not already familiar with eBPF, or want a detailed walkthrough, see our [eBPF tutorial](tutorial.md).

For API documentation, see https://microsoft.github.io/ebpf-for-windows/
### Port leak and bind observability demo
This section shows how to use eBPF for Windows in a demo that lets us control a UDP port leak by attaching an eBPF program to the socket `bind()` call via the `EBPF_ATTACH_TYPE_BIND` hook.
#### Prep
1. Build the ``port_leak`` and ``port_quota`` applications from under the tools project.
2. Copy both the exe's to a machine that has eBPF installed. See
   [Installing eBPF for Windows](#installing-ebpf-for-windows)
#### Demo
1. At a command prompt running as Administrator, run ``port_quota.exe load`` to load the port quota eBPF program attached to the bind hook.
2. Set a limit to a threshold number of ports you want to permit an application to bind to by doing ``port_quota.exe limit 5000``
3. Run ``port_leak.exe`` in another command prompt. This will just leak UDP ports. Observe the output that bind starts to fail after this app binds 5000 ports.
4. Running ```port_quota.exe stats``` will dump how many ports are taken up by an application. Under the covers, the eBPF program communicates this information up to the user mode application via an eBPF map.

### DNS flood attack demo
This section shows how to use eBPF for Windows in a demo that defends against a 0-byte UDP attack on a DNS server.

#### Prep
Set up 2 VMs, which we will refer to as the "attacker" machine and the "defender" machine.

On a defender machine with [eBPF installed](#installing-ebpf-for-windows), do the following:

1. Install and set up a DNS server.
2. Make sure that either test signing was enabled as discussed in
   [Installing eBPF for Windows](#installing-ebpf-for-windows), or the kernel debugger (KD) is attached and running.
3. Install [clang](https://github.com/llvm/llvm-project/releases/download/llvmorg-11.0.1/LLVM-11.0.1-win64.exe)
   if not already installed on the defender machine.
4. Copy `droppacket.c` and `ebpf.h` to a folder (such as `c:\test`).

On the attacker machine, do the following:
1. Copy `DnsFlood.exe` to attacker machine

#### Demo
##### On the attacker machine
1. Run ```for /L %i in (1,1,4) do start /min DnsFlood <ip of defender>```

##### On the defender machine
1. Start performance monitor and add UDPv4 Datagrams/sec
2. Show that 200K packets per second are being received
3. Show & explain code of `droppacket.c`
4. Compile `droppacket.c` ```clang -target bpf -O2 -Werror -c droppacket.c -o droppacket.o```
5. Show eBPF byte code for `droppacket.o` ```netsh ebpf show disassembly droppacket.o xdp```
6. Show that the verifier checks the code ```netsh ebpf show verification droppacket.o xdp```
7. Launch netsh ```netsh```
8. Switch to ebpf context ```ebpf```
9. Load eBPF program ```add program droppacket.o xdp``` and note the ID.
10. Show UDP datagrams received drop to under 10 per second
11. Unload program ```delete program <id>``` where <id> is the ID noted above.
12. Show UDP datagrams received drop to back up to ~200K per second
13. Modify `droppacket.c` to be unsafe - Comment out line 20 & 21
14. Compile `droppacket.c` ```clang -target bpf -O2 -Werror -c droppacket.c -o droppacket.o```
15. Show that the verifier rejects the code ```netsh ebpf show verification droppacket.o xdp```
16. Show that loading the program fails ```netsh ebpf add program droppacket.o xdp```

## Tests in Ebpf-For-Windows

The tests in Ebpf-For-Windows are written using the [Catch2](https://github.com/catchorg/Catch2) test framework.

### unit_tests.exe
This test uses a mocking layer to bind the user mode components to the kernel mode
components via a Mock IOCTL interface. The tests initialize the user mode and kernel
mode components, load an eBPF program from an ELF file, and then run the eBPF program
by having the mocked extensions emit events.

### api_test.exe
This test exercises various eBPF user mode eBPF APIs, including those to load programs,
enumerate maps and programs etc. This test requires the eBPF user mode service (EbpfSvc), and the
kernel execution context (`EbpfCore.sys`) and the Network Extension (`NetEbpfExt.sys`) to be running.
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
1.	`-s` to list both passing and failing test cases
2.	`-b` to break into the debugger on test failure
3.	`-l` to list test cases
4.	`Test_name` to run a single test

### xdp_tests.exe
This application tests various XDP functionalities. These tests require two hosts to run. There are three variations of the XDP tests.

#### Reflection Test
This tests the XDP_TX functionality.
1. On the first host:
   1. [Install eBPF for Windows](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md).
   2. Load the test eBPF program by running the following command: `netsh ebpf add program reflect_packet.o xdp` and note the ID. See **Note 3** below.
2. On the second host:
   1. Allow inbound traffic for `xdp_tests.exe` through Windows Defender Firewall. See **Note 1** below.
   2. Run `xdp_tests.exe xdp_reflect_test --remote_ip <IP on the first host>`. See **Note 2** below.

#### Encapsulation Test
This uses `bpf_xdp_adjust_head` helper function to encapsulate an outer IP header to a packet.
1. On the first host:
   1. [Install eBPF for Windows](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md).
   2. Load the test eBPF program by running the following command: `netsh ebpf add program encap_reflect_packet.o xdp` and note the ID. See **Note 3** below.
2. On the second host:
   1. Allow inbound traffic for `xdp_tests.exe` through Windows Defender Firewall. See **Note 1** below.
   2. Run `xdp_tests.exe xdp_encap_reflect_test --remote_ip <IP on the first host>`. See **Note 2** below.

#### Decapsulation Test
This uses `bpf_xdp_adjust_head` helper function to decapsulate an outer IP header from a packet.
1. On *both* the hosts, [install eBPF for Windows](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md).
2. On the first host load the first test eBPF program by running the following command: `netsh ebpf add program encap_reflect_packet.o xdp` and note the ID. See **Note 3** below.
3. On the second host:
   1. Load the second test eBPF program by running the following command: `netsh ebpf add program decap_permit_packet.o xdp` and note the ID. See **Note 3** below.
   2. Allow inbound traffic for `xdp_tests.exe` through Windows Defender Firewall. See **Note 1** below.
   3. Run `xdp_tests.exe xdp_reflect_test --remote_ip <IP on the first host>`. See **Note 2** below.

**Note 1:** To allow inbound traffic to `xdp_tests.exe`, in a Windows Powershell with administrative privilege, run `New-NetFirewallRule -DisplayName "XDP_Test" -Program "<Full path to xdp_tests.exe>" -Direction Inbound -Action Allow`.<br>
**Note 2:** For the `--remote-ip` parameter to `xdp_tests.exe` program that is run on the second host, pass an IPv4 or IPv6 address of an Ethernet-like interface on the first host in string format.<br>
**Note 3:** After completion of each test variation, unload the eBPF programs from both host machines by running `delete program <id>` on the netsh prompt, where `<id>` is the ID noted when the eBPF programs were loaded.<br>
***Advanced:*** The eBPF program can be attached to a specific interface by passing `interface=<IfIndex>` parameter either to the netsh `add program` or `set program` commands.

### socket_tests.exe
This application loads the `cgroup_sock_addr.o` eBPF program and attaches to hooks to handle various socket operations. Currently it tests authorizing ingress and egress connections based on entries in a map passed to the program.

### Using tracing
eBPF for Windows uses ETW for tracing.  A trace can be captured in a file, or viewed in real-time.

### Capturing traces
To capture a trace in a file use the following commands:
1) Start tracing: ```wpr.exe -start %ProgramFiles%\ebpf-for-windows\ebpfforwindows.wprp -filemode```. This will capture traces from eBPF execution context and the network eBPF extension drivers.  (The path `%ProgramFiles%\ebpf-for-windows` assumes you installed eBPF for Windows via the MSI file. If you installed it via some other method, [ebpfforwindows.wprp](../scripts/ebpfforwindows.wprp) may be in some other location.)
2) Run the scenario to be traced.
3) Stop tracing: ```wpr.exe -stop ebpfforwindows.etl```
4) Convert the traces to text format: ```netsh trace convert ebpfforwindows.etl overwrite=yes``` , or
   to convert to CSV format, use: ```netsh trace convert ebpfforwindows.etl ebpfforwindows.csv csv```

### Viewing traces in real-time
To view traces in real-time, the `tracelog.exe` and `tracefmt.exe` commands from the WDK can be used.
If you are running eBPF for Windows in a VM, you can either install the full WDK in the VM (see the Prerequisites
section above) or just copy the two executables into the VM.

To view all eBPF trace events that would be captured to a file, use the following commands:
1) Create a trace session with some name such as MyTrace: ```tracelog -start MyTrace -guid ebpf-all.guid -rt```
2) View the session in real-time on stdout: ```tracefmt -rt MyTrace -displayonly -jsonMeta 0```.  This will
   continue until you break out of the executable with Ctrl-C.
3) Close the trace session: ```tracelog -stop MyTrace```

Often when tracing eBPF programs, it is useful to only view output generated by the [bpf_printk](https://microsoft.github.io/ebpf-for-windows/bpf__helper__defs_8h.html#aae337e68db96b4b9470f8c519386cbec) helper.
To do so, use `ebpf-printk.guid` instead of `ebpf-all.guid` when creating a trace session.  That is:
1) Create a trace session with some name such as MyTrace: ```tracelog -start MyTrace -guid ebpf-printk.guid -rt```
2) View the session in real-time on stdout: ```tracefmt -rt MyTrace -displayonly -jsonMeta 0```.  This will
   continue until you break out of the executable with Ctrl-C.
3) Close the trace session: ```tracelog -stop MyTrace```

This will display lines like the following for `bpf_printk("Hello, world");`:
```
[3]1760.1910::03/10/2022-13:56:14.226 [EbpfForWindowsProvider]{"Message":"Hello, world"}
```
where `[3]` is the CPU ID, `1760` is the Process ID in hex, and `1910` is the Thread ID in hex.

If you want the prefix to look closer to Linux output, set the following [environment variable](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-message-prefix):
```
set TRACE_FORMAT_PREFIX=%8!u! [%9!03d!] %4!s!:
```

This will result in lines like:
```
5984 [003] 03/10/2022-13:56:14.226:{"Message":"Hello, world"}
```
where `5984` is the Process ID in decimal, and `003` is the CPU ID.

To view all trace events from the network eBPF extension (`netebpfext.sys`), use the following commands:
1) Create a trace session with some name such as MyTrace: ```tracelog -start MyTrace -guid net-ebpf-ext.guid -rt```
2) View the session in real-time on stdout: ```tracefmt -rt NetEbpfExtTrace -displayonly -jsonMeta 0```.  This will
   continue until you break out of the executable with Ctrl-C.
3) Close the trace session: ```tracelog -stop NetEbpfExtTrace```

## Using eBPF in Development

If you are developing eBPF programs and applications that interact with them,
your Visual Studio development will need to reference the eBPF for Windows project as follows.

If using Visual Studio as your IDE, your project can add a reference to the
[eBPF-for-Windows](https://www.nuget.org/packages/eBPF-for-Windows) nuget package.
(You can also manually download the nuget package from the
[latest release](https://github.com/microsoft/ebpf-for-windows/releases).)

If you [installed eBPF for Windows via the MSI](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md)
and checked the Development checkbox, installation was completed for you.
Otherwise, after installing the nuget package, as a one-time operation, you will
currently need to run the `export_program_info.exe` tool to complete the install. This
tool can be found in your project's `packages\eBPF-for-Windows\build\native\bin` directory.
