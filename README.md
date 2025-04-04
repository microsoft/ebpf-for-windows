<img src="docs/eBPF%20logo%20png%20800px.png" width=75 height=75 align=left />

# eBPF for Windows

[![CI/CD](https://github.com/microsoft/ebpf-for-windows/actions/workflows/cicd.yml/badge.svg?branch=main&event=schedule)](https://github.com/microsoft/ebpf-for-windows/actions/workflows/cicd.yml?query=event%3Aschedule++)
[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/5742/badge)](https://bestpractices.coreinfrastructure.org/projects/5742)
[![codecov](https://codecov.io/gh/microsoft/ebpf-for-windows/branch/main/graph/badge.svg?token=TXa0UAMvYf)](https://codecov.io/gh/microsoft/ebpf-for-windows)
[![Perf Dashboard](https://img.shields.io/static/v1?label=Performance&message=Dashboard&color=blue)](https://bpfperformancegrafana.azurewebsites.net/public-dashboards/3826972d0ff245158b6df21d5e6868a9?orgId=1)

eBPF is a well-known technology for providing programmability and agility, especially for extending an
OS kernel, for use cases such as DoS protection and observability. This project is a work-in-progress that
allows existing eBPF
toolchains and APIs familiar in the Linux ecosystem to be used on top of Windows.  That is, this project
takes existing eBPF projects as submodules and adds the layer in between to make them run on top of Windows.

## New to eBPF?

See our [basic eBPF tutorial](docs/tutorial.md) and our
[tutorial on debugging eBPF verification failures](docs/debugging.md).

## Architectural Overview

The following diagram shows the basic architecture of this project and related components:

![Architectural Overview](docs/ArchitectureDiagram.png)

As shown in the diagram, in a typical developer workflow, the existing eBPF toolchains (clang, etc.)
can be used to generate eBPF bytecode (stored in `ELF` format) from source code in various languages.

There are three main approaches to process the eBPF bytecode and load it into Windows kernel.

1. **Native eBPF Program**:
The eBPF bytecode is sent to the `bpf2c` tool in the next phase of the workflow. The `bpf2c` tool passes the
bytecode to the [PREVAIL verifier](https://github.com/vbpf/ebpf-verifier). If the eBPF program passes all the verifier checks,
the `bpf2c` tool converts every instruction in the bytecode to equivalent `C` statements as outlined in the
[native code generation](docs/NativeCodeGeneration.md) document. The generated `C` code is then built into a windows driver
module (stored in a `.sys` file) using the standard visual studio toolchain. The generated driver is also known as the native eBPF program.

   **Note:** This is the *preferred* way of deploying eBPF programs.
   See the [FAQ on HVCI](readme.md#3-will-ebpf-work-with-hypervisor-enforced-code-integrity-hvci) for details as to why this mode is
   also the most secure.

1. **JIT Compiler**
In this approach a user mode service (`eBPFSvc.exe`) *JIT compiles* the eBPF bytecode via the [uBPF](https://github.com/iovisor/ubpf) JIT compiler
into native code that is passed to the kernel-mode execution context.

1. **Interpreter**
In this approach the bytecode can be directly loaded into an *interpreter* (from [uBPF](https://github.com/iovisor/ubpf)) in the
kernel-mode execution context.
       **Note:** The interpreter is present only in debug builds and not in release builds as it is considered less secure.

*Note: The JIT Compiler and Interpreter are not shown in the architecture diagram.*

*Note: For the JIT and interpreter approaches, The `eBPFSvc` service ensures that the eBPF programs pass all the verifier checks.*

The eBPF programs can be consumed by any application, or via bpftool or the Netsh command line tool, which use a shared library (`ebpfapi.dll`) that exposes [Libbpf APIs](https://github.com/libbpf/libbpf). These APIs can be used to load the
eBPF programs to the kernel-mode `execution context`.

eBPF programs that are loaded into the kernel-mode execution context can attach to various
[hooks](https://microsoft.github.io/ebpf-for-windows/ebpf__structs_8h.html#a0f8242763b15ec665eaa47c6add861a0)
and call various helper APIs exposed by the eBPF shim,
which internally wraps public Windows kernel APIs, allowing the use of eBPF on existing versions of Windows.
Many [helpers](https://microsoft.github.io/ebpf-for-windows/bpf__helper__defs_8h.html)
already exist, and more hooks and helpers will be added over time.

## Getting Started

This project supports eBPF on Windows 11 or later, and on Windows Server 2022 or later.
To try out this project, see our [Getting Started Guide](docs/GettingStarted.md).

Want to help?  We welcome contributions!  See our [Contributing guidelines](CONTRIBUTING.md).
Feel free to take a look at our [Good First Issues](https://github.com/microsoft/ebpf-for-windows/labels/good%20first%20issue)
list if you're looking for somewhere to start.

Want to chat with us?  We have a:
* [Slack channel](https://cilium.slack.com/messages/ebpf-for-windows) (If you are new, sign up at http://slack.cilium.io/)
* Zoom meeting for github issue triage: see [meeting info](https://github.com/microsoft/ebpf-for-windows/discussions/427)

For tracking Q&A and general discussion, we use [Discussions](https://github.com/microsoft/ebpf-for-windows/discussions)
in github.  This can also function similar to a mailing list if you subscribe to discussion notifications by
clicking "Watch" (or "Unwatch") and selecting "Custom" -> "Discussions" (or by selecting "All Activity" if
you want to receive notifications about everything else too).

If you have issues with an eBPF program, start with the [Troubleshooting Guide](docs/TroubleshootingGuide.md).

## Frequently Asked Questions

### 1. Is this a fork of eBPF?

No.

The eBPF for Windows project leverages existing projects, including
the [IOVisor uBPF project](https://github.com/iovisor/ubpf) and
the [PREVAIL verifier](https://github.com/vbpf/ebpf-verifier),
running them on top of Windows by adding the Windows-specific hosting environment for that code.

### 2. Does this provide app compatibility with eBPF programs written for Linux?

The intent is to provide source code compatibility for code that uses common
hooks and helpers that apply across OS ecosystems.

Linux provides many hooks and helpers, some of which are very Linux specific (e.g., using
Linux internal data structs) that would not be applicable to other platforms.
Other hooks and helpers are generically applicable and the intent is to support them for eBPF
programs.

Similarly, the eBPF for Windows project exposes [Libbpf APIs](https://github.com/libbpf/libbpf)
to provide source code compatibility for applications that interact with eBPF programs.

### 3. Will eBPF work with HyperVisor-enforced Code Integrity (HVCI)?

Yes. With HVCI enabled, eBPF programs cannot be JIT compiled, but can be run in the native mode.
To understand why JIT compiled mode does not work, we must first understand what HVCI does.

[HyperVisor-enforced Code Integrity (HVCI)](https://techcommunity.microsoft.com/t5/windows-insider-program/virtualization-based-security-vbs-and-hypervisor-enforced-code/m-p/240571)
is a mechanism
whereby a hypervisor, such as Hyper-V, uses hardware virtualization to protect kernel-mode processes against
the injection and execution of malicious or unverified code. Code integrity validation is performed in a secure
environment that is resistant to attack from malicious software, and page permissions for kernel mode are set and
maintained by the hypervisor.

Since a hypervisor doing such code integrity checks will refuse to accept code pages that aren't signed by
a key that the hypervisor trusts, this does impact eBPF programs running natively.  As such, when HVCI
is enabled, eBPF programs work fine in interpreted mode, but not when using JIT compilation because the JIT
compiler does not have a key that the hypervisor trusts.  And since interpreted
mode is absent in release builds, neither mode will work on an HVCI-enabled production system.

Instead, a third mode is also supported by eBPF for Windows, in addition to JIT compiled and interpreted modes.
This third mode entails compiling eBPF programs into regular Windows drivers that can be accepted by HVCI.
For more discussion, see the [Native Code Generation documentation](docs/NativeCodeGeneration.md).

<small>(Technically, interpreted mode eBPF programs would run with HVCI too, but the interpreter is disabled in release builds
and is only supported in debug builds.)</small>
