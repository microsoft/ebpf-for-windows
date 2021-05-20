# eBPF for Windows

eBPF is a well-known technology for providing programmability and agility, especially for extending an
OS kernel, for use cases such as DoS protection and observability. This project is a work-in-progress that
allows using existing eBPF
toolchains and APIs familiar in the Linux ecosystem to be used on top of Windows.  That is, this project
takes existing eBPF projects as submodules and adds the layer in between to make them run on top of Windows.

## New to eBPF?

See our [eBPF tutorial](docs/tutorial.md).

## Architectural Overview

The following diagram shows the architecture of this project and related components:

![Architectural Overview](docs/ArchitectureDiagram.png)

As shown in the diagram, existing eBPF toolchains (clang, etc.) can be used to generate eBPF bytecode from
source code in various languages.  Bytecode can be consumed by any application, or via the Netsh command line tool, which use a shared library
that exposes [Libbpf APIs](https://github.com/libbpf/libbpf),
though this is still in progress.

The eBPF bytecode is sent to a static verifier (the [PREVAIL verifier](https://github.com/vbpf/ebpf-verifier))
that is hosted in a user-mode [protected process](https://docs.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-#system-protected-process)
(a Windows security environment that allows a kernel component to trust a user-mode daemon signed by
a key that it trusts).  If the bytecode passes all the verifier checks, it can be either loaded into
an interpreter (from [uBPF](https://github.com/iovisor/ubpf) in the kernel-mode execution context), or
JIT compiled (via the [uBPF](https://github.com/iovisor/ubpf) JIT compiler) and have native code load
into the kernel-mode execution context (but see the FAQ at bottom about HVCI).

*Temporary Note: some parts are still under development and may not appear
when building the master branch, but the end-to-end functionality can still be tested immediately
while the security hardening is still in progress.*

eBPF programs installed into the kernel-mode execution context can attach to various hooks (currently
two hooks so far: XDP and a socket bind hook) and call various helper APIs exposed by the eBPF shim,
which internally wraps public Windows kernel APIs, allowing the use of eBPF on existing versions of Windows.
More hooks and helpers will be added over time.

## Getting Started

This project supports eBPF on Windows 10, and on Windows Server 2016 or later.
To try out this project, see our [Getting Started Guide](docs/GettingStarted.md).

Want to help?  We welcome contributions!  See our [Contributing guidelines](CONTRIBUTING.md).

Want to chat with us?  We have a:
* [Slack channel](https://slack.com/app_redirect?channel=ebpf-for-windows)
* Zoom meeting for github issue triage: see [meeting info](https://github.com/microsoft/ebpf-for-windows/issues/162)

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

eBPF programs can be run either in an interpreter or natively using a JIT compiler.

[HyperVisor-enforced Code Integrity (HVCI)](https://techcommunity.microsoft.com/t5/windows-insider-program/virtualization-based-security-vbs-and-hypervisor-enforced-code/m-p/240571)
is a mechanism
whereby a hypervisor, such as Hyper-V, uses hardware virtualization to protect kernel-mode processes against
the injection and execution of malicious or unverified code. Code integrity validation is performed in a secure
environment that is resistant to attack from malicious software, and page permissions for kernel mode are set and
maintained by the hypervisor.

Since a hypervisor doing such code integrity checks will refuse to accept code pages that aren't signed by
a key that the hypervisor trusts, this does impact eBPF programs running natively.  As such, when HVCI
is enabled, eBPF programs work fine in interpreted mode, but not when using JIT compilation.
