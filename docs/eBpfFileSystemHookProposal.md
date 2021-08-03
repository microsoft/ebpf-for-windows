# Proposal for filesystem eBPF hook

## Overview

Windows provides functionality to create filesystem
[mini-filters](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts),
which are drivers that permit hooking filesystem operations to allow modification and inspection of filesystem
I/O operations. Exposing this as a set of eBPF hooks would allow developers to easily extend the filesystem
operations on Windows without the need for writing a new mini-filter.

## Scenarios

### Monitor file access for an executable

Permit a user to monitor which files are opened/read/written by an executable. A hook would need to call out at
the start of I/O operations and provide a helper to query information about the calling process. This would for
example allow for the classic antivirus software use case where file open calls are hooked and the file is
then compared with known malicious signatures, while making use of all the benefits of eBPF.

### I/O Latency

Permit a user to measure the I/O latency of filesystem operations. A hook would need to call out at start of I/O
operations and end of I/O operations and provide some context to permit associating the begin and end operation.

### Filesystem redirection

Permit a user to rewrite the path when a file is being opened. Optionally provide helpers to perform path modification.

## Requirements

### eBPF core requirements

An [eBPF extension](eBpfExtensions.md) driver needs to define a new eBPF program type (and define the context
structure passed to the eBPF program) as well as one or more eBPF hook types.

### NMR program information provider

A driver needs to register as an
[NMR](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-programming-interface) provider for
the eBPF program type. The driver needs to provide the program information as the NpiSpecificCharacteristics in the
[NmrRegisterProvider](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/netioddk/nf-netioddk-nmrregisterprovider)
call.

### NMR hook provider

The driver needs to register as an NMR provider for the eBPF hook type. In the
[ProviderAttachClient](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-module-attachment)
callback, the driver gets a pointer to the program context and the dispatch table. When an event occurs, the driver
invokes the function in the dispatch table, passing the program context as well as the hook context structure.

### Filter Manager

The driver needs to register with the Filter Manager on load (via FltRegisterFilter and FltStartFiltering). The
filter driver then needs to register the pre-operation and post-operation callbacks.
