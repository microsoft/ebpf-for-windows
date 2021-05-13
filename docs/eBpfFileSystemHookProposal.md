# Proposal for filesystem eBPF hook

## Overview

Windows provides functionality to create filesystem mini-filters, which are drivers that permit hooking filesystem operations to allow modification and inspection of filesystem IO operations. Exposing this as a set of eBPF hooks would allow developers to easily extend the filesystem operations on Windows with out the need for writing a new mini-filter.

## Scenarios

### Monitor file access for an executable

Permit a user to monitor which files are opened/read/written by an executable. Hook would need to callout at the start of IO operations and provide helper to query information about the calling process.

### IO Latency

Permit a user to measure the IO latency of filesystem operations. Hook would need to callout at start of IO operations and end of IO operations and provide some context to permit associating the begin and end operation.

### Filesystem redirection

Permit a user to rewrite the path when a file is being opened. Optionally provide helpers to perform path modification.

## Requirements

### eBPF core requirements

Driver needs to define a new eBPF program type (and define the context structure passed to the eBPF program) as well as one or more eBPF hook types.

### NMR program information provider

Driver needs to register as an NMR provider for the eBPF program type. Driver needs to provide the program information as a the NpiSpecificCharacteristics in the NmrRegisterProvider call.

### NMR hook provider

Driver needs to register as an NMR provider for the eBPF hook type. In the ProviderAttachClient callback, the driver gets a pointer to the program context and the dispatch table. When an event occurs, the driver invokes the function in the dispatch table, passing the program context as well as the hook context structure.

### Filter Manager

Driver needs to register with the Filter Manager on load (via FltRegisterFilter and FltStartFiltering). Filter driver then needs to register the pre-operation and post-operation callbacks.