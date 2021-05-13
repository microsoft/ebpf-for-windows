# eBPF extensions

## Overview

Ebpf-On-Windows is designed to permit anyone to add new hooks, program types or helper functions, with out the need to modify either the eBPF execution context or the eBPF verifier. Ebpf-On-Windows uses [NMR](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-module-registrar2) to decouple the eBPF extensions from the core Ebpf-For-Windows. [NPI](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-programming-interface) contracts are identified by a GUID.

## NPI for Program Information

The program information NPI contract is for providing information about an eBPF program type. Program types are defined as the ABI contract that the eBPF program exposes and what valid input to the eBPF program looks like. This information is consumed by the eBPF verifier to ensure that any eBPF programs of this type are safe to load and execute. The ABI contract includes both a description of the &quot;context&quot; parameter passed to the eBPF program as well as the list of program specific helper functions that the extension exposes. Extensions should not unload until the last NMR client detaches, signifying that no eBPF programs are using the helper functions.

Currently the information is exposed as an opaque blob of MS-RPCE serialized data with the schema defined by [ebpf_program_types](https://github.com/microsoft/ebpf-for-windows/blob/master/libs/platform/ebpf_program_types.idl). Due to limitations on Windows, it's not possible to serialize the contract from kernel mode. Proposals are underway to switch this to use [Google FlatBuffers](https://google.github.io/flatbuffers/) as that is more easily serialized from kernel mode.

## NPI for Attach Type

Attach type NPI contracts are the mechanism that extensions use to invoke eBPF programs when events occur. The extension registers as an NMR provider and supplies callback functions that are invoked when a NMR client attaches or detaches. To invoke an eBPF program, the extension uses the NpiSpecificCharacteristics as well as the supplied dispatch table. The first entry in the dispatch table is a pointer to the function that invokes the eBPF program and has the signature:

```
ebpf_error_code_t (*invoke_hook)(void* bind_context, void* context, uint32_t* result);
```