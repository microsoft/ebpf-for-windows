# eBPF extensions

## Overview

The eBPF for Windows project is designed to permit anyone to add new hooks, program types or helper functions,
without the need to modify either the eBPF execution context or the eBPF verifier.  We use the term "eBPF extension"
to mean a driver or component that exposes new eBPF hooks or helper functions.
The eBPF for Windows project uses the
[Network Module Registrar (NMR)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-module-registrar2)
to decouple the eBPF extensions from the core eBPF for Windows framework.  In the NMR architecture,
[Network Programming Interface (NPI)](https://docs.microsoft.com/en-us/windows-hardware/drivers/network/network-programming-interface)
contracts are identified by a GUID.

## NPI Contract for eBPF Program Information

The eBPF program information NPI contract is used to provide information about an eBPF program type. Program types
are defined as the ABI contracts that eBPF programs are written to conform to.
This information is consumed by the eBPF verifier to ensure that any eBPF programs of a given type are safe to load
and execute. The ABI contract includes both a description of the &quot;context&quot; parameter passed to the eBPF
program as well as the list of specific helper functions that are available to such eBPF programs. eBPF extensions
should not unload until the last NMR client detaches, signifying that no eBPF programs are using helper functions
it provides.

Currently the information is exposed as an opaque blob of
[MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15)
serialized data with the schema defined by
[ebpf_program_types](https://github.com/microsoft/ebpf-for-windows/blob/master/libs/platform/ebpf_program_types.idl).
Due to current limitations on Windows, it's not possible to serialize the contract from kernel mode. Proposals are
underway to switch the serialization to use [Google FlatBuffers](https://google.github.io/flatbuffers/) as that is
more easily serialized from kernel mode.

## NPI Contract for Attach Type

Attach type NPI contracts are the mechanism that extensions use to invoke eBPF programs when events occur. The
eBPF extension registers as an NMR provider and supplies callback functions that are invoked when a NMR client
attaches or detaches. To invoke an eBPF program, the extension uses the NpiSpecificCharacteristics as well as the
supplied dispatch table. The first entry in the dispatch table is a pointer to the function that invokes the eBPF
program and has the signature:

```
ebpf_error_code_t (*invoke_hook)(void* bind_context, void* context, uint32_t* result);
```
