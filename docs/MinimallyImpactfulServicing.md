# Minimally Impactful Servicing of eBPF For Windows

## Overview
As newer versions of eBPF for Windows are released, it is desirable to allow updating
the code currently executing on systems, without requiring a reboot. Simply stopping and restarting eBPF is
not a viable solution as applications are dependent on state stored within eBPF,
in the form of map, program, and link objects. This document outlines a strategy
for replacing the currently executing version of eBPF for Windows with a newer
version.

## Architectural changes
Under the new architecture, the eBPF for Windows execution context (the portion
of eBPF hosting the virtual machine in which eBPF programs execute) is split
into two parts.

The first part hosts the code that interacts with the Windows I/O Manager (the
part of the Windows kernel responsible for exposing handles to user mode). This
part of the code cannot be serviced without restarting the applications using
eBPF due to constraints imposed by the Windows kernel. The expectation is that
this portion of the code will be relatively stable and will not require frequent
updates. This part is referred to as ProxyDriver and is intended as a generic

The second part hosts the code that implements the eBPF for Windows virtual
machine. This part of the code supports serializing its state in a format that is
both forward and backward compatible. During termination of this code it
can optionally serialize its state and during initiation it can optionally
deserialize its state. The net effect is that this part of the code can be
reloaded without any user visible change. This part is referred to as eBPF Core
or the core driver.

To ensure that the state stored in eBPF Core remains consistent across updates,
the following actions are taken:
1. Calls from user mode are blocked in ProxyDriver.
2. eBPF hook providers are notified of servicing start.
3. eBPF programs are detached from attach points prior unloading the old code
and reattached after loading the new code.
4. eBPF hook providers are notified of servicing end.
5. Calls from user mode are unblocked in ProxyDriver.

Each eBPF hook provider is responsible for picking an appropriate strategy for
handling events during servicing. Possible behaviors include queueing the events
or dropping them. As an example, the XDP hook might choose to return XDP_DROP
for packets received during servicing, whereas the sockops hook provider might
choose to queue the events.

## Interface between ProxyDriver and eBPF Core
Both ProxyDriver and eBPF Core are WDF drivers, which expose a single exported
function named "DriverEntry". During calls to DriverEntry, the driver registers
a "DriverUnload" function that is called when the driver unloads. The ProxyDriver
and eBPF Core drivers will then exchange dispatch tables (a table of function
pointers) via [NMR](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-the-network-module-registrar), with NmrRegister* being called from DriverEntry and
NmrDeregister* being called from DriverUnload.

eBPF Core exposes functions to ProxyDriver to initiate and terminate the eBPF
virtual machine as well as functions to dispatch messages to the virtual
machine. During initiation, eBPF Core will deserialize any previously serialized
state, recreating any eBPF objects. During termination, eBPF Core will serialize
any eBPF objects.

ProxyDriver exposes function to eBPF Core to perform manipulation of I/O Manager
handles, specifically creation of new handles, closing handles, and resolving
handles to eBPF object identifiers. In addition ProxyDriver will expose functions
to eBPF Core to read and write from a serialization stream.

## Handle management
eBPF for Windows exposes maps, programs, and links as Windows handles to user
mode. All eBPF objects have a unique object ID assigned to them when they are
created, with APIs to obtain handles to eBPF objects via their ID.

ProxyDriver registers with the [Windows I/O Manager](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-i-o-manager) as the driver that owns the
\Device\EbpfIoDevice namespace. As a result, all handles created within this
namespace are dispatched to the ProxyDriver driver. The ProxyDriver driver in turn
dispatches these calls to the currently active instance of the eBPF Core driver
via its dispatch table.

Each I/O Manager handle points to a Windows FILE_OBJECT structure. Within this
structure, the device driver is responsible for maintaining and interpreting
the both the FsContext and the FsContext2 fields. The ProxyDriver driver stores
the id of eBPF object that this file object points to in the FsContext2 field.

Resolution of an I/O Manager handle to an eBPF object is a two step process. The
first step is to resolve the handle to the eBPF object ID. The object
ID is then resolved to a pointer to the eBPF object.

eBPF object IDs are maintained across serialization and as a result
handles remain valid.

## Serialization
During initiation and termination of eBPF Core the ProxyDriver will pass a
pointer to an opaque stream context. ProxyDriver will expose functions to iterate
over a list of flat buffers stored in memory within ProxyDriver.

During initiation and termination, eBPF Core will deserialize and serialized
objects into flat buffers stored in ProxyDriver. References between objects will
be preserved as object IDs and converted back to pointers on deserialization.

Due to dependencies between eBPF objects, serialization will occur in the
following order:
1. Maps
2. Programs
3. Links

Serialization format is still TBD, but possible candidates are:
1. [ASN.1](https://en.wikipedia.org/wiki/ASN.1) encoded using [DER](https://en.wikipedia.org/wiki/Distinguished_Encoding_Rules) or [BER](https://en.wikipedia.org/wiki/Basic_Encoding_Rules).
2. [Protocol Buffers](https://en.wikipedia.org/wiki/Protocol_Buffers)
3. [BSON](https://en.wikipedia.org/wiki/BSON)
4. [JSON](https://en.wikipedia.org/wiki/JSON)
5. [CBOR](https://en.wikipedia.org/wiki/CBOR)

## Potential future improvements
This design has several future improvements and/or open questions:
1. Should the ProxyDriver driver be a more generic driver that is decoupled from
eBPF as this functionality could be useful across a broad range of kernel
components that require servicing.
2. Should the control and data path continue to operate across servicing? This
would require some mechanism to reconcile state changes between the state of the
old code (captured in the serialized state) and the state in the new code.
Options might include journal/replay of changes or mirroring state changes.