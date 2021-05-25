# eBPF for Windows – Long term strategy

## Overview

This is intended as a living document that will be updated as the project
evolves. It is not intended as definitive guide, but rather as set of
aspirational goals for the project. It is expected that it will evolve based on
the needs of users and the feedback of contributors working on this project.

To achieve long term success, this project needs to succeed in several
different areas. Each section of this document covers an area or scenario that
eBPF For Windows needs to meet.

## Security

The most important aspect of this project is that it needs to uphold the security
principles in Windows and the security promises that Windows users have come
to expect, while maintaining the flexibility to meet their needs.
Users should be able to deploy and run eBPF programs on Windows when the
system is configured for its most secure mode, whether that is a shielded VM,
Hyper-Visor Code Integrity or other security mitigations.

The BPF ISA and VM clearly define limits as to what an eBPF program can do, with
limits on execution time, memory accessed and kernel functionality that can be
invoked. Within these limits eBPF programs should have the flexibility to
perform any operations.

## Compatibility

eBPF as a technology is available on other platforms (mainly Linux) and
users have an expectation that eBPF programs written for Linux should be
portable to Windows. While binary compatibility of the compiled eBPF programs is
likely not possible, it should be relatively straightforward to port programs
from Linux to Windows. The main obstacle to this is around helper APIs and
the type definitions that are OS-specific.

The project aims to provide interface compatible APIs for loading and managing
eBPF programs, while also providing extended APIs for functionality that is not
present in other platforms.

Given the fundamental differences between Linux and Windows, attach points are
unlikely to be the same as those present in Linux, but a best effort should be
made to offer similar functionality where it makes sense.

## Extensibility

A core aspiration of this project is for there to be an active ecosystem built
on top of eBPF for Windows. eBPF for Windows is not intended to offer a complete
set of helper functions and attach points to meet all customer needs by itself,
but rather to have an organically grown set of extensions that provide helper
functionality and attach point owned and maintained by the community at large.
Developing new scenarios and use cases should be achieved with out the need to
update the core eBPF for Windows project and likewise updates to the core eBPF
for Windows project should not break extensions.

The project envisions two main scenarios for extensions, observability of system
state and modification of system behavior.

### Observability

One of the largest use case of eBPF on other platforms is observe the behavior
of the system, both through predefined observability points as well as
dynamically created observability points. Similar technologies already exist for
Windows, with [DTrace on Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/dtrace)
being the primary example as well as
[Event Tracing for Windows](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal).
While these technologies can be used to achieve the observability goals, they
don't currently integrate with the eBPF ecosystem. As a long-term goal, this
project should carefully consider how best to leverage both technologies to
allow eBPF for Windows to meet its observability goals. Likely there will be a
small set of extensions that leverage Windows system capabilities to define new
attach points for visibility.

### Control

A secondary use case for eBPF on other platforms is to extend existing system
behavior with out the need to author new in-box components. As this invariably
involves modification of the flow of control within existing components, this is
often via predefined extension points. Typical modifications can include
permit/deny decisions, alteration of the flow of control, or modification of the
data transiting the system. The expectation is that many of these extensions
will be built on top of existing extensibility points within Windows or 3rd
party software running on Windows. Given the wide range of extensibility points
within the Windows ecosystem, this is likely to be the source of the largest
number of extensions.

## Context Agility

The threat profile being faced by computer systems is continually evolving and
as result it is likely that the mitigations required will likewise evolve. To
this end, the project has invested heavily in the ability to run code within in
a wide variety of contexts, ranging from operating in kernel mode, to running
within user mode processes or in isolate enclaves (either hardware backed or
virtualized). This primarily impacts the execution context, which is designed to
have a bounded set of dependencies that can be satisfied in a wide variety of
contexts.
