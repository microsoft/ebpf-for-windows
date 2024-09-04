# 1. Introduction

Often when writing eBPF programs, the first attempt will fail verification.
This tutorial illustrates how to understand and debug eBPF verification failures.

If you're new to eBPF for Windows, we recommend first going through the [basic eBPF tutorial](tutorial.md).
Once you understand that tutorial and have llvm-objdump and the netsh helper installed
on your machine, you're ready for the debugging tutorial.

# 2. Debugging a buggy eBPF program

Let's start with the [droppacket_unsafe.c](../tests/sample/unsafe/droppacket_unsafe.c) program, which
is compiled as part of building eBPF for Windows, as it is used in the unit tests.

**Step 1)** Let's first look at what sections are in the file:

```
> cd x64\Debug
> netsh ebpf show sections droppacket_unsafe.o

             Section       Type  # Maps    Size
====================  =========  ======  ======
               .text   xdp_test       1       3
            xdp_test   xdp_test       1      20
```

**Step 2)** Let's try to verify each section:

```
> netsh ebpf show ver droppacket_unsafe.o .text
Verification failed

Verification report:

; C:\your\path\ebpf-for-windows\tests\sample/./ebpf.h:15
; ntohs(uint16_t us)
1: r0.type == number
; C:\your\path\ebpf-for-windows\tests\sample/./ebpf.h:17
;     return us << 8 | us >> 8;
2: r0.type == number

2 errors

> netsh ebpf show ver droppacket_unsafe.o xdp_test
Verification failed

Verification report:

; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:29
;     if (ip_header->Protocol == IPPROTO_UDP) {
2: Upper bound must be at most packet_size (valid_access(r1.offset+9, width=1))
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:30
;         if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {
4: Upper bound must be at most packet_size (valid_access(r1.offset+24, width=2))

2 errors

```

We can see that both sections have issues.   We'll look at these one at a time.

**Step 3)** Let's first look at the netsh disassembly output for the .text section:

```
> netsh ebpf show disassembly droppacket_unsafe.o .text
; C:\your\path\ebpf-for-windows\tests\sample/./ebpf.h:15
; ntohs(uint16_t us)
       0:       r0 = r1
       1:       r0 = be16 r0
; C:\your\path\ebpf-for-windows\tests\sample/./ebpf.h:17
;     return us << 8 | us >> 8;
       2:       exit

```

We see there are 3 instructions, numbered 0 through 2.  In eBPF programs,
"r0" through "r10" are registers, where r0 is used for return values,
r1 through r5 are used to pass arguments to functions, and
r10 is the stack pointer.  This program, however, only uses
r0 and r1, where r0 is for the return value and r1 holds
the hook context (ctx) structure pointer that is
passed to the program as its first argument.

**Step 4)** To understand what went wrong, we can ask netsh for the informational or verbose output by using
"level=informational" or "level=verbose":

Note: Informational level will only show the first failure the verifier encounters on a specific path and not show
dependent failures. Verbose level will show both the initial failures as well as failures arising from that initial
failure. Informational is usually sufficient to understand the root cause of a failure, while verbose is useful to
gain a deeper understanding of what the impact of this failure is.

```
> netsh ebpf show ver droppacket_unsafe.o .text level=informational
Verification failed

Verification report:

Pre-invariant : [
    instruction_count=0,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
entry:
  goto 0;

Post-invariant: [
    instruction_count=1,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=1,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
0:
  r0 = r1;
  goto 1;

Post-invariant: [
    instruction_count=3,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.ctx_offset=0, r0.type=ctx, r0.value=[1, 2147418112], r0.value=r1.value,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=3,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.ctx_offset=0, r0.type=ctx, r0.value=[1, 2147418112], r0.value=r1.value,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
1:
  assert r0.type == number;
  r0 = be16 r0;
  goto 2;

Post-invariant: [
    instruction_count=6,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=ctx,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=6,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=ctx,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
2:
  assert r0.type == number;
  exit;
  goto exit;

Post-invariant: [
    instruction_count=9,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=ctx,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=9,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=ctx,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
exit:


Post-invariant: [
    instruction_count=10,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=ctx,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

; C:\your\path\ebpf-for-windows\tests\sample/./ebpf.h:15
; ntohs(uint16_t us)
1: r0.type == number
; C:\your\path\ebpf-for-windows\tests\sample/./ebpf.h:17
;     return us << 8 | us >> 8;
2: r0.type == number

2 errors
```

We see the non-verbose output at the end, but preceding it, we see a set of output where
each section has Pre-invariant and Stack info, then the instruction as it appears in the
disassembly along with any assertions and a goto indicating the next instruction to execute,
and then Post-invariant and Stack data.  Pre-invariants indicate the state immediately prior to the
instruction, and Post-invariants indicate the state immediately after the instruction.
Normally the Post-invariants of one instruction match the Pre-invariants of the next,
but we'll see later in step 9 where this is not the case.

Inside the invariants sections, we see the current values of various variables.
"instruction_count" tells us the maximum number of instructions executed, which is used
to prove that the program terminates.  "meta_offset" is the offset from the start of the
packet (if any) to the start of metadata about the packet, where the metadata occurs
immediately before the actual packet data, and "[-4098,0]" indicates that it could be
any value in the range -4098 to 0, inclusive.  "packet_size" shows the range of possible
sizes of the packet, if one associated with the hook.

For each register for which information is known, a set of attributes of that register are
then listed.  For example, in the Post-invariant of the last (exit) instruction, r0 and
r1 are both pointers to the ctx (at offset 0).  The "value" attribute is shown but is
meaningless for pointers, where instead the "offset" is the meaningful attribute.
Finally, r10 points to the end (offset=512) of a region of size 512 bytes, since eBPF
provides a stack space of exactly 512 bytes.   The "Stack" section shows that nothing
is known of the stack contents.

The errors at the end tell us which instruction number to look at, and what invariant could
not be proven.  The first error says it expected "r0.type == number" at instruction 1,
so we look at the Pre-invariant of instruction 1 where we find, among other things,
"r1.type=ctx".  As noted earlier, r1 is the first argument to the program and it initially
contains a ctx pointer, not a number, whereas the be16 instruction needs an integer to
operate on.   Similarly, all eBPF programs must return a number in r0, hence the assertion
and error in instruction 2.

**Step 5)** Where did that code come from?

If we look at the [droppacket_unsafe.c](../tests/sample/unsafe/droppacket_unsafe.c) source code,
it's not obvious where the instructions in the .text section came from.  Let's use
llvm-objdump -l -S to find out (in the future, netsh will show this information too but for now
we'll just use llvm-objdump).  This requires that the eBPF program was compiled with -g on the local
machine, or at least that the paths to the source code are the same so that the source lines
can be resolved.

```
> llvm-objdump -l -S droppacket_unsafe.o --section=.text

droppacket_unsafe.o:    file format ELF64-BPF


Disassembly of section .text:

0000000000000000 ntohs:
; C:\your\path\ebpf-for-windows\tests\sample\.\ebpf.h:16
; {
       0:       bf 10 00 00 00 00 00 00 r0 = r1
       1:       dc 00 00 00 10 00 00 00 r0 = be16 r0
; C:\your\path\ebpf-for-windows\tests\sample\.\ebpf.h:17
;     return us << 8 | us >> 8;
       2:       95 00 00 00 00 00 00 00 exit
```

We see that the code the ntohs() function in [tests\sample\ebpf.h](../tests/sample/ebpf.h):

```c
uint16_t
ntohs(uint16_t us)
{
    return us << 8 | us >> 8;
}
```

Clearly the .text section was not intended to be an actual eBPF program, but it did serve
to illustrate some basic steps.  So now let's move on to the real program in the xdp_test section.


**Step 6)** Let's first look at the disassembly output from netsh:

```

> netsh ebpf show disassembly droppacket_unsafe.o xdp_test
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:22
; DropPacket(xdp_md_t* ctx)
       0:       r0 = 1
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:24
;     IPV4_HEADER* ip_header = (IPV4_HEADER*)ctx->data;
       1:       r1 = *(u64 *)(r1 + 0)
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:29
;     if (ip_header->Protocol == IPPROTO_UDP) {
       2:       r2 = *(u8 *)(r1 + 9)
       3:       if r2 != 17 goto +15 <19>
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:30
;         if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {
       4:       r1 = *(u16 *)(r1 + 24)
       5:       r1 = be16 r1
       6:       if r1 > 8 goto +12 <19>
       7:       r1 = 0
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:31
;             long key = 0;
       8:       *(u64 *)(r10 - 8) = r1
       9:       r2 = r10
      10:       r2 += -8
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:32
;             long* count = bpf_map_lookup_elem(&port_map, &key);
      11:       r1 = map_fd 1
      13:       r0 = bpf_map_lookup_elem:1(map_fd r1, map_key r2)
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:33
;             if (count)
      14:       if r0 == 0 goto +3 <18>
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:34
;                 *count = (*count + 1);
      15:       r1 = *(u64 *)(r0 + 0)
      16:       r1 += 1
      17:       *(u64 *)(r0 + 0) = r1
      18:       r0 = 2
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:38
;     return rc;
      19:       exit
```

We see there are 20 instructions, numbered 0 through 19.  As noted earlier,
"r0" through "r10" are registers, where r10 is the stack pointer and
r0 is used for return values (such as in instructions 13 and 18).
r1 through r5 are used to pass arguments to other functions, such
as r1 and r2 are used in instruction 13.

The destination of jumps are shown after the goto.  For example, instruction
3 will jump to instruction 19 if the condition is true.


**Step 7)** Let's now look at the verification failures of xdp_test using level=informational:

```
> netsh ebpf show ver droppacket_unsafe.o xdp_test level=informational
...
Pre-invariant : [
    instruction_count=3,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
1:
  assert r1.type in {ctx, stack, packet, shared};
  assert valid_access(r1.offset, width=8);
  r1 = *(u64 *)(r1 + 0);
  goto 2;

Post-invariant: [
    instruction_count=7,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=7,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
2:
  assert r1.type in {ctx, stack, packet, shared};
  assert valid_access(r1.offset+9, width=1);
  r2 = *(u8 *)(r1 + 9);
  goto 3;

Post-invariant: [
    instruction_count=11,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=11,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
Stack: Numbers -> {}
3:
  assert r2.type == number;
  goto 3:4,3:19;

Post-invariant: [
    instruction_count=13,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=13,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
Stack: Numbers -> {}
3:4:
  assume r2 == 17;
  goto 4;

Post-invariant: [
    instruction_count=15,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=13,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
Stack: Numbers -> {}
3:19:
  assume r2 != 17;
  goto 19;

Post-invariant: [
    instruction_count=15,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=15,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17]
Stack: Numbers -> {}
4:
  assert r1.type in {ctx, stack, packet, shared};
  assert valid_access(r1.offset+24, width=2);
  r1 = *(u16 *)(r1 + 24);
  goto 5;

Post-invariant: [
    instruction_count=19,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.type=number, r1.value=[0, 65535],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17]
Stack: Numbers -> {}
...
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:29
;     if (ip_header->Protocol == IPPROTO_UDP) {
2: Upper bound must be at most packet_size (valid_access(r1.offset+9, width=1))
; C:\your\path\ebpf-for-windows\tests\sample/unsafe/droppacket_unsafe.c:30
;         if (ntohs(udp_header->length) <= sizeof(UDP_HEADER)) {
4: Upper bound must be at most packet_size (valid_access(r1.offset+24, width=2))

2 errors
```

Let's first explain how condition branches work, as in instruction 3 (`if r2 != 17 goto +15 <19>`).
There are two possible branches: if r2 != 17, then jump to 19, else continue to instruction 4.
This results in two sets of Post-conditions, and is shown in the output as postconditions of
"3:4" and "3:19", respectively.

Now we can look at the actual failures.  The first error says there was an issue at instruction 2,
where it could not verify the `valid_access(r1.offset+9, width=1)` assertion.  This means that
it could not verify that memory pointed to by r1 could be safely dereferenced for a size of 1 byte,
where we saw instruction 2 was `r2 = *(u8 *)(r1 + 9);`.  Looking at the instruction 2 Pre-invariant,
we see `r1.offset=0, r1.region_size=[0, 65534], r1.type=packet`, meaning r1 points to the start (offset=0)
of a packet, and the range of memory safe to reference is between 0 and 65534 bytes long, inclusive.
The invariant fails because the region_size could be 0, but we need at least one byte.

**Step 8)** Root causing the bug:

Looking at previous instructions, we see that r1 was set in instruction 1 by reading the packet start
from the ctx, and then used without checking the packet size.  Thus, the bug in the code is that
it dereferenced a pointer without knowing whether the packet is at least one byte long.

Again we can see the source lines involved using llvm-objdump:

```
> llvm-objdump -l -S droppacket_unsafe.o --section=xdp_test
...
0000000000000000 DropPacket:
; C:\your\path\ebpf-for-windows\tests\sample\unsafe/droppacket_unsafe.c:23
; {
       0:       b7 00 00 00 01 00 00 00 r0 = 1
; C:\your\path\ebpf-for-windows\tests\sample\unsafe/droppacket_unsafe.c:24
;     IPV4_HEADER* ip_header = (IPV4_HEADER*)ctx->data;
       1:       79 11 00 00 00 00 00 00 r1 = *(u64 *)(r1 + 0)
; C:\your\path\ebpf-for-windows\tests\sample\unsafe/droppacket_unsafe.c:29
...

```

Thus we could modify the code to add a length check, as is done in the fixed version
[droppacket.c](../tests/sample/unsafe/droppacket.c#L44).

**Step 9)** Understanding joins between two code paths

Let's return to the question of when the Post-invariants of one instruction might differ from
the Pre-invariants of the next one.  Looking back at the disassembly in step 6, we see there
are three possible ways to get to instruction 19: from 3, from 6, and from 18.  Each of these
can have different Post-invariants.   The Pre-invariant of instruction 19 is thus the union
of the Post-invariants from all the instructions that could go to it:

```
3:19:
...
Post-invariant: [
    instruction_count=15,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534], packet_size=r1.numeric_size,
    r0.type=number, r0.value=1,
    r1.numeric_size=[0, 65534], r1.packet_offset=0, r1.type=packet, r1.value=[4098, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=[0, 255]]
...
6:19:
...
Post-invariant: [
    instruction_count=26,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=[9, +oo],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17]
...
18:
...
Post-invariant: [
    instruction_count=[49, 61],
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=2,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.numeric_size=8,
    s[504...511].value=0]
```

The union of the above Post-invariants results in:

```
...
Pre-invariant : [
    instruction_count-r0.value<=59,
    instruction_count=[15, 61],
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value-instruction_count<=-14, r0.value=[1, 2],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
...
19:
```

**Step 10)** Understanding the stack

Looking back at the disassembly in step 6, we see several instructions using the stack
(where r10 points to the end of the stack space):

```
       8:       *(u64 *)(r10 - 8) = r1
       9:       r2 = r10
      10:       r2 += -8
      11:       r1 = map_fd 1
      13:       r0 = bpf_map_lookup_elem:1(map_fd r1, map_key r2)
```

We see r1's value is saved in the stack, and then r2 points to the saved value,
which is passed as the map_key to `bpf_map_lookup_elem`.  Let's see how the verifier
understands this.

```
> netsh ebpf show ver droppacket_unsafe.o xdp_test level=informational
...
Pre-invariant : [
    instruction_count=28,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17]
Stack: Numbers -> {}
8:
  assert valid_access(r10.offset-8, width=8);
  *(u64 *)(r10 - 8) = r1;
  goto 9;

Post-invariant: [
    instruction_count=31,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}

Pre-invariant : [
    instruction_count=31,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.type=number, r2.value=17,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}
9:
  r2 = r10;
  goto 10;

Post-invariant: [
    instruction_count=33,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112], r10.value=r2.value,
    r2.numeric_size=0, r2.stack_offset=512, r2.type=stack, r2.value=[512, 2147418112],
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}

Pre-invariant : [
    instruction_count=33,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112], r10.value=r2.value,
    r2.numeric_size=0, r2.stack_offset=512, r2.type=stack, r2.value=[512, 2147418112],
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}
10:
  assert r2.type in {number, ctx, stack, packet, shared};
  r2 += -8;
  goto 11;

Post-invariant: [
    instruction_count=36,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.numeric_size=8, r2.stack_offset=504, r2.type=stack, r2.value=[504, 2147418104], r2.value=r10.value+8,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}

Pre-invariant : [
    instruction_count=36,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.type=number, r1.value=0,
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.numeric_size=8, r2.stack_offset=504, r2.type=stack, r2.value=[504, 2147418104], r2.value=r10.value+8,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}
11:
  r1 = map_fd 1;
  goto 13;

Post-invariant: [
    instruction_count=38,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.map_fd=1, r1.type=map_fd, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.numeric_size=8, r2.stack_offset=504, r2.type=stack, r2.value=[504, 2147418104], r2.value=r10.value+8,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}

Pre-invariant : [
    instruction_count=38,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=1,
    r1.map_fd=1, r1.type=map_fd, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.numeric_size=8, r2.stack_offset=504, r2.type=stack, r2.value=[504, 2147418104], r2.value=r10.value+8,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}
13:
  assert r1.type == map_fd;
  assert r2.type in {stack, packet};
  assert within stack(r2:key_size(r1));
  r0 = bpf_map_lookup_elem:1(map_fd r1, map_key r2);
  goto 14;

Post-invariant: [
    instruction_count=43,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.numeric_size=8, r0.shared_offset=0, r0.shared_region_size=8, r0.type=shared, r0.value=[0, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112],
    r2.numeric_size=8,
    s[504...511].value=0]
Stack: Numbers -> {[504...511]}
...
```

Looking at the above output, we see that the "Stack" section just shows the ranges of bytes
that are known to hold numeric values (i.e., not pointers).  A program will fail verification
if it tries to treat a pointer as a number, such as if it tries to copy the value into a map
where it could leak out to user mode applications.

Furthermore, the invariants track the state of ranges of stack space just like if they were
registers.  Thus in instruction 8, r1's attributes are copied to s[504...511], where they
can be later used by assertions, or used when subsequently loading a stack value into a
variable.

# 3. Some final notes about other verifier errors and warnings

Let's look at a couple of other potential errors/warnings.

```
159:727: Code is unreachable after 159:727
```

When used on a branch (i.e., `:` is in the middle of the instruction), this simply indicates
a branch that will never be taken.  This is simply a warning, not an error.  If we look at
the Post-invariant on that goto, it will look like this:
```
Post-invariant: _|_

```
where the symbol `_|_` indicates that there are no possible values.


Here's an example of another actual error:

```
3151: r0.type in {ctx, stack, packet, shared}
```

The `{...}` notation indicates a set, and the same notation can appear when showing the
state of a `.type` attribute such as:

```
r8.type in {number, ctx}
```

We hope this tutorial has been useful, and you can use these techniques when debugging your
own program verification failures.
