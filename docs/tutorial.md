# 1. Introduction

This tutorial illustrates how eBPF works and in particular how the eBPF verifier works on Windows,
starting from authoring a new eBPF program in C.

To try out this tutorial yourself, you will need:

- Clang and nuget from [Prerequisites tools](GettingStarted.md#Prerequisites).
- a VM that can [load a Windows driver](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#installing-ebpf-for-windows).
  - Follow the [VM install instructions](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/vm-setup.md) to get started quickly.
- [eBPF installed](https://github.com/microsoft/ebpf-for-windows/blob/main/docs/InstallEbpf.md) on the VM. Using the MSI installer from a release is the fastest way to get started.
- ebpf-for-windows nuget package: `nuget install eBPF-for-Windows`

We'll start by understanding the basic structure of eBPF programs and then walk through how to
apply them in a real use case.

# 2. Authoring a simple eBPF Program

Note: This walkthrough is based on the one at [eBPF assembly with LLVM (qmonnet.github.io)](https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/),
and in fact the same steps should work on both Windows and Linux, including
in WSL on Windows.  (The only exception is that the llvm-objdump utility will
fail if you have an old LLVM version in WSL, i.e., if `llvm-objdump -version`
shows only LLVM version 3.8.0, it is too old and needs to be upgraded first.)
However, we'll do this walkthrough assuming one is only using Windows.

**Step 1)** Author a new file by putting some content into a file, say `bpf.c`:

```
int func()
{
    return 0;
}
```

For this example, that's all the content that's needed, no #includes or
anything.

**Step 2)** Compile optimized code with clang as follows:

```
> clang -target bpf -Werror -O2 -c bpf.c -o bpf.o
```

This will compile `bpf.c` (into `bpf.o` in this example) using bpf as the assembly format,
since eBPF has its own [instruction set architecture (ISA)](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md).

To see what clang did, we can generate disassembly as follows:

```
> llvm-objdump --triple=bpf -S bpf.o

bpf.o:  file format ELF64-BPF

Disassembly of section .text:
func:
       0:       b7 00 00 00 00 00 00 00         r0 = 0
       1:       95 00 00 00 00 00 00 00         exit
```

You can see that all the program does is set register 0 (the register used
for return values in the eBPF ISA) to 0, and exit.

Since we compiled the program optimized, and without debug info, that's
all we can get.

**Step 3)** Repeat the above exercise but enable debugging using `-g` and
for this walkthrough we will put the result into a separate `.o` file,
`bpf-d.o` in this example:

```
> clang -target bpf -Werror -g -O2 -c bpf.c -o bpf-d.o
```


The `llvm-objdump -S` command from step 2 will now be able to show the
source lines as well:

```
> llvm-objdump --triple=bpf -S bpf-d.o

bpf-d.o:        file format ELF64-BPF


Disassembly of section .text:

0000000000000000 func:
;     return 0;
       0:       b7 00 00 00 00 00 00 00 r0 = 0
       1:       95 00 00 00 00 00 00 00 exit
```

Adding the `-l` option as well will also show the source file and line number above
the source line itself.

```
>llvm-objdump --triple=bpf -S -l bpf-d.o

bpf-d.o:        file format ELF64-BPF


Disassembly of section .text:

0000000000000000 func:
; C:\your\path\here/bpf.c:3
;     return 0;
       0:       b7 00 00 00 00 00 00 00 r0 = 0
       1:       95 00 00 00 00 00 00 00 exit
```

**Step 4)** Learn how sections work

In steps 2 and 3, the code is placed into a section called ".text" as can be
seen from the header in the middle of the disassembly output.  One can list
all sections in the object file using `-h` as follows:

```
> llvm-objdump --triple=bpf -h bpf.o

bpf.o:  file format ELF64-BPF

Sections:
Idx Name          Size      Address          Type
  0               00000000 0000000000000000
  1 .strtab       00000030 0000000000000000
  2 .text         00000010 0000000000000000 TEXT
  3 .llvm_addrsig 00000000 0000000000000000
  4 .symtab       00000048 0000000000000000
```

Notice that the only section with actual code in it (i.e., with the "TEXT"
label after it) is section 2, named ".text".  And for comparison, the
debug-enabled object file also contains various debugging info:

```
> llvm-objdump --triple=bpf -h bpf-d.o

bpf-d.o:        file format ELF64-BPF

Sections:
Idx Name             Size     VMA              Type
  0                  00000000 0000000000000000
  1 .strtab          0000008c 0000000000000000
  2 .text            00000010 0000000000000000 TEXT
  3 .debug_str       00000073 0000000000000000
  4 .debug_abbrev    00000037 0000000000000000
  5 .debug_info      0000004b 0000000000000000
  6 .rel.debug_info  00000090 0000000000000000
  7 .BTF             000000b2 0000000000000000
  8 .BTF.ext         00000050 0000000000000000
  9 .rel.BTF.ext     00000020 0000000000000000
 10 .debug_frame     00000028 0000000000000000
 11 .rel.debug_frame 00000020 0000000000000000
 12 .debug_line      0000003c 0000000000000000
 13 .rel.debug_line  00000010 0000000000000000
 14 .llvm_addrsig    00000000 0000000000000000
 15 .symtab          00000120 0000000000000000
```

The static verifier that checks the safety of eBPF programs also supports multiple TEXT sections, with custom
names, so let's also try using a custom name instead, say "myprog".  We
can do this by adding a pragma, where any functions following that pragma
will be put into a section with a specified name, until another such
pragma is encountered with a different name, or the end of the file is
reached.  In this way, there can even be multiple sections per source file.

Author a new file, say in `bpf2.c` this time, with another function and a
pragma above each one:

```
#pragma clang section text="myprog"

int func()
{
    return 0;
}

#pragma clang section text="another"

int anotherfunc()
{
    return 1;
}
```

If we now compile the above code as before we can see the new list of sections.

```
> clang -target bpf -Werror -O2 -c bpf2.c -o bpf2.o

> llvm-objdump --triple=bpf -h bpf2.o

bpf2.o: file format ELF64-BPF

Sections:
Idx Name          Size     VMA              Type
  0               00000000 0000000000000000
  1 .strtab       00000047 0000000000000000
  2 .text         00000000 0000000000000000 TEXT
  3 myprog        00000010 0000000000000000 TEXT
  4 another       00000010 0000000000000000 TEXT
  5 .llvm_addrsig 00000000 0000000000000000
  6 .symtab       00000060 0000000000000000
```

Notice that there is still the .text section, but it has a size of 0,
because all the code is either in the "myprog" section or the "another"
section.

To dump a specific section (e.g., myprog), use the following:

```
> llvm-objdump --triple=bpf -S --section=myprog bpf2.o
```

# 3. Verifying eBPF programs on Windows

Normally verification happens at the time an eBPF program is submitted to be loaded.  That can be done,
but in this tutorial, we'll just do verification _without_ needing to load the program.  This allows this
tutorial to be done on any machine, not just one with the eBPF driver installed into the kernel.

**Step 1)** Enumerate sections

In step 4 of part 2, we saw how to use `llvm-objdump -h` to list all sections
in an object file.  We'll now do the same with netsh.  Do the following from
the directory you used for part 1:

```
> netsh ebpf show sections bpf.o

             Section    Type  # Maps    Size
====================  ======  ======  ======
               .text  unspec       0       2

> netsh ebpf show sections bpf-d.o

             Section    Type  # Maps    Size
====================  ======  ======  ======
               .text  unspec       0       2

> netsh ebpf show sections bpf2.o

             Section    Type  # Maps    Size
====================  ======  ======  ======
              myprog  unspec       0       2
             another  unspec       0       2
```

Notice that it only lists non-empty TEXT sections, whereas `llvm-objdump -h`
showed all sections.  That's because the netsh command is just looking for eBPF
programs, which are always in non-empty TEXT sections.

`netsh` allows all keywords to be abbreviated, so we could have done
`netsh ebpf sh sec bpf.o` instead.  Throughout this tutorial, we'll always spell
things out for readability, but feel free to abbreviate to save typing.

**Step 2)** Run the verifier on our sample program

```
> netsh ebpf show verification bpf.o type=xdp

Verification succeeded
Program terminates within 6 instructions
```

The verification command succeeded because there was only one
non-empty TEXT section in bpf.o, so the verifier found it and used that
as the eBPF program to verify.  If we try the same on an object file with
multiple such sections, we get this:

```
> netsh ebpf show verification bpf2.o type=xdp

Verification succeeded
Program terminates within 6 instructions
```

This is because the verifier ran on the *first* eBPF program it found,
which was "myprog" in the section listing.  We can explicitly
specify the section to use as follows:

```
> netsh ebpf show verification bpf2.o myprog type=xdp

Verification succeeded
Program terminates within 6 instructions

> netsh ebpf show verification bpf2.o another type=xdp

Verification succeeded
Program terminates within 6 instructions
```

**Step 2)** View disassembly

In step 2 of part 2, we saw how to use "llvm-objdump -S" to view disassembly.
We'll now do the same with netsh:

```
> netsh ebpf show disassembly bpf.o
       0:       r0 = 0
       1:       exit

> netsh ebpf show disassembly bpf-d.o
; C:\your\path\here/bpf.c:3
;     return 0;
       0:       r0 = 0
       1:       exit
```

You can see that the two instructions match the two seen back in step 2 of
part 2.  Again for bpf2.o we
can specify which section to use, since there is more than one:

```
> netsh ebpf show disassembly bpf2.o myprog
       0:       r0 = 0
       1:       exit

> netsh ebpf show disassembly bpf2.o another
       0:       r0 = 1
       1:       exit
```

**Step 3)** View program stats

One can view various stats about the program, without running the
verification process, using the "level=verbose" option to "show section":

```
> netsh ebpf show section bpf.o .text verbose

Section      : .text
Program Type : xdp
# Maps       : 0
Size         : 2 instructions
adjust_head  : 0
arith        : 0
arith32      : 0
arith64      : 1
assign       : 1
basic_blocks : 2
call_1       : 0
call_mem     : 0
call_nomem   : 0
joins        : 0
jumps        : 0
load         : 0
load_store   : 0
map_in_map   : 0
other        : 2
packet_access: 0
store        : 0
```

So for our tiny bpf.c program that just does `return 0;`, we can see that
it has 2 instructions, in 2 basic blocks, with 1 assign and no jumps or
joins.

**Step 4)** View verifier verbose output

We can view verbose output to see what the verifier is actually doing,
using the "level=verbose" option to "show verification":

```
> netsh ebpf show verification bpf.o type=xdp level=verbose

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
  r0 = 0;
  goto 1;

Post-invariant: [
    instruction_count=3,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=0,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=3,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=0,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
1:
  assert r0.type == number;
  exit;
  goto exit;

Post-invariant: [
    instruction_count=6,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=0,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}

Pre-invariant : [
    instruction_count=6,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=0,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}
exit:


Post-invariant: [
    instruction_count=7,
    meta_offset=[-4098, 0],
    packet_size=[0, 65534],
    r0.type=number, r0.value=0,
    r1.ctx_offset=0, r1.type=ctx, r1.value=[1, 2147418112],
    r10.numeric_size=0, r10.stack_offset=512, r10.type=stack, r10.value=[512, 2147418112]]
Stack: Numbers -> {}


Verification succeeded
Program terminates within 6 instructions

```

Normally we wouldn't need to do this, but it is illustrative to see how the
verifier works.

Each instruction is shown as before, but is preceded by its preconditions
(or inputs), and followed by its postconditions (or outputs).

"oo" means infinity, "r0" through "r10" are registers (r10 is the stack
pointer, r0 is used for return values, r1-5 are used to pass args to other
functions, r6 is the 'ctx' pointer, etc.

"meta_offset" is the number of bytes of packet metadata preceding (i.e.,
with negative offset from) the start of the packet buffer, "packet_size"
shows the range of sizes that the packet is known to fall within. Looking
at the last Post-invariant, we see that r0 contains the number 0, r1
contains a pointer to the ctx (context) with offset 0, r10 points to the
top of the stack, and nothing is known about the contents of the stack.

# 4. Advanced Topics

## 4.1. Hooks and arguments

Hook points are callouts exposed by the system to which eBPF programs can
attach.  By convention, the section name of the eBPF program in an ELF file
is commonly used to designate which hook point the eBPF program is designed
for.  Specifically, a set of prefix strings are typically used to match against the
section name.  For example, any section name starting with "xdp" is meant
as an XDP layer program.  This is a convenient default, but can be
overridden by an app asking to load an eBPF program, such as when the eBPF program is simply in the
".text" section.

Each hook point has a specified prototype which must be understood by the
verifier.  That is, the verifier needs to understand all the hooks for the
specified platform on which the eBPF program will execute.  The hook points
are in general different for Linux vs. Windows, as are the prototypes for
hook points, though some may be cross-platform.

Typically the first and only argument of the hook point is a context
structure which contains an arbitrary amount of data.  (Tail calls to
programs can have more than one argument, but hooks put all the info in a
hook-specific context structure passed as one argument.)

The "xdp" hook point has the following prototype in `ebpf_nethooks.h`:

```
typedef struct xdp_md
{
    void* data;               // Pointer to start of packet data.
    void* data_end;           // Pointer to end of packet data.
    uint64_t data_meta;       // Packet metadata.
    uint32_t ingress_ifindex; // Ingress interface index.
} xdp_md_t;

typedef enum _xdp_action
{
    XDP_PASS = 1, // Allow the packet to pass.
    XDP_DROP,     // Drop the packet.
    XDP_TX        // Bounce the received packet back out the same NIC it arrived on.
} xdp_action_t;

typedef xdp_action_t xdp_hook_t(xdp_md_t* context);
```

A sample eBPF program might look like this:

```
#include "bpf_helpers.h"
#include "ebpf_nethooks.h"

// Put "xdp" in the section name to specify XDP as the hook.
// The SEC macro below has the same effect as the
// clang pragma used in section 2 of this tutorial.
SEC("xdp")
int my_xdp_parser(xdp_md_t* ctx)
{
    int length = (char *)ctx->data_end - (char *)ctx->data;

    if (length > 1) {
        return XDP_PASS;
    }
    return XDP_DROP;
}
```

The verifier needs to be enlightened with the same prototype or all
programs written for that hook will fail verification.  For Windows,
information comes from the registry (HKCU:\Software\eBPF\Providers\SectionData)
which will look like:

```
> ls HKCU:\Software\eBPF\Providers\SectionData


    Hive: HKEY_CURRENT_USER\Software\eBPF\Providers\SectionData


Name                           Property
----                           --------
bind                           ProgramType   : {124, 81, 140, 96...}
                               AttachType    : {4, 126, 112, 185...}
                               BpfProgType   : 2
                               BpfAttachType : 2
cgroup/connect4                ProgramType   : {57, 142, 236, 146...}
                               AttachType    : {177, 55, 46, 168...}
                               BpfProgType   : 3
                               BpfAttachType : 3
cgroup/connect6                ProgramType   : {57, 142, 236, 146...}
                               AttachType    : {178, 55, 46, 168...}
                               BpfProgType   : 3
                               BpfAttachType : 4
cgroup/recv_accept4            ProgramType   : {57, 142, 236, 146...}
                               AttachType    : {179, 55, 46, 168...}
                               BpfProgType   : 3
                               BpfAttachType : 5
cgroup/recv_accept6            ProgramType   : {57, 142, 236, 146...}
                               AttachType    : {180, 55, 46, 168...}
                               BpfProgType   : 3
                               BpfAttachType : 6
sample_ext                     ProgramType   : {74, 239, 136, 247...}
                               AttachType    : {75, 239, 136, 247...}
                               BpfProgType   : 999
                               BpfAttachType : 8
sockops                        ProgramType   : {77, 34, 251, 67...}
                               AttachType    : {205, 2, 125, 131...}
                               BpfProgType   : 4
                               BpfAttachType : 7
xdp                            ProgramType   : {133, 42, 131, 241...}
                               AttachType    : {239, 216, 224, 133...}
                               BpfProgType   : 1
                               BpfAttachType : 1
```

With the above, our sample program will pass verification:

```
> clang -I ../../include -target bpf -Werror -O2 -c myxdp.c -o myxdp.o

> netsh ebpf show verification myxdp.o

Verification succeeded
Program terminates within 30 instructions
```

What would have happened had the prototype not matched?  Let's say the
verifier is the same as above but XDP instead had a different struct
definition:

```
typedef struct _xdp_md_t
{
    uint64_t more;
    uint64_t stuff;
    uint64_t here;
    void* data;
    void* data_end;
    uint64_t data_meta;
} xdp_md_t;
```

Now our sample program that checks the length would now be looking for
the data starting at offset 24, which is past the end of what the verifier
thinks the context structure size is, and the verifier fails the program:

```
> netsh ebpf show verification myxdp.o
Verification failed

Verification report:

1: Upper bound must be at most 32 (valid_access(r1.offset+32, width=8))

1 errors
```

Notice that the verifier is complaining about access to memory pointed to
by r1 (since the first argument is in register R1) past the end of the
valid buffer of size 32.  This illustrates why ideally the same header
file (ebpf_nethooks.h in the above example) should be used by the eBPF program,
the component exposing the hook, and the verifier itself, e.g., so that
the size of the context struct could be `sizeof(xdp_md_t)`
rather than hardcoding the number 32 in the above example.

## 4.2. Helper functions and arguments

Now that we've seen how hooks work, let's look at how calls from an eBPF
program into helper functions exposed by the system are verified.
As with hook prototypes, the set of helper functions and their prototypes
can vary by platform.  For comparison, helpers for Linux are documented in the
[IOVisor bpf helpers documentation](https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst).

Let's say the following helper function prototype is exposed by Windows:

```
#define EBPF_HELPER(return_type, name, args) typedef return_type(*name##_t) args
EBPF_HELPER(int64_t, bpf_map_update_elem, (struct bpf_map * map, void* key, void* value, uint64_t flags));
```

We'll cover in section 6.3 what this function does, but for now we only care about the prototype.
We can create a sample (but, as we will see, invalid) program like so:

```
#include "bpf_helpers.h"

int func()
{
    int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
    return result;
}
```

Let's compile it and see what it looks like.   Here we compile with `-g`
to include source line info:

> Note: Replace `.\eBPF-for-Windows.<X.Y.Z>\build\native\include\` with the path to the ebpf-for-windows nuget `./include` directory (should be in the directory where you ran `nuget install eBPF-for-Windows`). This is the first time we included header files while building so we need to use the Windows eBPF headers which we get from the nuget package.

```bash
# Replace X.Y.Z with the actual version of eBPF being used.
> clang -I .\eBPF-for-Windows.X.Y.Z\build\native\include\ -target bpf -Werror -g -O2 -c helpers.c -o helpers.o

> llvm-objdump --triple bpf -S helpers.o

helpers.o:      file format ELF64-BPF

Disassembly of section .text:
0000000000000000 func:
; {
       0:       b7 01 00 00 00 00 00 00         r1 = 0
; int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
       1:       b7 02 00 00 00 00 00 00         r2 = 0
       2:       b7 03 00 00 00 00 00 00         r3 = 0
       3:       b7 04 00 00 00 00 00 00         r4 = 0
       4:       85 00 00 00 02 00 00 00         call 2
; return result;
       5:       95 00 00 00 00 00 00 00         exit
```

Now let's see how the verifier deals with this.  The verifier needs to
know the prototype in order to verify that the eBPF program passes arguments
correctly, and handles the results correctly (e.g., not passing an invalid
value in a pointer argument).

The verifier calls into a `get_helper_prototype(2)` API exposed by
platform-specific code to query the prototype for a given helper function.
The platform-specific code ([ebpf_general_helpers.cpp](../libs/execution_context/ebpf_general_helpers.cpp))
will return an entry like this one:

```
    {BPF_FUNC_map_update_elem,
     "bpf_map_update_elem",
     EBPF_RETURN_TYPE_INTEGER,
     {EBPF_ARGUMENT_TYPE_PTR_TO_MAP, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_KEY, EBPF_ARGUMENT_TYPE_PTR_TO_MAP_VALUE}},
```

The above helps the verifier know the type and semantics of the arguments
and the return value.

```
> netsh ebpf show disassembly helpers.o
; C:\your\path\here/helpers.c:5
;     int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
       0:       r1 = 0
       1:       r2 = 0
       2:       r3 = 0
       3:       r4 = 0
       4:       r0 = bpf_map_update_elem:2(map_fd r1, map_key r2, map_value r3, uint64_t r4)
; C:\your\path\here/helpers.c:6
;     return result;
       5:       exit

> netsh ebpf show verification helpers.o type=xdp
Verification failed

Verification report:

; C:\your\path\here/helpers.c:5
;     int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
4: r1.type == map_fd
; C:\your\path\here/helpers.c:5
;     int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
4: r2.type in {stack, packet}
; C:\your\path\here/helpers.c:5
;     int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
4: Map key size is not singleton
; C:\your\path\here/helpers.c:5
;     int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
4: r3.type in {stack, packet}
; C:\your\path\here/helpers.c:5
;     int result = bpf_map_update_elem((struct bpf_map*)0, (uint32_t*)0, (uint32_t*)0, 0);
4: Map value size is not singleton

5 errors
```

As shown above, the verifier understands the function name and prototype,
and knows that the program is invalid because it is passing null instead
of a valid value.  We'll come back to this in section 6.3 to see how to
use the helper correctly.

## 4.3. Maps

Now that we've seen how helpers work, let's move on to
[maps](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps),
which are memory structures that can be shared between eBPF programs and/or
applications.  They are typically used to store state between invocations
of eBPF programs, or to expose information (e.g., statistics) to applications.

To see how maps are exposed to eBPF programs, let's first start from a
plain eBPF program:

```
SEC("myprog")
int func()
{
    return 0;
}
```

We can add a reference to a map to which the program will have access
by creating a `maps` section as follows.  We'll use a "per-CPU array"
in this example so that there are no race conditions or corrupted data
if multiple instances of our program are simultaneously running on different
CPUs.


```
#include "bpf_helpers.h"

SEC("maps")
struct bpf_map map =
    {sizeof(struct bpf_map), BPF_MAP_TYPE_PERCPU_ARRAY, 2, 4, 512};

SEC("myprog")
int func()
{
    return 0;
}
```

So far the program doesn't actually use the map, but the presence of
the maps section means that when the program is loaded, the system
will look for the given map and create one if it doesn't already exist,
using the map parameters specified.  We can see the fields encoded
into the `maps` section as follows:

```
# Replace X.Y.Z with the actual version of eBPF being used.
> clang -I -I .\eBPF-for-Windows.X.Y.Z\build\native\include\ -target bpf -Werror -g -O2 -c maponly.c -o maponly.o
> llvm-objdump -s -section maps maponly.o

maponly.o:      file format ELF64-BPF

Contents of section maps:
 0000 24000000 05000000 02000000 04000000  $...............
 0010 00020000 00000000 00000000 00000000  ................
 0020 00000000                             ....
```

Now to make use of the map, we have to use helper functions to access it:
```
void *bpf_map_lookup_elem(struct bpf_map* map, const void* key);
int bpf_map_update_elem(struct bpf_map* map, const void* key, const void* value, uint64_t flags);
int bpf_map_delete_elem(struct bpf_map* map, const void* key);
```

Let's update the program to write the value "42" to the map section for the
current CPU, by changing the "myprog" section to the following:
```
SEC("myprog")
int func1()
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = bpf_map_update_elem(&map, &key, &value, 0);
    return result;
}
```

This program results in the following disassembly:
```
> llvm-objdump -S -section=myprog map.o

map.o:  file format ELF64-BPF

Disassembly of section myprog:
func1:
; {
       0:       b7 01 00 00 00 00 00 00         r1 = 0
; uint32_t key = 0;
       1:       63 1a fc ff 00 00 00 00         *(u32 *)(r10 - 4) = r1
       2:       b7 01 00 00 2a 00 00 00         r1 = 42
; uint32_t value = 42;
       3:       63 1a f8 ff 00 00 00 00         *(u32 *)(r10 - 8) = r1
       4:       bf a2 00 00 00 00 00 00         r2 = r10
; uint32_t key = 0;
       5:       07 02 00 00 fc ff ff ff         r2 += -4
       6:       bf a3 00 00 00 00 00 00         r3 = r10
       7:       07 03 00 00 f8 ff ff ff         r3 += -8
; int result = bpf_map_update_elem(&map, &key, &value, 0);
       8:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00         r1 = 0 ll
      10:       b7 04 00 00 00 00 00 00         r4 = 0
      11:       85 00 00 00 02 00 00 00         call 2
; return result;
      12:       95 00 00 00 00 00 00 00         exit
```

Above shows "call 2", but `netsh` shows more details
```
> netsh ebpf show disassembly map.o
; C:\your\path\here/map.c:8
; int func1()
       0:       r1 = 0
; C:\your\path\here/map.c:10
;     uint32_t key = 0;
       1:       *(u32 *)(r10 - 4) = r1
       2:       r1 = 42
; C:\your\path\here/map.c:11
;     uint32_t value = 42;
       3:       *(u32 *)(r10 - 8) = r1
       4:       r2 = r10
       5:       r2 += -4
       6:       r3 = r10
       7:       r3 += -8
; C:\your\path\here/map.c:12
;     int result = bpf_map_update_elem(&map, &key, &value, 0);
       8:       r1 = map_fd 1
      10:       r4 = 0
      11:       r0 = bpf_map_update_elem:2(map_fd r1, map_key r2, map_value r3, uint64_t r4)
; C:\your\path\here/map.c:13
;     return result;
      12:       exit
````

Notice from instruction 11 that `netsh` understands that `bpf_map_update_elem()` expects
a map file descriptor (FD) in R1, a map key in R2, and a map value in R3.

R1 was set in instruction 8 to a map FD value of 1.  Where did that value
come from, since the llvm-objdump disassembly didn't have it?  The
create_map_crab() function in the Prevail verifier creates a dummy value
starting at 1.  When loaded into an execution context,
this value gets replaced with a real map address.  Let's see how that happens.

Now that we're actually using the map, rather than just defining it,
the relocation section is also populated.  The relocation section for
a program is in a section with the ".rel" prefix followed by the
program section name ("myprog" in this example):

```
> llvm-objdump --triple bpf -section=.relmyprog -r map.o

map.o:  file format ELF64-BPF

RELOCATION RECORDS FOR [.relmyprog]:
0000000000000040 R_BPF_64_64 map
```

This record means that the actual address of `map` should be inserted at
offset 0x40, but where is that?  llvm-objdump and check both gave us
instruction numbers not offsets, but we can see the raw bytes as follows:

```
> llvm-objdump -s -section=myprog map.o

map.o:  file format ELF64-BPF

Contents of section myprog:
 0000 b7010000 00000000 631afcff 00000000  ........c.......
 0010 b7010000 2a000000 631af8ff 00000000  ....*...c.......
 0020 bfa20000 00000000 07020000 fcffffff  ................
 0030 bfa30000 00000000 07030000 f8ffffff  ................
 0040 18010000 00000000 00000000 00000000  ................
 0050 b7040000 00000000 85000000 01000000  ................
 0060 95000000 00000000                    ........
```

We see that offset 0x40 has "18010000 00000000 00000000 00000000".
Looking back at the llvm-objdump disassembly above, we see that
is indeed instruction 8.

So, to summarize, the verifier operates on pseudo FDs, not actual
FDs or addresses.  When the program is actually installed, the relocation
section will be used to insert the actual map address into the executable
code.

## 5. Installing eBPF programs

`netsh ebpf` can also install your eBPF program. As an example, the program we created above won't do much but we can install it via:

```
netsh ebpf add program .\myxdp.o xdp
```

To see it installed:

```
> netsh ebpf show programs

    ID  Pins  Links  Mode       Type           Name
======  ====  =====  =========  =============  ====================
 65568     1      1  JIT        xdp            my_xdp_parser
```

And remove it by the id, which we saw above is 65568:

```
> netsh ebpf delete program 65568
```

You can also install and interact with the eBPF programs programmatically. See https://github.com/microsoft/ebpf-for-windows-demo for examples.

Learn more about using eBPF at https://github.com/microsoft/ebpf-for-windows/blob/main/docs/GettingStarted.md#using-ebpf-for-windows

# 7. Next steps

Once you've completed this tutorial, you may want to check out our
[tutorial on debugging eBPF verification failures](debugging.md).
