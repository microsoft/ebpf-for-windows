# 1. Introduction

This tutorial illustrates how to run the Prevail verifier on Windows, starting from authoring a new program in C.

Prerequisites:
* Visual Studio 2019 (any edition)
* Git
* Clang/LLVM for Windows (download from [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe) if needed)

# 2. Authoring a simple eBPF Program

Note: This walkthrough is based on the one at [eBPF assembly with LLVM (qmonnet.github.io)](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe),
and in fact the same steps should work on both Windows and Linux, including
in WSL on Windows.  (The only exception is that the llvm-objdump utility will
fail if you have an old LLVM version in WSL, i.e., if `llvm-objdump -version`
shows only LLVM version 3.8.0, it is too old and needs to be upgraded first.)
However, we'll do the walkthrough assuming one is only using Windows.

**Step 1)** Author a new file by putting some content into a file, say bpf.c:

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
> clang -target bpf -Wall -O2 -c bpf.c -o bpf.o
```

This will compile bpf.c (into bpf.o in this example) using bpf as the
assembly format.

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
for return values) to 0, and exit.

Since we compiled the program optimized, and without debug info, that's
all we can get.

**Step 3)** Repeat the above exercise but enable debugging using `-g` and
for this walkthrough we will put the result into a separate .o file,
bpf-d.o in this example:

```
> clang -target bpf -Wall -g -O2 -c bpf.c -o bpf-d.o
```


The `llvm-objdump -S` command from step 2 will now be able to show the
source lines as well:

```
> llvm-objdump --triple=bpf -S bpf-d.o

bpf.o:  file format ELF64-BPF

Disassembly of section .text:
func:
; {
       0:       b7 00 00 00 00 00 00 00         r0 = 0
; return 0;
       1:       95 00 00 00 00 00 00 00         exit
```

**Step 4)** Learn how sections work

In steps 2 and 3, the code is placed into a section called ".text" as can be
seen from the header in the middle of the disassembly output.  One can list
all sections in the object file using -h as follows:

```
> llvm-objdump --triple=bpf -h bpf.o

bpf.o:  file format ELF64-BPF

Sections:
Idx Name          Size      Address          Type
  0               00000000 0000000000000000
  1 .strtab       0000002a 0000000000000000
  2 .text         00000010 0000000000000000 TEXT
  3 .llvm_addrsig 00000000 0000000000000000
  4 .symtab       00000030 0000000000000000
```

Notice that the only section with actual code in it (i.e., with the "TEXT"
label after it) is section 2, named ".text".  And for comparison, the
debug-enabled object file also contains various debugging info:

```
> llvm-objdump --triple=bpf -h bpf-d.o

bpf-d.o:  file format ELF64-BPF

Sections:
Idx Name          Size      Address          Type
  0               00000000 0000000000000000
  1 .strtab       000000ab 0000000000000000
  2 .text         00000010 0000000000000000 TEXT
  3 .debug_str    00000049 0000000000000000
  4 .debug_abbrev 00000037 0000000000000000
  5 .debug_info   0000004b 0000000000000000
  6 .rel.debug_info 00000090 0000000000000000
  7 .debug_macinfo 00000001 0000000000000000
  8 .debug_pubnames 0000001b 0000000000000000
  9 .rel.debug_pubnames 00000010 0000000000000000
 10 .debug_pubtypes 0000001a 0000000000000000
 11 .rel.debug_pubtypes 00000010 0000000000000000
 12 .debug_frame  00000028 0000000000000000
 13 .rel.debug_frame 00000020 0000000000000000
 14 .debug_line   0000003c 0000000000000000
 15 .rel.debug_line 00000010 0000000000000000
 16 .llvm_addrsig 00000001 0000000000000000
 17 .symtab       00000120 0000000000000000
```

The Prevail verifier also supports multiple TEXT sections, with custom
names, so let's also try using a custom name instead, say "myprog".  We
can do this by adding a pragma, where any functions following that pragma
will be put into a section with a specified name, until another such
pragma is encountered with a different name, or the end of the file is
reached.  In this way, there can even be multiple sections per source file.

Author a new file, say in "bpf2.c" this time, with another function and a
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
> clang -target bpf -Wall -O2 -c bpf2.c -o bpf2.o

> llvm-objdump --triple=bpf -h bpf2.o

bpf2.o: file format ELF64-BPF

Sections:
Idx Name          Size      Address          Type
  0               00000000 0000000000000000
  1 .strtab       00000040 0000000000000000
  2 .text         00000000 0000000000000000 TEXT
  3 myprog        00000010 0000000000000000 TEXT
  4 another       00000010 0000000000000000 TEXT
  5 .llvm_addrsig 00000000 0000000000000000
  6 .symtab       00000048 0000000000000000
```

Notice that there is still the .text section, but it has a size of 0,
because all the code is either in the "myprog" section or the "another"
section.

To dump a specific section (e.g., myprog), use the following:

```
> llvm-objdump --triple=bpf -S --section=myprog bpf2.o
```

# 3. Compiling the Prevail Verifier for Windows

**Step 1)** Get the source code, currently in the windows branch of Dave's
fork:

```
> git clone --recurse-submodules -b windows https://github.com/dthaler/ebpf-verifier.git

> cd ebpf-verifier
```

**Step 2)** Generate a solution:

```
> cmake -B build
```

This will result in a Visual Studio solution and projects getting generated
in the specified subdirectory ("build").

**Step 3)** Build the solution:

This can be done either from the command line or from within the Visual
Studio UI.

From the command line, this can be done with:

```
> cmake --build build --config Release
```

(or replace "Release" with "Debug" to build the debug configuration instead).

Or to build inside Visual Studio, open the solution in Visual Studio:

```
> ebpf-verifier.sln
```

Then compile it with "Build->Build Solution".

Building the solution may generate some compiler warnings, but should still
compile successfully:

```
... (many other messages)
1>Generating Code...
1>check.vcxproj -> C:\Temp\ebpf\ebpf-verifier\x64\Debug\check.exe
1>Done building project "check.vcxproj".
========== Build: 1 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========
```

# 4. Running the Prevail verifier on Windows

**Step 1)** Enumerate sections

In step 4 of part 2, we saw how to use `llvm-objdump -h` to list all sections
in an object file.  We'll now do the same with the Prevail verifier by using
the `-l` argument (replace "Release" in the path with "Debug" if you only
built a Debug version in step 3):

```
> Release\check.exe -l ..\bpf.o
.text

> Release\check.exe -l ..\bpf-d.o
.text

> Release\check.exe -l ..\bpf2.o
myprog another
```

Notice that it only lists non-empty TEXT sections, whereas `llvm-objdump -h`
showed all sections.  That's because the verifier is just looking for eBPF
programs, which are always in non-empty TEXT sections.

**Step 2)** Run the verifier on our sample program

```
> Release\check.exe ..\bpf.o
1,0.011,6672
```

The first number "1" indicates that verification passed ("0" would show for
a failure).

The second number ("0.014" here) indicates the amount of CPU time consumed,
in seconds.

The third number ("6644" here) indicates the amount of memory consumed during
the verification process, in kB.

One can see the labels for these values via:

```
> Release\check.exe @headers
zoneCrab?,zoneCrab_sec,zoneCrab_kb
```

This is so a .csv file can be generated by running the above command,
followed by running the verifier on any number of .o files, and redirecting
all the results to a file that can then be opened in a spreadsheet such as
Excel.

The first verification command succeeded because there was only one
non-empty TEXT section in bpf.o, so the verifier found it and used that
as the eBPF program to verify.  If we try the same on an object file with
multiple such sections, we instead get this:

```
> Release\check.exe ..\bpf2.o
please specify a section
available sections:
myprog another
```

This is because the verifier needs to run on a single eBPF program, i.e.,
a single TEXT section.  For object files with multiple such sections, we
must specify the section to use, to disambiguate:

```
> Release\check.exe ..\bpf2.o myprog
1,0.012,6656

> Release\check.exe ..\bpf2.o another
1,0.01,6668
```

**Step 2)** View disassembly

In step 2 of part 2, we saw how to use "llvm-objdump -S" to view disassembly.
We'll now do the same with the Prevail verifier.  Normally it would save
output to a file, but we can use the special "CON" file in Windows to output
to stdout:

```
> Release\check.exe --asm CON ..\bpf.o
       0:       r0 = 0
       1:       exit
1,0.014,6644
```

You can see that the two instructions match the two seen back in step 2 of
part 2, and then the verification results are shown.  Again for bpf2.o we
would need to specify which section to use, since there is more than one:

```
> Release\check.exe --asm CON ..\bpf2.o myprog
       0:       r0 = 0
       1:       exit
1,0.02,6628

> Release\check.exe --asm CON ..\bpf2.o another
       0:       r0 = 1
       1:       exit
1,0.019,6664
```

**Step 3)** View program stats

One can view various stats about the program, without running the
verification process:

```
> Release\check.exe --domain=stats @headers
hash,instructions,basic_blocks,joins,other,jumps,assign,arith,load,store,load_store,packet_access,call_1,call_mem,call_nomem,adjust_head,map_in_map,arith64,arith32

> Release\check.exe --domain=stats ..\bpf.o
b4a9048dc70e4fd,2,2,0,2,0,1,0,0,0,0,0,0,0,0,0,0,1,0
```

So for our tiny bpf.c program that just does `return 0;`, we can see that
it has 2 instructions, in 2 basic blocks, with 1 assign and no jumps or
joins.  Again these outputs are formatted such that one can construct a .csv
file by running the `@headers` command followed by the second command on any
number of .o files.

**Step 4)** View verifier verbose output

We can view verbose output to see what the verifier is actually doing,
using the `-v` argument:

```
> Release\check.exe -v ..\bpf.o

{r10 -> [512, +oo], off10 -> [512], t10 -> [-2], r1 -> [1, 2147418112], off1 -> [0], t1 -> [-3], packet_size -> [0, 65534], meta_offset -> [-4098, 0]
}
Numbers -> {}
0:
  r0 = 0;
  goto 1;

{r10 -> [512, +oo], off10 -> [512], t10 -> [-2], r1 -> [1, 2147418112], off1 -> [0], t1 -> [-3], packet_size -> [0, 65534], meta_offset -> [-4098, 0], r0 -> [0], t0 -> [-4]
}
Numbers -> {}

{r10 -> [512, +oo], off10 -> [512], t10 -> [-2], r1 -> [1, 2147418112], off1 -> [0], t1 -> [-3], packet_size -> [0, 65534], meta_offset -> [-4098, 0], r0 -> [0], t0 -> [-4]
}
Numbers -> {}
1:
  assert r0 : num;
  exit;


{r10 -> [512, +oo], off10 -> [512], t10 -> [-2], r1 -> [1, 2147418112], off1 -> [0], t1 -> [-3], packet_size -> [0, 65534], meta_offset -> [-4098, 0], r0 -> [0], t0 -> [-4]
}
Numbers -> {}


0 warnings
1,0.029,6692
```

Normally we wouldn't need to do this, but it is illustrative to see how the
verifier works.

Each instruction is shown as before, but is preceded by its preconditions
(or inputs), and followed by its postconditions (or outputs).

"oo" means infinity, "r0" through "r10" are registers (r10 is the stack
pointer, r0 is used for return values, r1-5 are used to pass args to other
functions, r6 is the 'ctx' pointer, etc., "t0" through "t10" contains the
type of value in the associated register, where -4 means an integer, etc.

"meta_offset" is the number of bytes of packet metadata preceding (i.e.,
with negative offset from) the start of the packet buffer.

# 5. Advanced Topics

## 5.1. Hooks and arguments

Hook points are callouts exposed by the system to which eBPF programs can
attach.  By convention, the section name of the eBPF program in an ELF file
is commonly used to designate which hook point the eBPF program is designed
for.  Specifically, a set of prefix strings are used to match against the
section name.  For example, any section name starting with "xdp" is meant
as an XDP layer program.  This is a convenient default, but can be
overridden by an app, such as when the eBPF program is simply in the
".text" section.

Each hook point has a specified prototype which must be understood by the
verifier.  That is, the verifier needs to understand all the hooks for the
specified platform on which the eBPF program will execute.  The hook points
are in general different for Linux vs. Windows, as are the prototypes for
hook points that might be similarly named.

Typically the first and only argument of the hook point is a context
structure which contains an arbitrary amount of data.  (Tail calls to
programs can have more than one argument, but hooks put all the info in a
hook-specific context structure passed as one argument.)

Let's say that the "xdp" hook point has the following prototype:

```
// xdp.h

struct ebpf_xdp_args {
    int length;
};

typedef int (*xdp_callout)(struct ebpf_xdp_args* args);
```

A sample eBPF program might look like this:

```
#include "xdp.h"

// Put "xdp" in the section name to specify XDP as the hook.
// The __attribute__ below has the same effect as the
// clang pragma used in section 2 of this tutorial.
__attribute__((section("xdp"), used))
int my_xdp_parser(struct ebpf_xdp_args* args)
{
    int length = args->length;

    if (length > 1) {
        return 1; // allow
    }
    return 0;     // block
}
```

The verifier needs to be enlightened with the same prototype or all
programs written for that hook will fail verification.  For Windows,
this info is in the ebpf-verifier\src\windows\windows_platform.cpp file,
which for the above prototype might have:

```
constexpr EbpfContextDescriptor xdp_context_descriptor = {
    4, // Size of ctx struct.
    -1, // Offset into ctx struct of pointer to data, or -1 if none.
    -1, // Offset into ctx struct of pointer to end of data, or -1 if none.
    0, // Offset into ctx struct of pointer to metadata, or -1 if none.
};

const EbpfProgramType windows_xdp_program_type =
    PTYPE("xdp",    // Just for printing messages to users.
          xdp_context_descriptor,
          EBPF_PROG_TYPE_XDP,
          {"xdp"}); // Set of section name prefixes for matching.
```

Let's look at the code above in more detail.  The EbpfContextDescriptor
info (i.e., xdp_context_descriptor) tells the verifier about the format
of the context structure (i.e., struct ebpf_xdp_args). The struct is
4 bytes long, does not include packet data, and so the scalar fields that
are safe to access start at offset 0.

With the above, our sample program will pass verification (note the
`-p windows` to tell the verifier to use the Windows platform data
instead of the Linux platform data):

```
> Release\check.exe -p windows -f myxdp.o

0 warnings
1,0.148,6336
```

What would have happened had the prototype not matched?  Let's say the
verifier is the same as above but xdp.h instead had a different struct
definition:

```
struct ebpf_xdp_args {
    int dummy;
    int length;
};
```

Now our sample program that checks the length would now be looking for
the length starting at offset 4, which is larger than what the verifier
thinks the context structure size is, and the verifier fails the program:

```
> Release\check.exe -p windows -f myxdp2.o

entry:
  Upper bound must be lower than 4 (valid_access(r1, 4:4))
  Invariant became _|_ after entry

1 warnings
0,0.05,6184
```

Notice that the verifier is complaining about access to memory pointed to
by R1 (since the first argument is in register R1) past the end of the
valid buffer of size 4.  This illustrates why ideally the same header
file (xdp.h in the above example) should be included by the ebpf program,
the component exposing the hook, and the verifier itself, e.g., so that
the size of the context struct could be `sizeof(struct ebpf_xdp_args)`
rather than hardcoding the number 4 in the above example.

## 5.2. Helper functions and arguments

Now that we've seen how hooks work, let's look at how calls from an eBPF
program into helper functions exposed by the system are verified.
As with hook prototypes, the set of helper functions and their prototypes
can vary by platform.  Helpers for Linux are documented in the
[IOVisor docs](https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst).

Let's say the following helper function prototype is exposed by Windows:

```
// helpers.h
static int (*ebpf_get_tick_count)(void* ctx) = (void*) 3;
```

A sample eBPF program that uses it might look like this:

```
#include "helpers.h"

int func(void* ctx)
{
    return ebpf_get_tick_count(ctx);
}
```

Let's compile it and see what it looks like.   Here we compile with `-g`
to include source line info:

```
> clang -target bpf -Wall -g -O2 -c helpers.c -o helpers.o

> llvm-objdump --triple bpf -S helpers.o

helpers.o: file format ELF64-BPF

Disassembly of section .text:
func:
; {
       0:       85 00 00 00 03 00 00 00         call 3
; return ebpf_get_tick_count(ctx);
       1:       95 00 00 00 00 00 00 00         exit
```

Now let's see how the verifier deals with this.  The verifier needs to
know the prototype in order to verify that eBPF program passes arguments
correctly, and handles the results correct (e.g., not passing an invalid
value in a pointer argument).

The verifier calls into a `get_helper_prototype(3)` API exposed by
platform-specific code to query the prototype for a given helper function.
The platform-specific code will return an entry like this one:

```
    {
        // int ebpf_get_tick_count(void* ctx);
        .name = "ebpf_get_tick_count",
        .return_type = EbpfHelperReturnType::INTEGER,
        .argument_type = {
            EbpfHelperArgumentType::PTR_TO_CTX,
            EbpfHelperArgumentType::DONTCARE,
            EbpfHelperArgumentType::DONTCARE,
            EbpfHelperArgumentType::DONTCARE,
            EbpfHelperArgumentType::DONTCARE,
        }
    },
```

The above helps the verifier know the type and semantics of the arguments
and the return value.

```
> Release\check.exe -p windows --asm CON -f helpers.o
       0:       r0 = ebpf_get_tick_count:3(r1:CTX)
       1:       exit


0 warnings
1,0.007,6020
```

As shown above, verification is successful, and check.exe understands
the function name, and knows that the first argument is the context.

### 5.2.1. Why -O2?

This section is a slight digression, so skip ahead if you prefer.  It's
important that we compiled with `-O2` throughout this tutorial.  What
happens if we didn't compile with `-O2`?  The disassembly looks instead
like this:

```
func:
; {
       0:       bf 12 00 00 00 00 00 00         r2 = r1
       1:       7b 1a f8 ff 00 00 00 00         *(u64 *)(r10 - 8) = r1
; return bpf_get_socket_uid(ctx);
       2:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00         r1 = 0 ll
       4:       79 11 00 00 00 00 00 00         r1 = *(u64 *)(r1 + 0)
       5:       79 a3 f8 ff 00 00 00 00         r3 = *(u64 *)(r10 - 8)
       6:       7b 1a f0 ff 00 00 00 00         *(u64 *)(r10 - 16) = r1
       7:       bf 31 00 00 00 00 00 00         r1 = r3
       8:       79 a3 f0 ff 00 00 00 00         r3 = *(u64 *)(r10 - 16)
       9:       7b 2a e8 ff 00 00 00 00         *(u64 *)(r10 - 24) = r2
      10:       8d 00 00 00 03 00 00 00         callx 3
      11:       95 00 00 00 00 00 00 00         exit
```

The helper function is called in line 10 via the `callx` instruction
(0x8d), but importantly that instruction *is not listed in the
[eBPF spec](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)*!
Furthermore, the Prevail verifier's ELF parser also has problems with it.
Let's see
why.  Unlike the optimized disassembly where the helper id is encoded in
the instruction, here the value 47 (0x2f) is encoded in the data section:

```
> llvm-objdump --triple bpf -s helpers.o --section .data

helpers.o:       file format ELF64-BPF

Contents of section .data:
0000 2f000000 00000000                    /.......
```

An entry also appears in the relocation section, which we can see as follows.
Since we compiled with `-g`, there are also relocation sections for debug
symbols so we use `-section` to specify the code (i.e., text) section only,
where without it llvm-objdump will dump all of them.

```
> llvm-objdump --triple bpf --section .rel.text -r helpers.o

helpers.o:       file format ELF64-BPF

RELOCATION RECORDS FOR [.rel.text]:
0000000000000010 R_BPF_64_64 bpf_get_socket_uid
```

However the verifier's ELF parser only handles relocation records for
maps, not helper functions, since in "correct" eBPF bytecode (i.e.,
bytecode conforming to the eBPF spec), relocation records are always for
maps.  So if you forget to compile with -O2, it will fail elf parsing even
before trying to verify the bytecode.

## 5.3. Maps

Now that we've seen how helpers work, let's move on to
[maps](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps),
which are memory structures that can be shared between eBPF programs and/or
applications.  They are typically used to store state between invocations
of eBPF programs, or to expose information (e.g., statistics) to applications.

To see how maps are exposed to eBPF programs, let's first start from a
plain eBPF program:

```
__attribute__((section("myprog"), used))
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
#include <stdint.h>

struct ebpf_map {
    uint32_t size;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
};
#define BPF_MAP_TYPE_PERCPU_ARRAY 1

__attribute__((section("maps"), used))
struct ebpf_map map =
    {sizeof(struct ebpf_map), BPF_MAP_TYPE_PERCPU_ARRAY, 2, 4, 512};

__attribute__((section("myprog"), used))
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
> llvm-objdump -s -section maps maponly.o

maponly.o:      file format ELF64-BPF

Contents of section maps:
 0000 14000000 01000000 02000000 04000000  ................
 0010 00020000                             ....
```

Now to make use of the map, we have to use helper functions to access it:
```
void *ebpf_map_lookup_elem(struct ebpf_map* map, const void* key);
long ebpf_map_update_elem(struct ebpf_map* map, const void* key, const void* value, uint64_t flags);
long ebpf_map_delete_elem(struct ebpf_map* map, const void* key);
```

Let's update the program to write the value "42" to the map section for the
current CPU, by changing the "myprog" section to the following:
```
static void* (*ebpf_map_lookup_elem)(struct ebpf_map* map, const void* key) = (void*) 0;
static int (*ebpf_map_update_elem)(struct ebpf_map *map, const void *key, const void *value, uint64_t flags) = (void*) 1;

__attribute__((section("myprog"), used))
int func1()
{
    uint32_t key = 0;
    uint32_t value = 42;
    int result = ebpf_map_update_elem(&map, &key, &value, 0);
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
; int result = ebpf_map_update_elem(&map, &key, &value, 0);
       8:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00         r1 = 0 ll
      10:       b7 04 00 00 00 00 00 00         r4 = 0
      11:       85 00 00 00 01 00 00 00         call 1
; return result;
      12:       95 00 00 00 00 00 00 00         exit
```

Above shows "call 1", but check.exe shows more details:
```
> check -p windows --asm CON  -f map.o
       0:       r1 = 0
       1:       *(u32 *)(r10 - 4) = r1
       2:       r1 = 42
       3:       *(u32 *)(r10 - 8) = r1
       4:       r2 = r10
       5:       r2 += -4
       6:       r3 = r10
       7:       r3 += -8
       8:       r1 = map_fd 65664
      10:       r4 = 0
      11:       r0 = ebpf_map_update_elem:1(r1:FD, r2:K, r3:V, r4)
      12:       exit


0 warnings
1,0.057,6256
````

Notice from instruction 11 that check.exe understands that
ebpf_map_update_elem expects
a file descriptor (FD) in R1, a key in R2, a value in R3, and R4 can be
anything.

R1 was set in instruction 8 to a map FD value of 65664.  Where did that value
come from, since the llvm-objdump disassembly didn't have it?  The
create_map_crab() function in the Prevail verifier creates a dummy value
based on (value_size * 16384) + (key_size * 64).  Since we passed
value_size = 4 and key_size = 2, this gives us 65664.  When installed,
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

This record means that the actual address of map should be inserted at
offset 0x40, but where is that?  llvm-objdump and check both gave us
instruction numbers not offsets, but we can see the raw bytes as follows:

```
> >llvm-objdump -s -section=myprog map.o

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
