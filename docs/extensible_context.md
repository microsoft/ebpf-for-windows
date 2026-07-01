Markdown

\# Architectural Design Specification: Zero-Overhead Context Relocation (Windows CO-RE) for ebpf-for-windows



This document defines the architectural specification to implement a \*\*Compile Once – Run Everywhere (CO-RE)\*\* relocation mechanism for `ebpf-for-windows`. This design eliminates the rigid cryptographic context-hash validation blocking backward compatibility, enabling eBPF programs to remain compatible across different OS versions without sacrificing runtime performance or violating the offline verification model.



\---



\## 1. Executive Summary \& Problem Statement



In the current `ebpf-for-windows` architecture, the `bpf2c` tool translates eBPF bytecode into native C code, which is then compiled into a standard Windows driver (`.sys` binary). During this translation, context structure offsets (e.g., `struct bpf\_sock\_ops`) are hardcoded into the instruction stream as explicit pointer-arithmetic constants based on compilation-time headers.



To ensure type and memory safety, `bpf2c` embeds a cryptographic hash of the verification-time context structure layout into the binary. When the driver attempts to load, `ebpfcore` validates this hash against the hosting extension's layout hash via the Network Module Registrar (NMR) interface. If any field is appended or shifted in a newer OS version, the hashes mismatch, and the driver fails to load.



\### Target Constraints

\* \*\*Zero Runtime Performance Overhead:\*\* Context accesses must not introduce dynamic lookups, hash-map queries, or pointer-indirection overhead during hot-path execution (e.g., networking packet processing).

\* \*\*Preservation of Offline Verification:\*\* The pipeline must still mathematically prove memory isolation and safety using the PREVAIL verifier during the offline build phase, where no live Windows kernel or extensions are present.



\---



\## 2. Solution Architecture: Context Access Virtualization



The proposed design shifts context layout resolution from \*\*Compile-Time Hardcoding\*\* to \*\*Load-Time Relocation Patching\*\*. Instead of hardcoding offsets, `bpf2c` emits relocatable global variables located in a dedicated, page-aligned memory section. These variables are patched exactly \*once\* by the eBPF kernel framework during the driver initialization phase and subsequently frozen as read-only.



The process is split cleanly across two execution timelines:

1\. \*\*Build Time (Offline):\*\* Proves memory boundaries against an abstract baseline context structure layout.

2\. \*\*Run Time (Kernel Load):\*\* Intercepts the loading driver, queries the active environment's NMR extension for true offsets, patches the variables, and locks the memory section.



\---



\## 3. Detailed Component Specifications



\### Phase A: `bpf2c` Code Generation Changes



`bpf2c` must be updated to replace explicit pointer offsets with descriptive, external relocation variables. These variables must reside within a dedicated memory section (`.ebpf\_reloc`).



\#### 1. Generated Dynamic Context Reference

Instead of emitting:

```c

// Legacy Code Generation

uint32\_t port = \*(uint32\_t\*)((char\*)ctx + 24);

bpf2c must generate:



C

\#include <ntddk.h>



// Declare the relocation variable within a dedicated tracking section

\#pragma section(".ebpf\_reloc", read, write)

\_\_declspec(allocate(".ebpf\_reloc")) \_\_declspec(selectany) 

ULONG32\_OFF\_struct\_bpf\_sock\_ops\_remote\_port = 0xFFFFFFFF; // Sentinel default



void bpf\_program\_entry(void\* ctx) {

&#x20;   // Zero-overhead dynamic offset evaluation

&#x20;   ULONG32 offset = ULONG32\_OFF\_struct\_bpf\_sock\_ops\_remote\_port;

&#x20;   uint32\_t port = \*(uint32\_t\*)((char\*)ctx + offset);

&#x20;   // ... rest of program logic

}

2\. Relocation Metadata Table

bpf2c must append an exported structure array at the end of the generated C source code. This acts as the manifest allowing the kernel loader to discover and map the placeholder variables.



C

typedef struct \_EBPF\_CONTEXT\_RELOCATION\_ENTRY {

&#x20;   const char\* struct\_name;

&#x20;   const char\* field\_name;

&#x20;   ULONG32\* offset\_variable\_ptr;

&#x20;   ULONG32     fallback\_offset;      // Derived from build-time headers

&#x20;   ULONG32     field\_size;           // Size of the data type being read

} EBPF\_CONTEXT\_RELOCATION\_ENTRY;



\_\_declspec(allocate(".ebpf\_reloc"))

EBPF\_CONTEXT\_RELOCATION\_ENTRY ContextRelocationTable\[] = {

&#x20;   { "bpf\_sock\_ops", "remote\_port", \&ULONG32\_OFF\_struct\_bpf\_sock\_ops\_remote\_port, 24, sizeof(uint32\_t) },

&#x20;   { NULL, NULL, NULL, 0, 0 } // Null terminator

};

Phase B: Offline Verification Modification

Because the PREVAIL verifier executes completely offline without access to a running Windows environment or active extensions, it cannot resolve variables initialized to a sentinel value (0xFFFFFFFF).



The Isolation Strategy

Mock Allocation: Before invoking the PREVAIL verifier library, bpf2c mocks the relocation variables in its internal state, assigning them their local compilation-time fallback\_offset values.



Boundary Assertions: PREVAIL runs its mathematical validation under the assumption that the context structure matches this local definition.



The Validation Constraint: PREVAIL enforces that all memory reads must reside inside the total allocated size boundary of the compilation-time structure (e.g., sizeof(struct bpf\_sock\_ops) as defined in the local headers). If a program attempts to access an offset past this boundary, the verifier rejects the binary offline.



Phase C: NMR Interface Modifications

To pass dynamic offset layouts instead of a rigid cryptographic layout hash, the Network Module Registrar (NMR) contract between ebpfcore (the registrar) and the context-specific extensions (the providers) must be expanded.



1\. Provider Characteristics Update

Modify the core registration contract passed during NmrRegisterProvider to expose an offset-resolution callback:



C

typedef struct \_EBPF\_PROGRAM\_PROVIDER\_CHARACTERISTICS\_V2 {

&#x20;   GUID ProgramType;

&#x20;   size\_t ContextSize;

&#x20;   

&#x20;   // Schema Resolution Callback

&#x20;   NTSTATUS (\*GetFieldOffset)(

&#x20;       \_In\_ const char\* struct\_name,

&#x20;       \_In\_ const char\* field\_name,

&#x20;       \_Out\_ ULONG32\* resolved\_offset

&#x20;   );

} EBPF\_PROGRAM\_PROVIDER\_CHARACTERISTICS\_V2;

2\. Extension Side Implementation (e.g., Network Extension Driver)

The extension utilizes standard compile-time offsetof() calls matching its target OS environment to answer queries dynamically:



C

NTSTATUS Extension\_GetFieldOffset(

&#x20;   \_In\_ const char\* struct\_name,

&#x20;   \_In\_ const char\* field\_name,

&#x20;   \_Out\_ ULONG32\* resolved\_offset

) {

&#x20;   if (strcmp(struct\_name, "bpf\_sock\_ops") == 0) {

&#x20;       if (strcmp(field\_name, "remote\_port") == 0) {

&#x20;           \*resolved\_offset = (ULONG32)offsetof(struct bpf\_sock\_ops, remote\_port);

&#x20;           return STATUS\_SUCCESS;

&#x20;       }

&#x20;       if (strcmp(field\_name, "local\_port") == 0) {

&#x20;           \*resolved\_offset = (ULONG32)offsetof(struct bpf\_sock\_ops, local\_port);

&#x20;           return STATUS\_SUCCESS;

&#x20;       }

&#x20;   }

&#x20;   return STATUS\_NOT\_FOUND;

}

Phase D: Kernel Loader Fix-up Engine (ebpfcore)

When a compiled native eBPF .sys driver is registered into the Windows kernel, ebpfcore intercepts initialization to perform the single-pass fix-up routine.



The Fix-up Loop Blueprint

C

NTSTATUS ResolveContextRelocations(PROV\_HANDLE ebpf\_driver\_handle, EBPF\_PROGRAM\_PROVIDER\_CHARACTERISTICS\_V2\* provider) {

&#x20;   // 1. Locate the exported metadata table symbol from the loaded image

&#x20;   EBPF\_CONTEXT\_RELOCATION\_ENTRY\* table = FetchSymbol(ebpf\_driver\_handle, "ContextRelocationTable");

&#x20;   if (!table) return STATUS\_SUCCESS; 



&#x20;   // 2. Elevate section protection temporarily to allow patching

&#x20;   SetSectionProtection(ebpf\_driver\_handle, ".ebpf\_reloc", PAGE\_READWRITE);



&#x20;   for (int i = 0; table\[i].struct\_name != NULL; i++) {

&#x20;       ULONG32 actual\_offset = 0;

&#x20;       

&#x20;       // 3. Query the active extension via the modified NMR callback

&#x20;       NTSTATUS status = provider->GetFieldOffset(table\[i].struct\_name, table\[i].field\_name, \&actual\_offset);

&#x20;       

&#x20;       if (!NT\_SUCCESS(status)) {

&#x20;           // Fallback to compilation-time offset if field is missing on this OS version

&#x20;           actual\_offset = table\[i].fallback\_offset;

&#x20;       }



&#x20;       // 4. CRITICAL SAFETY GUARD: Verify the runtime layout doesn't violate 

&#x20;       // the boundary math originally proved during offline verification.

&#x20;       if (actual\_offset + table\[i].field\_size > provider->ContextSize) {

&#x20;           // Overwriting this would cause an out-of-bounds kernel panic

&#x20;           SetSectionProtection(ebpf\_driver\_handle, ".ebpf\_reloc", PAGE\_ONLY);

&#x20;           return STATUS\_EBPF\_CORRUPTED\_CONTEXT\_BOUNDS;

&#x20;       }



&#x20;       // 5. Patch the variable location

&#x20;       \*(table\[i].offset\_variable\_ptr) = actual\_offset;

&#x20;   }



&#x20;   // 6. Freeze the memory section permanently into PAGE\_READONLY

&#x20;   SetSectionProtection(ebpf\_driver\_handle, ".ebpf\_reloc", PAGE\_READONLY);



&#x20;   return STATUS\_SUCCESS;

}

4\. Performance \& Security Analysis

Execution Performance Verification

This architecture introduces zero execution overhead on the runtime hot-path.



Register-relative addressing (char\* ctx + offset) compiles down to a basic native assembly sequence.



Because the .ebpf\_reloc memory section is modified exactly once and permanently frozen as PAGE\_READONLY, these variables remain highly optimized within CPU L1/L2 caches across subsequent execution loops.



No memory allocations, marshalling, or "thunking" steps occur during hot-path execution.



Security Assertions

Accidental/Malicious Tampering Prevention: Forcing the .ebpf\_reloc section to a read-only state via PAGE\_READONLY prevents any user-mode or compromised kernel component from rewriting offsets post-initialization.



Out-of-Bounds Protection: The explicit ContextSize validation step inside the runtime fix-up engine blocks the driver from loading if a structural shift on a modified OS would result in data access beyond the boundary verified by PREVAIL.

