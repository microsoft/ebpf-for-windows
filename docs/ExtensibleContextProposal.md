# Extensible Context for Native eBPF Programs

**Status:** Proposal  
**Date:** 2026-06-12  
**Goal:** Allow extensions to append new fields to program context structs without breaking previously compiled native eBPF programs.

---

## 1. Problem Statement

The current design for native modules does not allow extending the context for a program type (i.e., adding new fields at the end of the context struct). This is because:

1. **bpf2c** computes a SHA-256 hash of the program info (including the full `ebpf_ctx_descriptor_t`) and embeds it in the native driver.
2. **ebpfcore** recomputes the hash at load time using the live extension's program info and rejects the program if the hashes don't match.
3. The `ebpf_ctx_descriptor_t.size` field reflects `sizeof(context_struct)`, so appending a field changes the size, changes the hash, and breaks loading.

This differs from Linux, where a new field can be added at the end of a context struct and older programs continue to work on newer kernels.

**Goal:** Achieve the same for Windows — if an extension adds a new field at the end of the context, a native BPF program verified against an older version of the extension should still load.

---

## 2. Current System Analysis

### 2.1 The Context Descriptor

Defined in `external/ebpf-verifier/src/spec/ebpf_base.h`:

```c
typedef struct _ebpf_context_descriptor {
    int size; // Size of ctx struct.
    int data; // Offset into ctx struct of pointer to data.
    int end;  // Offset into ctx struct of pointer to end of data.
    int meta; // Offset into ctx struct of pointer to metadata.
} ebpf_context_descriptor_t;
```

Each program type defines one of these. For example, the BIND program type in `netebpfext/net_ebpf_ext_program_info.h`:

```c
static const ebpf_ctx_descriptor_t _ebpf_bind_context_descriptor = {
    sizeof(bind_md_t),
    EBPF_OFFSET_OF(bind_md_t, app_id_start),
    EBPF_OFFSET_OF(bind_md_t, app_id_end),
    -1};
```

### 2.2 Data Flow: Extension → ebpfcore

The context descriptor is embedded in a chain of structs:

```
ebpf_ctx_descriptor_t
    ↑ (pointer)
ebpf_program_type_descriptor_t   (.context_descriptor)
    ↑ (pointer)
ebpf_program_info_t              (.program_type_descriptor)
    ↑ (pointer)
ebpf_program_data_t              (.program_info)
    │
    └── Passed via NMR (NpiSpecificCharacteristics) ──→ ebpfcore
```

Extensions register via `NmrRegisterProvider()` with `EBPF_PROGRAM_INFO_EXTENSION_IID`. ebpfcore registers as an NMR client and receives the `ebpf_program_data_t` in its attach callback (`_ebpf_program_type_specific_program_information_attach_provider`).

### 2.3 How bpf2c Computes the Hash

`get_program_info_type_hash()` in `tools/bpf2c/bpf2c.cpp` computes a **SHA-256** over the following fields, in order:

1. Program type name (string, e.g., `"bind"`)
2. **`ebpf_ctx_descriptor_t`** — the entire 16-byte struct (size, data, end, meta)
3. Program type GUID
4. `bpf_prog_type` enum value
5. `is_privileged` flag
6. Count of helpers actually called by the program
7. Per-helper (sorted by helper ID): id, name, return type, 5 argument types, optional flags

The context descriptor is hashed as raw bytes:
```cpp
hash_t::append_byte_range(byte_range, *program_info->program_type_descriptor->context_descriptor);
```

The resulting hash is embedded in the native driver as a `static const uint8_t[]` array inside a `program_entry_t` struct in the `"programs"` PE section.

### 2.4 How ebpfcore Compares the Hash

At load time, `ebpf_program_set_program_info_hash()` in `libs/execution_context/ebpf_program.c` recomputes the hash using `_ebpf_program_compute_program_information_hash()` with the **live** `ebpf_program_data_t` from the extension. It then does:

```c
if ((program->parameters.program_info_hash_length != hash_length) ||
    (memcmp(program->parameters.program_info_hash, hash, hash_length) != 0)) {
    result = EBPF_INVALID_ARGUMENT;  // REJECT
}
```

This is also re-checked on extension re-attach in `_ebpf_program_type_specific_program_information_attach_provider()`.

### 2.5 How Context Access Works at Runtime

Native programs use **hardcoded offsets from compile time**. bpf2c emits direct memory reads:

```c
READ_ONCE_64(r0, r1, OFFSET(0));  // ctx->data at offset 0
```

There is no indirection. The `ebpf_ctx_descriptor_t` is used by the PREVAIL verifier for bounds-checking during offline verification, not at execution time. This means **as long as existing field offsets don't change, old programs are safe at runtime**.

### 2.6 Why Appending Fields Breaks Loading

```
Extension v1: bind_md_t = { app_id_start, app_id_end, protocol, ... }
              context_descriptor = { .size = 48, .data = 0, .end = 8, .meta = -1 }
              → hash: 0xABCD...

Extension v2: bind_md_t = { app_id_start, app_id_end, protocol, ..., new_field }
              context_descriptor = { .size = 56, .data = 0, .end = 8, .meta = -1 }
              → hash: 0x1234...  ← DIFFERENT (only .size changed)

Native program compiled against v1 → hash 0xABCD → REJECTED on v2
```

The program never accesses `new_field` and all existing fields are at the same offsets, but the hash changes because `context_descriptor.size` changed.

---

## 3. Review of Existing Proposal (extensible_context.md)

The existing `docs/extensible_context.md` proposes a full CO-RE (Compile Once – Run Everywhere) relocation system:

- bpf2c emits offset variables in a `.ebpf_reloc` PE section
- Extensions expose a `GetFieldOffset(struct_name, field_name)` callback
- ebpfcore patches offsets at load time and freezes the section as read-only

**Assessment:** This is over-engineered for the stated requirement.

| Concern | Details |
|---------|---------|
| **Scope** | Redesigns the entire context access model |
| **Breaking change** | New bpf2c output format; all native programs must be recompiled |
| **Extension changes** | Every extension must implement a string-based field lookup callback |
| **Verification changes** | PREVAIL needs to understand sentinel offsets |
| **Unnecessary capability** | Supports field reordering, which isn't needed — Linux doesn't do this either |

---

## 4. Proposed Design: Size-Tolerant Context Hash

### 4.1 Core Insight

When a field is appended to the end of a context struct:
- `context_descriptor.size` increases
- `data`, `end`, and `meta` offsets **don't change**
- All existing field offsets **don't change**

A program verified against context size `N` that only accesses offsets `[0, N)` is safe on a context of size `M >= N`. We can solve this by:

1. **Excluding `context_descriptor.size` from the hash** — hash the shape (data/end/meta offsets) but not the total size.
2. **Storing the compile-time context size alongside the hash** — so ebpfcore can verify `runtime_size >= compile_time_size`.

### 4.2 Detailed Changes

#### Change 1: Modify Hash Computation to Exclude `context_descriptor.size`

**In bpf2c** (`tools/bpf2c/bpf2c.cpp`, `get_program_info_type_hash()`):

```cpp
// BEFORE
hash_t::append_byte_range(byte_range, *program_info->program_type_descriptor->context_descriptor);

// AFTER
hash_t::append_byte_range(byte_range, program_info->program_type_descriptor->context_descriptor->data);
hash_t::append_byte_range(byte_range, program_info->program_type_descriptor->context_descriptor->end);
hash_t::append_byte_range(byte_range, program_info->program_type_descriptor->context_descriptor->meta);
```

**In ebpfcore** (`libs/execution_context/ebpf_program.c`, `_ebpf_program_compute_program_information_hash()`):

```c
// BEFORE
EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(hash, *context_descriptor);

// AFTER
EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(hash, context_descriptor->data);
EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(hash, context_descriptor->end);
EBPF_CRYPTOGRAPHIC_HASH_APPEND_VALUE(hash, context_descriptor->meta);
```

This must be done **identically** in both places.

#### Change 2: Embed Compile-Time Context Size in Native Module

Add a new field to `program_entry_t` in `include/bpf2c.h`:

```c
typedef struct _program_entry {
    // ... existing fields ...
    const uint8_t* program_info_hash;
    size_t program_info_hash_length;
    const char* program_info_hash_type;
    size_t bpf2c_context_size;   // NEW: sizeof(context_struct) at bpf2c compile time
} program_entry_t;
```

bpf2c emits this value from the context descriptor it sees at compile time.

#### Change 3: Context Size Check in ebpfcore at Load Time

After the hash matches, verify the context size is compatible:

```c
size_t runtime_context_size =
    extension_program_data->program_info->program_type_descriptor->context_descriptor->size;
size_t compile_time_context_size = program->parameters.bpf2c_context_size;

if (compile_time_context_size > runtime_context_size) {
    // Program was compiled against a LARGER context than available.
    // Unsafe — program could access fields that don't exist.
    result = EBPF_INVALID_ARGUMENT;
    goto Exit;
}
// compile_time_context_size <= runtime_context_size → SAFE
```

#### Change 4: Hash Algorithm Version Bump for Backward Compatibility

Bump the hash algorithm identifier to distinguish old vs. new hashing:

```c
#define EBPF_HASH_ALGORITHM "SHA256v2"  // was "SHA256"
```

ebpfcore supports both:

```c
if (hash_type == "SHA256") {
    // Legacy path: compute hash the old way (including context_descriptor.size)
    // Exact match required — existing behavior, no regression.
} else if (hash_type == "SHA256v2") {
    // New path: compute hash excluding context_descriptor.size
    // + verify compile_time_context_size <= runtime_context_size
}
```

### 4.3 Files Changed

| File | Change |
|------|--------|
| `include/bpf2c.h` | Add `bpf2c_context_size` field to `program_entry_t` |
| `tools/bpf2c/bpf2c.cpp` | Hash only data/end/meta offsets; use `SHA256v2` |
| `tools/bpf2c/bpf_code_generator.cpp` | Emit `bpf2c_context_size` value in generated code |
| `tools/bpf2c/bpf_code_generator.h` | Update `EBPF_HASH_ALGORITHM` constant |
| `libs/execution_context/ebpf_program.c` | Support both hash modes; add context size check |
| `libs/execution_context/ebpf_native.c` | Pass `bpf2c_context_size` through parameters |
| `libs/execution_context/ebpf_program.h` | Add `bpf2c_context_size` to `ebpf_program_parameters_t` |

### 4.4 Compatibility Matrix

| Program compiled with | Running on old ebpfcore | Running on new ebpfcore |
|---|---|---|
| **Old bpf2c** (`SHA256`) | Works (unchanged) | Works (legacy path) |
| **New bpf2c** (`SHA256v2`) | Fails (unknown hash algo) | Works (new path) |
| **New bpf2c**, newer extension (appended fields) | N/A | Works (size-tolerant) |

The only incompatible case (new bpf2c on old ebpfcore) is expected — a new kernel is needed to support the new feature. Critically, **old native programs continue to work without recompilation**.

### 4.5 Comparison With CO-RE Proposal

| Aspect | Size-Tolerant Hash (this proposal) | CO-RE Relocation (extensible_context.md) |
|--------|-----------------------------------|----------------------------------------|
| **Lines changed** | ~200 | ~2000+ across codegen, NMR, loader |
| **Breaking changes** | None (version-gated) | Yes (new bpf2c output format) |
| **Runtime overhead** | Zero (one comparison at load) | Zero (after one-time relocation) |
| **Extension changes** | None | New `GetFieldOffset` callback per extension |
| **Verification changes** | None | Mock allocation / sentinel offset support |
| **Covers append-at-end** | Yes | Yes |
| **Covers field reordering** | No (not needed) | Yes (overkill) |

---

## 5. Constraints & Limitations

1. **Append-only** — Fields can only be added at the end of the context struct. Reordering or removing fields still breaks the hash (data/end/meta offsets would change).
2. **data/end/meta offsets are immutable** — If an extension needs to move these pointer fields, it's a breaking change regardless.
3. **Old programs cannot access new fields** — An older program won't know about new fields. This matches Linux behavior.

---

## 6. Security Considerations

- The verifier proved the program only accesses `[0, compile_time_size)`. The runtime context is `>= compile_time_size`. No out-of-bounds access is possible.
- The hash still covers all structural aspects (offsets, helpers, types) — only the total size is decoupled.
- The hash algorithm version prevents downgrade attacks (old ebpfcore won't accept new-format programs and vice versa).

---

## 7. Test Plan

1. **Backward compatibility:** Compile a native program with old bpf2c (`SHA256`), load on new ebpfcore → must succeed.
2. **Same-version:** Compile with new bpf2c (`SHA256v2`), load on matching extension version → must succeed.
3. **Forward-compatible extension:** Compile with new bpf2c against extension v1, load on extension v2 (appended fields) → must succeed.
4. **Shrunk context rejection:** Compile against extension v2, load on extension v1 (smaller context) → must fail.
5. **Modified offsets rejection:** Change data/end/meta offsets between compile and load → must fail.
6. **Helper changes rejection:** Change helper signatures between compile and load → must fail.
