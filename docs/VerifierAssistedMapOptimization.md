# Verifier-Assisted Inline Array Map Lookup Optimization for bpf2c

## 1. Problem Statement

Today, bpf2c generates code where **every** helper function call (including
`bpf_map_lookup_elem`) goes through an indirect function pointer:

```c
r1 = POINTER(runtime_context->map_data[2].address);  // LDDW loads map
r0 = runtime_context->helper_data[4].address(r1, r2, r3, r4, r5, context);
```

For `BPF_MAP_TYPE_ARRAY`, the lookup is a simple bounds check and array index:

```c
if (key < max_entries)
    return &map->data[key * value_size];
```

This indirect call overhead is unnecessary when the map type and dimensions are
known at compile time.

## 2. Goal

Enable bpf2c to **inline array map lookups** by leveraging the PREVAIL
verifier's abstract domain to deterministically identify which map each helper
call operates on, eliminating the indirect function call for the most common
map operations.

## 3. Design Approach: Verifier Abstract Domain

The PREVAIL verifier performs abstract interpretation over the eBPF program's
control flow graph. At each instruction, it maintains an `EbpfDomain` that
tracks register types and values through all possible execution paths. For map
helper calls, the domain can answer:

- **`get_map_fd_range(Reg{1})`**: What range of map fds could `r1` hold?
  If the result is a **singleton** (start_fd == end_fd), the map is
  unambiguous across all paths.

- **`get_map_type(Reg{1})`**: What type is the map? Returns an `optional`
  value; only has a value if all maps in the fd range have the same type.

These answers are **sound** — the verifier has already proven the program is
safe, so if it says r1 holds exactly one map, that is guaranteed to be true at
runtime.

### The map name bridging problem

The verifier and bpf2c use **different numbering schemes** for maps:

| System | Key | Numbering |
|--------|-----|-----------|
| PREVAIL verifier | `original_fd` | 1-based pseudo file descriptors |
| bpf2c | `map_definitions[name].index` | Sequential 0-based insertion order |
| Generated code | `map_data[index]` | Same as bpf2c index |

These numbering schemes are **not aligned** — maps may be parsed in different
orders by the ELF parser (BTF metadata order) vs bpf2c (ELF section order).

**Solution**: The annotation carries the **map name** (string) from the
verifier's `EbpfMapDescriptor`. bpf2c looks up the name in its own
`map_definitions` to get the correct runtime index. This is safe because both
systems parse the same ELF file and use the same symbol names for maps.

## 4. Architecture

### Data flow

```
 ┌──────────────┐         ┌────────────────────────┐
 │  bpf2c.cpp   │────────▶│  PREVAIL Verifier       │
 │              │  ELF    │                          │
 │              │◀────────│  analyze() →             │
 │              │  bool + │  AnalysisResult          │
 │              │  stats  │    .invariants[Label]     │
 │              │         │      .pre: EbpfDomain     │
 │              │         │        .get_map_fd_range()│ ◄── public
 │              │         │        .get_map_type()    │ ◄── public
 │              │         └────────────────────────┘
 │              │
 │              │◀──── ebpf_get_map_annotations_from_verifier()
 │              │      returns: [{offset, helper_id, map_name, type, ...}]
 └──────┬───────┘
        │  map_name lookup in map_definitions
        ▼
 ┌──────────────┐
 │  bpf_code_   │  For ARRAY + map_lookup_elem:
 │  generator   │  → inline bounds check + direct array index
 │              │  → prefetch hint for next map access
 │  For others: │  → standard helper call (unchanged)
 └──────────────┘
```

### Annotation struct (`ebpf_api.h`)

```c
typedef struct _ebpf_verifier_map_info
{
    uint32_t instruction_offset; ///< BPF program counter of the CALL instruction.
    int32_t helper_id;           ///< Helper function ID (e.g., BPF_FUNC_map_lookup_elem).
    const char* map_name;        ///< Map name from ELF (NULL if ambiguous).
    uint32_t map_type;           ///< Map type (e.g., BPF_MAP_TYPE_ARRAY).
    uint32_t value_size;         ///< Map value size in bytes.
    uint32_t max_entries;        ///< Map maximum entries.
    bool is_inner_map_template;  ///< True if this map is only an inner map template.
} ebpf_verifier_map_info_t;
```

### Annotation extraction (in `api_common.cpp`)

After `prevail::analyze()` returns the `AnalysisResult`, the code iterates
all invariants. Labels that are jump targets, have non-empty stack frame
prefixes, or are special labels are skipped. For each remaining `Call`
instruction with `is_map_lookup == true`:

1. Query `pre.get_map_fd_range(Reg{1}, &start_fd, &end_fd)`.
2. If the query fails or is **not** a singleton (`start_fd != end_fd`),
   skip — map is ambiguous.
3. Query `pre.get_map_type(Reg{1})`. If it returns no value, skip —
   type is ambiguous.
4. Look up `original_fd` in `ProgramInfo::map_descriptors` to find the
   `EbpfMapDescriptor` with the map's **name**, `value_size`, `max_entries`,
   and `is_inner_map_template`.
5. If the descriptor has no name, skip — can't match to bpf2c's definitions.
6. Store the annotation in thread-local storage.

The annotation strings are stored in a `std::deque<std::string>` (TLS) to
ensure `c_str()` pointers remain stable as new entries are added. The
annotation array is a `std::vector<ebpf_verifier_map_info_t>` (TLS). Both
are cleared at the start of each verification and when TLS is torn down.

### Annotation retrieval API

```c
_Must_inspect_result_ ebpf_result_t
ebpf_get_map_annotations_from_verifier(
    _Outptr_result_buffer_maybenull_(*count) const ebpf_verifier_map_info_t** annotations,
    _Out_ size_t* count) EBPF_NO_EXCEPT;
```

Returns a pointer to the TLS-owned annotation array. The caller must not free
the result, and must consume it before the next verification call.

### Annotation consumption (in `bpf_code_generator.cpp`)

bpf2c stores annotations in an `unordered_map<uint32_t, ebpf_verifier_map_info_t>`
keyed by `instruction_offset` for O(1) lookup during code generation.

At each `BPF_FUNC_map_lookup_elem` CALL instruction:

1. Look up `_map_annotations[instruction_offset]`.
2. If found and `map_type == BPF_MAP_TYPE_ARRAY` and `map_name != NULL`
   and `!is_inner_map_template`:
3. Look up `map_definitions.find(map_name)` → get bpf2c's own map index.
4. Emit inline array lookup using compile-time constants.
5. Otherwise, emit standard indirect helper call.

## 5. Generated Code

### Before (indirect helper call):

```c
r1 = POINTER(runtime_context->map_data[0].address);
r2 = r10;
r2 += IMMEDIATE(-84);
r0 = runtime_context->helper_data[1].address(r1, r2, r3, r4, r5, context);
```

### After (inline array lookup):

```c
r1 = POINTER(runtime_context->map_data[0].address);
r2 = r10;
r2 += IMMEDIATE(-84);
{
    uint32_t _array_key = *(uint32_t*)(uintptr_t)r2;
    if (_array_key < 1) {
        r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data +
             (uint64_t)_array_key * 4);
    } else {
        r0 = 0;
    }
}
```

## 6. Runtime Support

### `map_data_t` extension

Added `array_data` field to `map_data_t` in `bpf2c.h`:

```c
typedef struct _map_data
{
    ebpf_native_module_header_t header;
    uintptr_t address;        // Existing: opaque map handle
    uint8_t* array_data;      // NEW: direct pointer to array data (NULL for non-array maps)
} map_data_t;
```

### Backward compatibility

The native module loader uses element-size-based versioning to support both
old modules (without `array_data`) and new modules (with `array_data`).

In `shared_common.c`, two supported sizes are registered in the version table:

```c
#define EBPF_NATIVE_MAP_DATA_SIZE_0 EBPF_SIZE_INCLUDING_FIELD(map_data_t, address)
#define EBPF_NATIVE_MAP_DATA_SIZE_1 EBPF_SIZE_INCLUDING_FIELD(map_data_t, array_data)
size_t _ebpf_native_map_data_supported_size[] = {
    EBPF_NATIVE_MAP_DATA_SIZE_0,
    EBPF_NATIVE_MAP_DATA_SIZE_1
};
```

In `ebpf_native.c`, the function `_ebpf_native_get_map_data_element_size()`
determines which layout a module expects by comparing the module's bpf2c
version against `{1, 2, 0}` (the minimum version that supports `array_data`):

```c
static const bpf2c_version_t _ebpf_version_map_data_v2 = {1, 2, 0};

static size_t
_ebpf_native_get_map_data_element_size(_In_ const ebpf_native_module_t* module)
{
    if (_ebpf_compare_versions(&module->version, &_ebpf_version_map_data_v2) >= 0) {
        return EBPF_SIZE_INCLUDING_FIELD(map_data_t, array_data);
    } else {
        return EBPF_SIZE_INCLUDING_FIELD(map_data_t, address);
    }
}
```

This ensures that old native drivers compiled before this feature still load
correctly — they get a smaller `map_data` element that excludes `array_data`.

### Native loader population

In `ebpf_native.c`, after resolving map addresses, the loader populates
`array_data` only if the module's element size is large enough to include the
field. It calls `ebpf_map_get_value_address()` which returns the base pointer
to the array map's contiguous data region. For non-`BPF_MAP_TYPE_ARRAY` maps,
`ebpf_map_get_value_address()` returns `EBPF_INVALID_ARGUMENT` and
`array_data` is set to NULL:

```c
if (map_data_element_size >= EBPF_SIZE_INCLUDING_FIELD(map_data_t, array_data)) {
    uintptr_t value_address = 0;
    if (ebpf_map_get_value_address((ebpf_map_t*)map_addresses[i], &value_address) == EBPF_SUCCESS) {
        map_data_entry->array_data = (uint8_t*)value_address;
    } else {
        map_data_entry->array_data = NULL;
    }
}
```

## 7. Correctness Guarantees

| Concern | Guarantee |
|---------|-----------|
| **Map identity** | Verifier's `EbpfDomain` proves r1 holds a **singleton** map fd — unambiguous across all control-flow paths |
| **Map index** | Annotation carries the **map name**; bpf2c looks it up in its own `map_definitions` by name → correct index by construction |
| **Control flow** | Verifier's abstract interpretation is sound — if it reports singleton, the map is the same on all paths |
| **Value size** | Taken from `EbpfMapDescriptor::value_size`, same source as what the kernel uses to allocate the array |
| **Inner maps** | Inner map templates are excluded via `is_inner_map_template` check in both annotation extraction and code generation |
| **Fallback** | If verifier reports ambiguous fd range, ambiguous type, missing map name, inner map template, or non-ARRAY type → standard helper call emitted |
| **No PREVAIL internal access** | Only uses public API methods on `EbpfDomain` |

## 8. Changes Summary

### PREVAIL verifier changes (for separate PR to ebpf-verifier)

| File | Change |
|------|--------|
| `src/spec/type_descriptors.hpp` | Added `std::string name` and `bool is_inner_map_template` to `EbpfMapDescriptor` |
| `src/crab/ebpf_domain.hpp` | Made `get_map_type()`, `get_map_fd_range()`, `get_map_value_size()`, `get_map_max_entries()`, `get_map_key_size()`, `get_map_inner_map_fd()` **public** |
| `src/io/elf_map_parser.cpp` | Populated `.name` on all `EbpfMapDescriptor` creation sites (BTF maps, global vars, legacy maps) |

### ebpf-for-windows changes

| File | Change |
|------|--------|
| `include/ebpf_api.h` | `ebpf_verifier_map_info_t` struct + `ebpf_get_map_annotations_from_verifier()` API |
| `libs/api_common/api_common.cpp` | Annotation extraction using `EbpfDomain::get_map_fd_range()` and `get_map_type()`. TLS storage with `std::deque` for name stability. |
| `ebpfapi/Source.def` | Export `ebpf_get_map_annotations_from_verifier` |
| `tools/bpf2c/bpf2c.cpp` | Calls annotation API after verification, passes to generator via `set_map_annotations()` |
| `tools/bpf2c/bpf_code_generator.h` | `set_map_annotations()` method, `_map_annotations` unordered_map keyed by instruction offset |
| `tools/bpf2c/bpf_code_generator.cpp` | Inline array lookup code generation + cache prefetch for next map access |
| `include/bpf2c.h` | `uint8_t* array_data` field in `map_data_t` |
| `libs/shared/shared_common.c` | `EBPF_NATIVE_MAP_DATA_SIZE_1` entry for new map_data size |
| `libs/execution_context/ebpf_native.c` | `_ebpf_native_get_map_data_element_size()` version check + `array_data` population via `ebpf_map_get_value_address()` |
| `libs/execution_context/ebpf_maps.c` | `ebpf_map_get_value_address()` accessor returning array map's data pointer |
| `libs/execution_context/ebpf_maps.h` | Declaration of `ebpf_map_get_value_address()` |

## 9. Scope and Limitations

### Optimized (Phase 1)

| Helper | Map Type | Condition |
|--------|----------|-----------|
| `bpf_map_lookup_elem` | `BPF_MAP_TYPE_ARRAY` | Verifier proves singleton map fd at call site, map is not an inner map template |

### Not optimized (falls back to helper call)

- Verifier reports ambiguous map fd (multiple maps possible on different paths).
- Verifier reports ambiguous map type.
- Map descriptor has no name (e.g., unnamed maps).
- Map name not found in bpf2c's `map_definitions`.
- Map is an inner map template (`is_inner_map_template == true`).
- Non-array map types (hash, LRU, ring buffer, etc.).
- `bpf_map_update_elem`, `bpf_map_delete_elem` (future work).
- `BPF_MAP_TYPE_PERCPU_ARRAY` (different data layout).

### Future extensions

| Helper | Map Type | Optimization |
|--------|----------|-------------|
| `bpf_map_update_elem` | `BPF_MAP_TYPE_ARRAY` | Inline bounds check + memcpy |
| `bpf_map_delete_elem` | `BPF_MAP_TYPE_ARRAY` | Inline bounds check + memset |
