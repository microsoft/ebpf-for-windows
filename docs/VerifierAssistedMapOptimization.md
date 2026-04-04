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

- **`get_map_type(Reg{1})`**: What type is the map? Only returns a value if
  all maps in the fd range have the same type.

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
 │              │         │        .get_map_fd_range()│ ◄── public (new)
 │              │         │        .get_map_type()    │ ◄── public (new)
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
 │              │
 │  For others: │  → standard helper call (unchanged)
 └──────────────┘
```

### Annotation extraction (in `api_common.cpp`)

After `prevail::analyze()` returns the `AnalysisResult`, the code iterates
all invariants. For each `Call` instruction with `is_map_lookup == true`:

1. Query `pre.get_map_fd_range(Reg{1}, &start_fd, &end_fd)`.
2. If **not** a singleton (`start_fd != end_fd`), skip — map is ambiguous.
3. Query `pre.get_map_type(Reg{1})` to get the map type.
4. Look up `original_fd` in `ProgramInfo::map_descriptors` to find the
   `EbpfMapDescriptor` with the map's **name**, value_size, and max_entries.
5. Store the annotation in thread-local storage.

### Annotation consumption (in `bpf_code_generator.cpp`)

At each `BPF_FUNC_map_lookup_elem` CALL instruction:

1. Look up `map_annotations[instruction_offset]`.
2. If found and `map_type == BPF_MAP_TYPE_ARRAY` and `map_name != NULL`:
3. Look up `map_definitions.find(map_name)` → get bpf2c's own map index.
4. Emit inline array lookup using compile-time constants.
5. Otherwise, emit standard helper call.

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
    if (_array_key < 64) {
        r0 = (uint64_t)(uintptr_t)(runtime_context->map_data[0].array_data +
             (uint64_t)_array_key * 8);
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
    uint8_t* array_data;      // NEW: direct pointer to array data
} map_data_t;
```

Version bumped from 1 to 2. The `shared_common.c` version table supports both
old (version 0, address only) and new (version 1, with array_data) modules
for backward compatibility.

### Native loader population

In `ebpf_native.c`, after resolving map addresses, the loader calls the
existing `ebpf_map_get_value_address()` accessor. For `BPF_MAP_TYPE_ARRAY`
maps this returns the `data` pointer; for all others it returns failure and
`array_data` is set to NULL.

## 7. Correctness Guarantees

| Concern | Guarantee |
|---------|-----------|
| **Map identity** | Verifier's `EbpfDomain` proves r1 holds a **singleton** map fd — unambiguous across all control-flow paths |
| **Map index** | Annotation carries the **map name**; bpf2c looks it up in its own `map_definitions` by name → correct index by construction |
| **Control flow** | Verifier's abstract interpretation is sound — if it reports singleton, the map is the same on all paths |
| **Value size** | Taken from `EbpfMapDescriptor::value_size`, same source as what the kernel uses to allocate the array |
| **Fallback** | If verifier reports ambiguous fd range, or map name unresolvable, or type is not ARRAY → standard helper call emitted |
| **No PREVAIL internal access** | Only uses public API methods on `EbpfDomain` |

## 8. Changes Summary

### PREVAIL verifier changes (for separate PR to ebpf-verifier)

| File | Change |
|------|--------|
| `src/spec/type_descriptors.hpp` | Added `std::string name` to `EbpfMapDescriptor` |
| `src/crab/ebpf_domain.hpp` | Made `get_map_type()`, `get_map_fd_range()`, `get_map_value_size()`, `get_map_max_entries()`, `get_map_key_size()`, `get_map_inner_map_fd()` **public** |
| `src/io/elf_map_parser.cpp` | Populated `.name` on all `EbpfMapDescriptor` creation sites (BTF maps, global vars, legacy maps) |

### ebpf-for-windows changes

| File | Change |
|------|--------|
| `include/ebpf_api.h` | `ebpf_verifier_map_info_t` struct + `ebpf_get_map_annotations_from_verifier()` API |
| `libs/api_common/api_common.cpp` | Annotation extraction using `EbpfDomain::get_map_fd_range()` and `get_map_type()`. TLS storage. |
| `ebpfapi/Source.def` | Export `ebpf_get_map_annotations_from_verifier` |
| `tools/bpf2c/bpf2c.cpp` | Calls annotation API, passes to generator |
| `tools/bpf2c/bpf_code_generator.h` | `set_map_annotations()`, `_map_annotations` storage |
| `tools/bpf2c/bpf_code_generator.cpp` | Annotation lookup by instruction offset → map name → `map_definitions` index → inline code |
| `include/bpf2c.h` | `array_data` field in `map_data_t`, version 2 |
| `libs/shared/shared_common.c` | Version table entry for new map_data size |
| `libs/execution_context/ebpf_native.c` | Populate `array_data` via `ebpf_map_get_value_address()` |

## 9. Scope and Limitations

### Optimized (Phase 1)

| Helper | Map Type | Condition |
|--------|----------|-----------|
| `bpf_map_lookup_elem` | `BPF_MAP_TYPE_ARRAY` | Verifier proves singleton map fd at call site |

### Not optimized (falls back to helper call)

- Verifier reports ambiguous map fd (multiple maps possible on different paths).
- Map name not found in bpf2c's `map_definitions`.
- Non-array map types (hash, LRU, ring buffer, etc.).
- `bpf_map_update_elem`, `bpf_map_delete_elem` (future work).
- `BPF_MAP_TYPE_PERCPU_ARRAY` (different data layout).

### Future extensions

| Helper | Map Type | Optimization |
|--------|----------|-------------|
| `bpf_map_update_elem` | `BPF_MAP_TYPE_ARRAY` | Inline bounds check + memcpy |
| `bpf_map_lookup_elem` | `BPF_MAP_TYPE_PERCPU_ARRAY` | Per-CPU base + inline index |
| `bpf_map_delete_elem` | `BPF_MAP_TYPE_ARRAY` | Inline bounds check + memset |
