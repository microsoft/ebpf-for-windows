# LPM Trie Performance Analysis & Optimization Proposals

## 1. Current Implementation Overview

The `BPF_MAP_TYPE_LPM_TRIE` is implemented as a hash table with special lookup behavior, rather than a traditional trie data structure. The key components are:

| Component | File | Purpose |
|-----------|------|---------|
| `ebpf_core_lpm_map_t` | `libs/execution_context/ebpf_maps.c` | Map struct with prefix-length bitmap |
| `_lpm_extract()` | `libs/execution_context/ebpf_maps.c` | Extract function for variable-length hashing |
| `ebpf_hash_table_t` | `libs/runtime/ebpf_hash_table.c` | Underlying hash table with bucket-based storage |
| `ebpf_bitmap_t` | `libs/runtime/ebpf_bitmap.c` | Bitmap tracking which prefix lengths are populated |

### Data Structures

```
ebpf_core_lpm_map_t
├── core_map        (contains pointer to ebpf_hash_table_t)
├── max_prefix      (max prefix length in bits, e.g. 32 for IPv4, 128 for IPv6)
└── data[]          (ebpf_bitmap_t tracking which prefix lengths have entries)
```

Each LPM key (`ebpf_core_lpm_key_t`) is:
```
┌──────────────────┬─────────────────────┐
│ prefix_length    │ prefix bytes        │
│ (uint32_t)       │ (variable length)   │
└──────────────────┴─────────────────────┘
```

The hash table uses an `extract` function (`_lpm_extract`) that returns the key's effective bit-length as `sizeof(uint32_t)*8 + prefix_length`. This means keys with different prefix lengths hash differently and compare unequal, so each `(prefix_length, prefix)` pair is a distinct hash table entry.

### Current Lookup Algorithm (`_find_lpm_map_entry`)

```
1. Start with the caller's prefix_length
2. Initialize a reverse bitmap cursor at that prefix_length
3. Loop:
   a. Find next set bit in bitmap (next populated prefix length, decreasing)
   b. Overwrite the key's prefix_length field with this value
   c. Call _find_hash_map_entry() → ebpf_hash_table_find()
   d. If found → return match
   e. If bitmap exhausted → return KEY_NOT_FOUND
4. Restore original prefix_length
```

### Current Update Algorithm (`_update_lpm_map_entry`)

```
1. Validate prefix_length <= max_prefix
2. Call _update_hash_map_entry() (inserts/updates in hash table)
3. On success, set the bit for this prefix_length in the bitmap
```

### Current Delete Algorithm (`_delete_lpm_map_entry`)

```
1. Validate prefix_length <= max_prefix
2. Call _delete_hash_map_entry() (removes from hash table)
   (Note: bitmap bit is NOT cleared)
```

---

## 2. Performance Analysis

### 2.1 Lookup — Primary Bottleneck

The lookup is the most critical path (called from eBPF programs on every packet). Here is the cost breakdown for a single `_find_lpm_map_entry` call:

**Per-iteration cost** (one iteration = one candidate prefix length):

| Step | Operation | Cost |
|------|-----------|------|
| 1 | `ebpf_bitmap_reverse_search_next_bit` | `_BitScanReverse64` intrinsic — very fast (1-3 cycles) |
| 2 | `_ebpf_hash_table_compute_bucket_index` → calls `_lpm_extract` + `_ebpf_murmur3_32` | Extract function call + murmur3 hash (cannot use CRC32 fast path because extract is set) |
| 3 | Bucket access + linear scan of bucket entries | Memory access (potential cache miss) + per-entry `_ebpf_hash_table_compare_extracted_keys` |
| 4 | `_ebpf_hash_table_compare_extracted_keys` | Calls `_lpm_extract` **twice** (once per key), then `memcmp` |

**Worst-case iteration count**: Number of distinct prefix lengths with entries in the map. For an IPv4 routing table with entries at /8, /16, /24, /32 — that's 4 iterations. For a densely populated IPv6 table, this could be up to 129 iterations.

#### Issue 2.1.1: Hash + Compare Uses Murmur3 Instead of CRC32

In `_ebpf_hash_table_compute_bucket_index`, when an `extract` function is provided, the code always falls through to `_ebpf_murmur3_32` even on x64 processors that support SSE4.2:

```c
if (!hash_table->extract) {
    if (ebpf_processor_supports_sse42) {
        return _ebpf_compute_crc32(...);  // Fast path — NOT taken for LPM
    }
}
// extract path: always uses murmur3 (slower)
hash_table->extract(key, &data, &length);
return _ebpf_murmur3_32(data, length, hash_table->seed) & hash_table->bucket_count_mask;
```

CRC32 (`_mm_crc32_u64`) is a single-cycle instruction on modern x86. Murmur3 requires multiple multiplications and rotations per 4-byte chunk — roughly 4-10x slower depending on key size.

**Impact**: Every hash table probe (and there are multiple per LPM lookup) pays the murmur3 cost instead of the CRC32 cost.

#### Issue 2.1.2: `_lpm_extract` Called Redundantly

During a single hash table probe, `_lpm_extract` is called:
1. Once in `_ebpf_hash_table_compute_bucket_index` (to get data + length for hashing)
2. **Twice** in `_ebpf_hash_table_compare_extracted_keys` (once for the search key, once for each candidate key in the bucket)

For each candidate bucket entry, that's **3 calls to `_lpm_extract`** minimum. The extract function is trivial (reads `prefix_length` and does arithmetic), but it's called through a function pointer, defeating inlining and adding indirect-call overhead.

#### Issue 2.1.3: Multiple Full Hash Table Lookups Per LPM Lookup

Each iteration of the LPM lookup loop calls `_find_hash_map_entry` → `ebpf_hash_table_find`, which performs:
1. Compute bucket index (hash the key)
2. Load bucket pointer (memory access, potential L1/L2 cache miss)
3. Scan bucket entries with compare

For a typical routing table with entries at 4-5 distinct prefix lengths, this means 4-5 complete hash table lookups in the worst case (when the match is at the shortest prefix or there is no match).

#### Issue 2.1.4: Bitmap Bits Never Cleared on Delete

`_delete_lpm_map_entry` does NOT clear the bitmap bit for the deleted prefix length. Over time, after inserts and deletes, the bitmap accumulates stale bits for prefix lengths that no longer have any entries. Each stale bit causes a wasted hash table lookup during `_find_lpm_map_entry`.

**Example**: Insert prefixes at /8, /16, /24, /32. Delete all /16 entries. The bitmap still has the /16 bit set, so every subsequent lookup that doesn't match at /32 or /24 will probe the hash table for /16 — and fail — before trying /8.

#### Issue 2.1.5: Key Mutation During Lookup

`_find_lpm_map_entry` overwrites `lpm_key->prefix_length` in-place during the search loop, then restores it afterward. This:
- Mutates caller-provided data (surprising API behavior)
- Prevents concurrent lookups from sharing the same key buffer
- Requires the restore step even on success

### 2.2 Update — Moderate Overhead

Update performance is reasonable. The main costs are:
1. One `ebpf_hash_table_update` call (hash + bucket replacement)
2. One bitmap `test_bit` + conditional `set_bit`

The bitmap update uses a non-interlocked `test_bit` followed by an interlocked `set_bit` (if needed). This is a correct optimization to avoid unnecessary interlocked operations.

No significant issues identified in the update path beyond the murmur3-vs-CRC32 hash cost (Issue 2.1.1).

### 2.3 Delete — Correctness and Performance Issue

Beyond the stale bitmap bits (Issue 2.1.4), delete is a single hash table delete operation and is performant.

---

## 3. Optimization Proposals

### Proposal A: Enable CRC32 Fast Path for Extracted Keys (Low effort, High impact)

**Problem**: The hash computation always uses murmur3 when an extract function is set, even on SSE4.2-capable hardware.

**Solution**: After extracting the key data and length, use CRC32 if available:

```c
static uint32_t
_ebpf_hash_table_compute_bucket_index(
    _In_ const ebpf_hash_table_t* hash_table, _In_ const uint8_t* key)
{
    if (!hash_table->extract) {
#if defined(_M_X64)
        if (ebpf_processor_supports_sse42) {
            return _ebpf_compute_crc32(key, hash_table->key_size, hash_table->seed)
                   & hash_table->bucket_count_mask;
        }
#endif
        return _ebpf_murmur3_32(key, hash_table->key_size * 8, hash_table->seed)
               & hash_table->bucket_count_mask;
    } else {
        const uint8_t* data;
        size_t length;
        hash_table->extract(key, &data, &length);
#if defined(_M_X64)
        if (ebpf_processor_supports_sse42) {
            return _ebpf_compute_crc32(data, (length + 7) / 8, hash_table->seed)
                   & hash_table->bucket_count_mask;
        }
#endif
        return _ebpf_murmur3_32(data, length, hash_table->seed)
               & hash_table->bucket_count_mask;
    }
}
```

**Expected impact**: ~4-10x speedup on the hash computation step of each hash table probe. Since LPM lookup does multiple probes, this compounds. For a 4-prefix-depth IPv4 lookup, this saves ~12-40 hash computations worth of overhead.

> **⚠ CORRECTNESS ISSUE**: The code above has a **hash invariant violation** for non-byte-aligned prefix lengths. `_ebpf_compute_crc32` operates on whole bytes only, but `_lpm_extract` returns length in **bits**. The round-up `(length + 7) / 8` hashes trailing garbage bits in the final byte. Meanwhile, `_ebpf_hash_table_compare_extracted_keys` correctly masks partial bytes when comparing. This breaks the invariant: if `compare(a, b) == 0` then `hash(a)` must equal `hash(b)`. Two keys identical in their first N bits but differing in trailing bits would compare as equal but hash to different buckets, causing **silent lookup failures**.
>
> `_ebpf_murmur3_32` handles this correctly — it isolates the high-order `remaining_bits` of the final byte (see `ebpf_hash_table.c` lines 142-145).
>
> **Fix options**:
> 1. Write a bit-aware CRC32 variant that masks the final byte before hashing: `last_byte &= (0xFF << (8 - remaining_bits))`.
> 2. Only use CRC32 when `length_in_bits % 8 == 0`, falling back to murmur3 for sub-byte prefixes.
> 3. For LPM specifically: note that `_lpm_extract` returns `sizeof(uint32_t)*8 + prefix_length` bits. The `sizeof(uint32_t)*8 = 32` portion is always byte-aligned, so the sub-byte issue only arises when `prefix_length % 8 != 0`. For IPv4 (/8, /16, /24, /32) this never triggers, but for arbitrary prefix lengths it will.
>
> **Recommendation**: Option 1 (mask final byte) is the safest general fix.

**Risk**: **Medium** (was Low). Requires careful handling of bit-granularity to avoid the hash invariant bug described above.

---

### Proposal B: Clear Bitmap Bits on Delete When Prefix Length Becomes Empty (Low effort, Medium impact)

**Problem**: Stale bitmap bits cause unnecessary hash table probes during lookup.

**Solution**: After a successful delete, check if any entries with that prefix length remain. If not, clear the bit. Two sub-approaches:

#### Option B1: Optimistic Clear With Lazy Re-set (Recommended)

Clear the bitmap bit on every delete. If a concurrent insert for the same prefix length races, the insert will re-set the bit. In the worst case, a concurrent lookup might miss a just-inserted entry for one lookup — but this is already possible in the current lock-free read design.

```c
static ebpf_result_t
_delete_lpm_map_entry(_In_ ebpf_core_map_t* map, _Inout_ const uint8_t* key)
{
    ebpf_core_lpm_map_t* trie_map = EBPF_FROM_FIELD(ebpf_core_lpm_map_t, core_map, map);
    ebpf_core_lpm_key_t* lpm_key = (ebpf_core_lpm_key_t*)key;
    if (lpm_key->prefix_length > trie_map->max_prefix) {
        return EBPF_INVALID_ARGUMENT;
    }

    ebpf_result_t result = _delete_hash_map_entry(map, key);
    if (result == EBPF_SUCCESS) {
        // Optimistically clear the bit. If another entry with the same
        // prefix length exists, the bit is stale-cleared — lookups will
        // skip this prefix length until the next insert re-sets the bit.
        // This may cause one false-negative lookup in a narrow race window,
        // which is acceptable given the existing lock-free read semantics.
        ebpf_bitmap_reset_bit((ebpf_bitmap_t*)trie_map->data, lpm_key->prefix_length, true);
    }
    return result;
}
```

> **Note**: This approach introduces a subtle correctness trade-off. If there are multiple entries at the same prefix length (different prefix values, same prefix length), clearing the bit when one is deleted will cause lookups to skip *all* entries at that prefix length until the next insert. This is **only safe if the map semantics tolerate brief false negatives** during concurrent access. If strict correctness is required, use Option B2.

#### Option B2: Reference-Count Bitmap Bits (Safe but Higher Effort)

Replace the bitmap with a per-prefix-length counter array. Increment on insert, decrement on delete. The "bit is set" check becomes "count > 0". This is strictly correct but requires changing the bitmap to a counter array and adds interlocked increment/decrement overhead.

**Expected impact**: Eliminates wasted hash table probes due to stale prefix lengths. In workloads with frequent insert/delete churn, this can significantly reduce lookup latency. For a long-running rule table that has accumulated 10 stale prefix lengths, each lookup saves up to 10 hash table probes.

**Risk**: Option B1 has a narrow race-condition window but matches existing lock-free read semantics. Option B2 is fully correct but requires more code changes.

---

### Proposal C: Use a Stack-Local Key Copy Instead of Mutating Caller's Key (Low effort, Low-Medium impact)

**Problem**: `_find_lpm_map_entry` overwrites `lpm_key->prefix_length` in-place during search.

**Solution**: Copy the key to a stack-local buffer and iterate on the copy:

```c
static ebpf_result_t
_find_lpm_map_entry(
    _Inout_ ebpf_core_map_t* map, _In_opt_ const uint8_t* key,
    uint64_t flags, _Outptr_ uint8_t** data)
{
    // ... validation ...

    // Work on a stack-local copy to avoid mutating the caller's key.
    size_t key_size = ebpf_map_get_effective_key_size(map);
    uint8_t local_key[EBPF_MAX_KEY_SIZE];  // Or use alloca/VLA if key_size varies
    memcpy(local_key, key, key_size);
    ebpf_core_lpm_key_t* search_key = (ebpf_core_lpm_key_t*)local_key;

    // ... iterate using search_key instead of lpm_key ...
}
```

**Expected impact**: Eliminates the key restore step, makes the API side-effect free, and allows potential future parallelism. The `memcpy` cost is negligible for typical key sizes (8 bytes for IPv4, 20 bytes for IPv6).

**Risk**: Very low. Purely local change with no behavioral difference.

---

### Proposal D: Dedicated LPM Lookup in Hash Table to Avoid Repeated Overhead (Medium effort, High impact)

**Problem**: Each iteration of the LPM lookup loop pays the full cost of `ebpf_hash_table_find` — compute bucket index, load bucket, scan entries. The hashing and extract function calls are repeated unnecessarily.

**Solution**: Add a dedicated `ebpf_hash_table_find_lpm` function (or an internal helper) that performs the LPM search inside the hash table layer, avoiding repeated overhead:

```c
// Pseudocode for optimized LPM lookup
ebpf_result_t
_find_lpm_map_entry_optimized(map, key, flags, data) {
    hash_table = map->data;
    lpm_key = (ebpf_core_lpm_key_t*)key;

    // Precompute the full key's bucket index for the maximum prefix length.
    // For shorter prefix lengths, recompute only when needed.
    bitmap_cursor = reverse_search_at(bitmap, lpm_key->prefix_length);

    while (prefix_len = next_set_bit(bitmap_cursor)) {
        // Compute hash for this prefix length directly
        // (inline the extract logic, use CRC32)
        effective_bits = 32 + prefix_len;
        effective_bytes = (effective_bits + 7) / 8;
        bucket_index = crc32(key, effective_bytes, seed) & mask;

        bucket = get_bucket(hash_table, bucket_index);
        if (!bucket) continue;

        // Scan bucket entries, comparing only the effective prefix bits
        for each entry in bucket {
            if (entry.prefix_length == prefix_len &&
                memcmp(entry.prefix, key.prefix, prefix_len / 8) == 0 &&
                /* check remaining bits if prefix_len not byte-aligned */) {
                *data = entry->data;
                return EBPF_SUCCESS;
            }
        }
    }
    return EBPF_KEY_NOT_FOUND;
}
```

**Key optimizations in this approach**:
1. **No function-pointer overhead**: The extract function is inlined since we know the key format
2. **No redundant extract calls**: Extract logic is called once for hashing and used directly for comparison
3. **Direct bucket access**: Bypasses the `_find_hash_map_entry` → `ebpf_hash_table_find` call chain
4. **CRC32 used directly**: Since we compute the hash inline, we can always use CRC32 on x64

> **⚠ CORRECTNESS ISSUES**:
>
> **1. Same CRC32 bit-granularity bug as Proposal A.** The pseudocode uses `crc32(key, effective_bytes, seed)` which rounds up to whole bytes — hashing garbage trailing bits for non-byte-aligned prefixes. This causes the same hash invariant violation: keys that should match will hash to different buckets. See Proposal A's correctness note for details and fixes.
>
> **2. Abstraction violation and fragile coupling.** The proposal directly accesses hash table internals:
>    - **Bucket layout**: `ebpf_hash_bucket_header_t`, `ebpf_hash_bucket_entry_t`, and the variable-size entry stride (`EBPF_OFFSET_OF(ebpf_hash_bucket_entry_t, key) + key_size`) are internal to `ebpf_hash_table.c` and not exposed in the header.
>    - **Memory ordering**: Bucket reads use `ReadSizeTAcquire` (via `_ebpf_hash_table_get_bucket`) to ensure correct ordering with concurrent writers. A custom lookup must replicate this exactly.
>    - **Comparison logic**: The custom comparison must exactly replicate `_ebpf_hash_table_compare_extracted_keys`, including the partial-byte masking (`remainder >>= 8 - (length % 8)`). Any divergence causes silent lookup failures.
>    - **Maintenance risk**: Any future change to bucket layout, locking, or memory ordering in `ebpf_hash_table.c` would silently break the custom LPM lookup.
>
> **Safer alternative**: Add a new API **inside** `ebpf_hash_table.c` (e.g., `ebpf_hash_table_find_with_key_transform`) that accepts a callback to modify the key before each probe but keeps all hashing, comparison, and bucket access inside the hash table module. This preserves encapsulation while eliminating the redundant overhead.

**Expected impact**: Roughly 2-3x speedup on the overall LPM lookup, by eliminating function pointer overhead, redundant extract calls, and enabling CRC32. This is the single highest-impact change.

**Risk**: **High** (was Medium). The CRC32 bug causes silent lookup failures. The abstraction violation creates long-term maintenance risk. Both are fixable but require careful implementation.

---

### Proposal E: Coalesce Prefix-Length Groups Into a Faster Index (Medium effort, High impact for dense tables)

**Problem**: For each candidate prefix length, we compute a hash, access a potentially cold cache line for the bucket pointer, and scan bucket entries. With many prefix lengths, this causes many cache misses.

**Solution**: Maintain a small sorted array of active prefix lengths (instead of or in addition to the bitmap). For lookup, iterate the array in reverse order. The array fits in 1-2 cache lines for typical use cases (≤32 distinct prefix lengths) and avoids the bitmap scan overhead.

```c
typedef struct _ebpf_core_lpm_map {
    ebpf_core_map_t core_map;
    uint32_t max_prefix;
    volatile uint32_t active_prefix_count;
    uint32_t active_prefixes[MAX_DISTINCT_PREFIXES]; // sorted, fits in cache
    uint64_t data[1]; // existing bitmap, kept for compatibility
} ebpf_core_lpm_map_t;
```

On update: insert prefix length into sorted array (if not already present).
On delete: remove from array if no more entries at that prefix length.

**Expected impact**: Faster iteration over prefix lengths (sequential memory access pattern vs. bitmap scan). Marginal improvement for sparse bitmaps, significant for dense ones (e.g., IPv6 with many prefix lengths).

**Risk**: Medium. Adds complexity to update/delete. Concurrent access to the sorted array needs careful handling.

---

## 4. Summary & Prioritization

| # | Proposal | Effort | Impact | Risk | Recommendation |
|---|----------|--------|--------|------|----------------|
| **A** | CRC32 for extracted keys | Low-Med | High | Medium ⚠ | **Do first** — but must fix bit-granularity bug (mask final byte) |
| **B1** | Clear bitmap on delete (optimistic) | Low | Medium | Low | **Do first** |
| **C** | Stack-local key copy | Low | Low-Med | Very Low | **Do first** |
| **D** | Dedicated LPM lookup in hash table | Medium | High | High ⚠ | **Do second** — via new hash table API, not by inlining internals |
| **B2** | Reference-count bitmap | Medium | Medium | Low | Consider if B1 race condition is unacceptable |
| **E** | Sorted prefix-length array | Medium | Med-High | Medium | Consider for IPv6/dense workloads |

### Recommended Implementation Order

1. **Phase 1** (Low-hanging fruit): Proposals B1 + C (safe), then A (with bit-masking fix)
   - B1 and C are safe, minimal code changes
   - A requires writing a bit-aware CRC32 wrapper or guarding with `length % 8 == 0` check
   - A alone should measurably improve lookup latency once the fix is in place

2. **Phase 2** (Architecture improvement): Proposal D
   - Must be implemented as a new `ebpf_hash_table` API, not by inlining hash table internals
   - Requires the same bit-aware CRC32 fix as Proposal A
   - Can be measured against Phase 1 baseline

3. **Phase 3** (Optimization for scale): Proposal E
   - Worthwhile if IPv6 or dense prefix-length workloads are a priority

---

## 5. Benchmarking Recommendations

To validate these proposals, the following benchmarks are recommended:

1. **Micro-benchmark**: LPM lookup with IPv4 keys (/8, /16, /24, /32 entries), measure:
   - Lookups/second for exact match at /32
   - Lookups/second for match at /8 (worst case — 4 probes)
   - Lookups/second for no match (all prefix lengths probed)

2. **Stale-bitmap test**: Insert entries at 32 distinct prefix lengths, delete all but 2, measure lookup latency before/after Proposal B.

3. **Scale test**: IPv6 table with 50+ distinct prefix lengths, measure lookup latency.

All benchmarks should be run with CPU performance counters (cache misses, branch mispredictions, IPC) to validate that the optimizations target the correct bottlenecks.
