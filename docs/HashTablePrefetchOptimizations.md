# Hash Table Prefetch Optimizations

This document describes the prefetch optimizations applied to `ebpf_hash_table.c` to reduce cache miss latency in the hash table lookup and update paths.

## Background: Three Cache Misses in a Lookup

A hash table lookup touches three distinct memory regions, each typically a cache miss:

```
Miss #1:  hash_table->buckets[i].header   (the pointer slot in the bucket array)
Miss #2:  bucket->count, bucket->entries[] (the bucket contents the pointer points to)
Miss #3:  entry->data                      (the actual value, behind another pointer)
```

The **original code** had one prefetch in `_ebpf_hash_table_compute_bucket_index` that targeted miss #1:

```c
PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, &hash_table->buckets[bucket_index]);
```

This brings the slot (containing the `.header` pointer and `.lock`) into L1 cache while the hashing function returns to the caller. It works well for `_ebpf_hash_table_replace_bucket` where lock acquisition and allocation separate the prefetch from the read, but in `ebpf_hash_table_find` the slot is read immediately after — almost no latency is hidden.

Misses #2 and #3 were **not addressed at all**. There was a `PreFetchCacheLine` on `data` in `ebpf_hash_table_find`, but it fired **after** the loop already dereferenced `data`, making it useless.

## Change 1: Prefetch `entry->data` in `ebpf_hash_table_find` Loop

**Location:** `ebpf_hash_table_find`, inside the key search loop.

**What changed:** Inside the key search loop, we now prefetch `entry->data` before comparing `entry->key`:

```c
for (index = 0; index < bucket->count; index++) {
    ebpf_hash_bucket_entry_t* entry = ...;
    PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, entry->data);   // NEW
    if (_ebpf_hash_table_compare(hash_table, key, entry->key) == 0) {
        data = entry->data;
        break;
    }
}
```

The old post-loop prefetch (`PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, data)`) was removed since it was redundant — `data` had already been read.

**Why it helps (miss #3):** `entry->data` points to heap-allocated value memory that is almost certainly not in cache. The key comparison (`memcmp` or integer compare) takes ~10-30 cycles, which is enough time for the CPU's prefetch unit to start fetching the data cache line. If this entry matches, the `entry->data` line is already in-flight or in L1 when we assign `data = entry->data` and the caller reads through `*value`. If it doesn't match, the prefetch is harmless — it's a hint, not a fault.

**What about wrong prefetches for non-matching entries?** For buckets with N entries, we issue N-1 "wasted" prefetches that pollute L1 slightly. In practice, buckets are small (typically 1-3 entries) and the prefetch for the matching entry is the one that matters, outweighing the minor pollution.

## Change 2: Prefetch Bucket Contents in `_ebpf_hash_table_replace_bucket`

**Location:** `_ebpf_hash_table_replace_bucket`, immediately after lock acquisition.

**What changed:** Immediately after acquiring the bucket lock, we read the `.header` pointer and prefetch the bucket contents it points to:

```c
ebpf_lock_state_t state = ebpf_lock_lock(&hash_table->buckets[bucket_index].lock);

// NEW: prefetch bucket contents
{
    ebpf_hash_bucket_header_t* prefetch_bucket = hash_table->buckets[bucket_index].header;
    if (prefetch_bucket) {
        PreFetchCacheLine(PF_TEMPORAL_LEVEL_1, prefetch_bucket);
    }
}

// ... then allocation, memcpy, notification callback work happens ...

old_bucket = _ebpf_hash_table_get_bucket(hash_table, bucket_index);  // actual use ~20 lines later
```

**Why it helps (miss #2 on the update path):** The lock `ebpf_lock_lock(&hash_table->buckets[bucket_index].lock)` brings the `ebpf_hash_bucket_header_and_lock_t` slot into cache (the lock lives in that struct). Reading `.header` is then free — it's on the same cache line. The pointer in `.header` points to the actual `ebpf_hash_bucket_header_t` (with `count` and `entries[]`), which is heap-allocated and likely a cache miss.

Between this prefetch and the first real access (`old_bucket->count`), there are ~40 lines of work:

- Memory allocation (`hash_table->allocate(...)`)
- `memcpy` of the value
- Notification callback invocation

This is hundreds to thousands of cycles — more than enough for the prefetch to resolve. By the time we iterate over the bucket entries to find the key, `bucket->count` and the first entries are already in cache.

**Why `.header` not `_ebpf_hash_table_get_bucket()`?** We read `.header` directly (without `ReadSizeTAcquire`) because this is just a prefetch hint — it doesn't need acquire semantics. The actual authoritative read still goes through `_ebpf_hash_table_get_bucket()` with proper memory ordering later. Even if the prefetch fetches a slightly stale pointer, it's harmless: worst case the prefetch brings in an old bucket (or the prefetch is wasted), and the real `ReadSizeTAcquire` gets the correct value.

## What Was NOT Changed (and Why)

**Miss #2 in `ebpf_hash_table_find`:** After `_ebpf_hash_table_get_bucket` returns the bucket pointer, the very next instruction reads `bucket->count`. There is no intervening work to hide the latency of prefetching the bucket contents. The only way to address this would be a two-phase / batched lookup API where multiple lookups are interleaved, or moving the pointer read into `_ebpf_hash_table_compute_bucket_index` itself. Both would be API-level changes beyond the scope of these optimizations.
