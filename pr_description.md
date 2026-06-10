## Description

Fixes a race in test setup for native helper initialization by serializing global link cleanup across threads. Closes #5238.

### Problem

`_native_module_helper::initialize()` detached all existing BPF links unconditionally. In multi-threaded test runs, concurrent cleanup operations could race: one thread detaches links while another is attaching them, causing spurious attach failures.

### Solution

In [tests/libs/util/native_helper.cpp](tests/libs/util/native_helper.cpp) and [tests/libs/util/native_helper.hpp](tests/libs/util/native_helper.hpp), serialize link cleanup using a static `CRITICAL_SECTION`:

- Add static `_cleanup_lock` mutex to `_native_module_helper` class
- Initialize/destroy the lock on module load/unload via a static helper object
- Wrap the `bpf_link_get_next_id` / `bpf_link_get_fd_by_id` / `bpf_link_detach` cleanup sequence in `EnterCriticalSection` / `LeaveCriticalSection`

This ensures:
- Only one thread executes cleanup at a time (no concurrent detach races)
- All threads still clean up their state (no pollution from worker threads)
- The lock is released immediately after cleanup (minimal contention)

## Testing

- [x] Verified by rerunning multi-threaded test scenarios that previously showed racy attach failures.
- [ ] Unit tests are added.
- [ ] Driver tests are added.
- [ ] Fuzz tests are added.

## Documentation

No documentation impact.

## Installation

No installer impact.
