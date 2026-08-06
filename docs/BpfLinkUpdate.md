# BPF_LINK_UPDATE (Atomic link program replacement)

This document specifies atomic update of the program attached to an existing eBPF link. The behavior matches the intent of Linux `bpf_link_update()` / `BPF_LINK_UPDATE`: the link identity stays the same while the program executed through that link changes.

## Overview

An eBPF *link* represents an attachment of a program to a hook point (for example, XDP). When a link update occurs:

- The link handle/FD continues to refer to the same link object.
- The program executed by the link changes from an old program to a new program.
- There is no detach/attach window for the link itself.
- In-flight invocations may continue executing the old program; subsequent invocations observe the new program.

This provides an atomic “replace program” operation for link-based attachments.

## API surface

### `bpf()` syscall command

The feature uses a `BPF_LINK_UPDATE` command in the `bpf()` syscall compatibility layer.

Inputs:
- `link_fd`: a file descriptor that refers to a link.
- `new_prog_fd`: a file descriptor that refers to the new program.
- `flags`: behavior flags.
- `old_prog_fd` (optional): a file descriptor that refers to the expected old program.

Supported flags:
- `BPF_F_REPLACE`: When set, the update requires that the link currently refers to `old_prog_fd` (if provided). If the expectation does not match, the update fails.

### libbpf-style helper

The libbpf-compatible API includes a `bpf_link_update()` helper that maps to `BPF_LINK_UPDATE`:

```c
int bpf_link_update(int link_fd, int new_prog_fd, const struct bpf_link_update_opts *opts);
```

The `bpf_link_update_opts` structure provides optional parameters:

```c
struct bpf_link_update_opts {
    size_t sz;           // Size of this struct for forward/backward compatibility.
    __u32 flags;         // Behavior flags (e.g., BPF_F_REPLACE).
    __u32 old_prog_fd;   // Expected old program FD (used with BPF_F_REPLACE).
};
```

When `opts` is `NULL`, the update uses default behavior (unconditional replacement).

**Return value:** Returns 0 on success, or a negative error code on failure (with errno set).

## Semantics

### Atomicity

Updating a link changes the program used by that link in a single operation. The link remains attached throughout the update.

The implementation updates the link’s program pointer as one atomic switch from the perspective of readers (invocation path). This means:

- A given invocation uses either the old program or the new program.
- A single invocation does not observe a partially-updated state.

### In-flight execution

Invocations that start before the update may execute the old program even after the update returns. Invocations that start after the update returns execute the new program.

This behavior relies on the execution context’s lifetime rules: programs remain valid while they are referenced and while in-flight invocations complete (epoch/refcount lifetime protection).

### Link identity

The link object does not change. All properties of the link that are independent of the program (such as link ID, attachment point, and metadata) remain the same.

### Type compatibility

The new program is compatible with the link’s attach type and the hook’s expected program type. If the new program is not compatible, the update fails.

### Old program validation (conditional replace)

When `BPF_F_REPLACE` is used with an `old_prog_fd`, the update succeeds only if the link currently refers to that exact program. If the link refers to a different program, the update fails.

This supports concurrent update safety by preventing accidental replacement when multiple agents manage the same link.

## Errors

A link update fails with an error when any of the following occurs:

- `link_fd` does not refer to a valid link.
- `new_prog_fd` does not refer to a valid program.
- The new program is not compatible with the link’s attachment.
- `BPF_F_REPLACE` is specified and the current program does not match `old_prog_fd` (when provided).
- Unsupported flags are provided.

## Examples

### Replace a program on an existing link

1. Create a link by attaching a program.
2. Load a second program that is compatible with the same attach point.
3. Call `bpf_link_update(link_fd, new_prog_fd, NULL)`.

The link stays attached and subsequent traffic executes the new program.

### Conditional replace (compare-and-swap)

```c
struct bpf_link_update_opts opts = {
    .sz = sizeof(opts),
    .flags = BPF_F_REPLACE,
    .old_prog_fd = old_prog_fd,
};
int err = bpf_link_update(link_fd, new_prog_fd, &opts);
```

If the link’s program is not `old_prog_fd`, the call fails and the link remains unchanged.

## Implementation notes (for contributors)

The execution context stores a program pointer on the link object. Invocation reads this pointer on the fast path.

A link update:

- Takes a reference on the new program as if attaching it to the link.
- Atomically swaps the link’s program pointer from old to new.
- Releases the old program reference as if detaching it from the link.

The epoch/refcount lifetime model ensures that in-flight invocations that captured the old program pointer continue safely until completion.
