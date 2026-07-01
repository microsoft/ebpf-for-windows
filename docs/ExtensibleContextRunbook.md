# Extensible Context Runbook

**Purpose:** Capture the implementation pattern behind the size-tolerant context hash change so future work can extend it safely without re-deriving the entire design.

**Branch history anchor:**
- `b3206ed4f8a19dac1c983a541452cbd441d9b13d` introduced the size-tolerant hash path and the `bpf2c_context_size` plumbing.
- `2c0f14ea83ff73edf666f1903b1efa84c6d70329` refreshed the bpf2c expected outputs after the generator changed.

---

## 1. What Changed

The implementation decouples native program compatibility from the full `ebpf_ctx_descriptor_t` size while keeping the existing safety model intact.

The practical result is:
- The hash now treats the context descriptor as shape data, not a strict `sizeof(...)` match.
- `bpf2c` records the compile-time context size in generated native metadata.
- `ebpfcore` accepts the legacy hash path and the extensible hash path side by side.
- Runtime loading still rejects programs if the compile-time context was larger than the live context.

---

## 2. Files To Touch When Extending This Feature

Use these as the primary surfaces for future changes:

- `tools/bpf2c/bpf2c.cpp` for hash input changes.
- `tools/bpf2c/bpf_code_generator.cpp` and `tools/bpf2c/bpf_code_generator.h` for generated metadata and constants.
- `include/bpf2c.h` for native program entry versioning and layout.
- `libs/execution_context/ebpf_program.h` and `libs/execution_context/ebpf_native.c` for loader parameter plumbing.
- `libs/execution_context/ebpf_program.c` for hash computation and runtime compatibility checks.
- `libs/shared/shared_common.c` for supported native program entry sizes.
- `tests/bpf2c_tests/expected/*.c` for regenerated output baselines.

If a future change touches the hash shape, update both sides of the comparison path together:
- bpf2c emission
- ebpfcore verification

If they diverge, the branch will load programs inconsistently.

---

## 3. Change Pattern

When extending the compatibility model, follow this order:

1. Change the data model first.
   Add or extend the metadata in the generated native program entry and the runtime loader parameters before changing hash behavior.

2. Update the hash inputs in both places.
   Keep `tools/bpf2c/bpf2c.cpp` and `libs/execution_context/ebpf_program.c` aligned. Any field included or excluded from the hash must match exactly.

3. Preserve legacy compatibility.
   Keep the old hash mode working for existing native modules. New behavior should be version-gated or inferred from metadata presence, not a silent replacement.

4. Add the runtime safety gate.
   The loader must continue checking that the compile-time context size does not exceed the live runtime context size.

5. Regenerate bpf2c expected files.
   The second commit in this branch shows the normal follow-up: generator output changes usually require updating `tests/bpf2c_tests/expected/*`.

6. Rebuild and rerun the focused tests.
   Verify both code generation and load-time compatibility paths.

---

## 4. Invariants To Preserve

These are the rules that should not change unless the whole feature is being redesigned:

- Older native programs must continue to load on a new runtime.
- A program compiled against a larger context must still be rejected on a smaller runtime context.
- Hash inputs in `bpf2c` and `ebpfcore` must stay identical for the same compatibility mode.
- The context-size check must happen after hash verification and before the program is accepted.
- The generated native metadata must remain backward-compatible with older loaders through the program entry versioning path.

---

## 5. Validation Checklist

Use a narrow validation loop after any extension:

1. Build the affected bpf2c and execution-context targets.
2. Run the bpf2c expected-output tests for any changed sample.
3. Run the native loading or unit tests that cover program info hash handling.
4. Confirm the legacy hash path still accepts old modules.
5. Confirm the extensible path rejects a smaller runtime context.

If the change only affects code generation, regenerate the expected files before rerunning tests.

---

## 6. Practical Notes

- The feature is append-only at the context level; field reordering is still a breaking change.
- `bpf2c_context_size` is compatibility metadata, not runtime access data.
- The second commit in this branch is mostly baseline churn, so future changes that alter generated output should expect the same kind of expected-file refresh.
- Keep documentation and the cold prompt in sync with the implementation pattern so future sessions do not reintroduce the old full-struct hash behavior.
