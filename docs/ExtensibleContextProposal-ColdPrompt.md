# Cold Prompt: Extensible Context Hash Maintenance

Use this prompt in a new Copilot session to extend the existing size-tolerant context hash implementation.

Before editing code, read these files first:
- docs/ExtensibleContextProposal.md for the design intent and compatibility rules.
- docs/ExtensibleContextRunbook.md for the implementation pattern, validation flow, and extension notes.

---

## Prompt

```
I need to extend the existing "Size-Tolerant Context Hash" implementation described in docs/ExtensibleContextProposal.md.
Read docs/ExtensibleContextProposal.md and docs/ExtensibleContextRunbook.md first.

Current implementation state:

- bpf2c hashes the context descriptor shape fields only, not the full ebpf_ctx_descriptor_t.
- bpf2c records the compile-time context size in the generated native metadata.
- ebpfcore supports both the legacy hash mode and the extensible hash mode.
- Runtime loading still rejects programs if the compile-time context size exceeds the runtime context size.

When extending this feature, keep the hash inputs identical in tools/bpf2c/bpf2c.cpp and libs/execution_context/ebpf_program.c, update the generated metadata plumbing, and refresh the expected bpf2c outputs whenever codegen changes.

Summary of extension work that may be needed:

## 1. bpf2c hash computation — tools/bpf2c/bpf2c.cpp

Keep get_program_info_type_hash() aligned with ebpfcore by hashing only the three offset fields (data, end, meta), not the full ebpf_ctx_descriptor_t.

## 2. Hash mode constant — tools/bpf2c/bpf_code_generator.h

If a hash-mode constant or version gate is used, keep it synchronized between the generator and loader paths.

## 3. program_entry_t struct — include/bpf2c.h

Keep the size_t bpf2c_context_size field at the end of program_entry_t. This is compatibility metadata that records sizeof(context_struct) at bpf2c compile time.

## 4. bpf2c code emission — tools/bpf2c/bpf_code_generator.cpp

Emit the bpf2c_context_size value in the generated program_entry_t initialization from program_info->program_type_descriptor->context_descriptor->size.

## 5. Program parameters — libs/execution_context/ebpf_program.h

Keep size_t bpf2c_context_size in ebpf_program_parameters_t so the loader can distinguish legacy and extensible-context modules.

## 6. Native loading — libs/execution_context/ebpf_native.c

In _ebpf_native_load_programs(), copy bpf2c_context_size from the program_entry_t into the program parameters.

## 7. Hash computation in ebpfcore — libs/execution_context/ebpf_program.c

In _ebpf_program_compute_program_information_hash():
- Keep the hash-mode decision in sync with the metadata coming from the native module.
- For the extensible-context path: hash only data/end/meta, not the full context_descriptor.
- For the legacy path: hash the full context_descriptor as before.

In ebpf_program_set_program_info_hash():
- Determine the hash mode from program->parameters.program_info_hash_type and the presence of bpf2c_context_size.
- After hash comparison succeeds for the extensible-context path, verify:
  program->parameters.bpf2c_context_size <= runtime_context_descriptor->size
- If compile-time size is greater than runtime size, fail with EBPF_INVALID_ARGUMENT.

Also update _ebpf_program_type_specific_program_information_attach_provider() with the same hash-mode and size-check logic.

## Key requirements:
- Old programs must continue to work via the legacy code path.
- Both bpf2c and ebpfcore must produce identical hashes for the same inputs.
- All existing tests must continue to pass.
- Add test cases for same-version load, forward-compatible extension load, shrunk context rejection, and backward compatibility with the old hash.

## 8. Required Follow-Up for Generated Output Changes

If the change affects bpf2c output formatting or emitted metadata, update the expected files under tests/bpf2c_tests/expected/ and rerun the relevant generator tests. The second commit in this branch is the example to follow.
```
