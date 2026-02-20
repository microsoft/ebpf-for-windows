# HashTableModel (TLA+)

This folder contains a small, bounded TLA+ model that captures the key concurrency pattern in `libs/runtime/ebpf_hash_table.c`:

- buckets are immutable snapshots
- writers replace a bucket via an atomic pointer swap
- old buckets/values are retired and later reclaimed (freed) via epoch-based reclamation

The model focuses on a safety property: while a reader is inside an epoch, it must never dereference a reclaimed bucket/value.

## Files

- `HashTableModel.tla`: the spec
- `HashTableModel.cfg`: “safe usage” config (readers enter/exit epoch; no use-after-exit)
- `HashTableModel_buggy_use_after_exit.cfg`: config that allows use-after-exit (expected to find a counterexample)
- `CONFORMANCE.md`: mapping from model concepts to the C implementation

## Running TLC

From the repo root:

```powershell
# Safe config: should pass.
java -jar models\tla2tools.jar -config models\hash_table\HashTableModel.cfg models\hash_table\HashTableModel.tla

# Buggy config: should fail (Safety invariant violation).
java -jar models\tla2tools.jar -config models\hash_table\HashTableModel_buggy_use_after_exit.cfg models\hash_table\HashTableModel.tla
```

Notes:
- TLC creates `states/` folders next to the model by default.
- If you don’t have Java installed, you can use `winget install Microsoft.OpenJDK.21`.
