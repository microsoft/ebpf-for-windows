# Formal models (TLA+)

This folder contains small **TLA+** models used to explore and verify correctness properties of selected eBPF-for-Windows components.

These models are intentionally **bounded and executable** (checked with TLC) so we can:

- catch concurrency / lifecycle hazards (e.g., use-after-free scenarios)
- document critical invariants and assumptions in a precise way
- provide “known-buggy” configurations that demonstrate why a fix matters

These models are not meant to be a full formal specification of the entire project.

## What is TLA+?

TLA+ (Temporal Logic of Actions) is a specification language for describing system behavior over time.

In this repo we use it pragmatically:

- **State**: variables describe the system state (e.g., epochs, bucket pointers).
- **Actions**: steps that transition state (e.g., reader enter/exit, writer update).
- **Invariants**: properties that must always hold (e.g., “no reclaimed object is observed by an in-epoch reader”).
- **Model checking (TLC)**: explores all behaviors within finite bounds and finds counterexamples when properties are violated.

## How to run the models

### Prerequisites

- Java (JRE/JDK). On Windows you can install:
  - `winget install Microsoft.OpenJDK.21`

### TLC

This repo vendors the TLA+ tools jar at:

- `models/tla2tools.jar`

Run TLC from the repo root using the model’s `.cfg` file:

```powershell
java -jar models\tla2tools.jar -config models\<model>\<config>.cfg models\<model>\<spec>.tla
```

Many models also run faster with multiple workers:

```powershell
java -jar models\tla2tools.jar -workers 8 -terse -nowarning -config models\<model>\<config>.cfg models\<model>\<spec>.tla
```

TLC writes state exploration artifacts into `states/` folders next to the model by default.

## Models in this repo

- `models/epoch/`
  - Models the epoch-based reclamation scheme and checks safety properties around published/released epochs.
  - Includes “fixed” and “buggy” configurations to demonstrate the hazard.

- `models/hash_table/`
  - Models the runtime hash table’s immutable-bucket replacement pattern plus simplified epoch-based reclamation.
  - Includes a “safe usage” configuration and a deliberately unsafe “use-after-exit” configuration that demonstrates a safety violation.

- `models/ring_buffer/`
  - Models core ring buffer producer/consumer behavior plus map async-query completion.
  - Includes a “safe” configuration and a deliberately buggy “publish-before-lock” configuration that demonstrates a safety violation.

- `models/object_array_map/`
  - Models lock-free reads of object pointers stored in array map slots (prog array / array-of-maps) and the epoch-based lifetime contract that makes them safe.
  - Includes a “safe” configuration and a deliberately buggy “read outside epoch” configuration that demonstrates a safety violation.

- `models/extension_invoke/`
  - Models the lock-free "extension still loaded?" check in the invoke fast path (`ReadPointerNoFence` on `program->extension_program_data`) and the ordering assumption that makes it safe.
  - Includes a “safe” configuration and a deliberately buggy “epoch enter is not a barrier” configuration that demonstrates a safety violation.

## Conformance to implementation

Each model directory should include a short `CONFORMANCE.md` that maps model variables/actions to the corresponding implementation concepts and calls out simplifications.

If you change the implementation in a way that affects:

- memory ordering assumptions (acquire/release publish)
- lifetime/reclamation semantics
- API usage requirements (e.g., callers must hold an epoch)

…please update the model and/or its `CONFORMANCE.md`.

## Adding a new model

Suggested structure:

- `<ModelName>.tla`: the spec
- `<ModelName>.cfg`: a configuration expected to pass
- `<ModelName>_buggy*.cfg`: one or more configurations expected to fail (optional but encouraged)
- `README.md`: how to run the model and what it checks
- `CONFORMANCE.md`: mapping to code + key assumptions

Note: new `.tla` and `.cfg` files should include the repo’s license header in the first lines (see other models for examples).
