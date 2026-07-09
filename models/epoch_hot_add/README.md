# EpochHotAddModel (TLA+)

This folder contains a small TLA+ model of the **epoch CPU hot-add topology protocol**, focused on proving the safety of a **quiesce-then-modify** design.

The model checks these properties:

- **No election walker ever runs on a CPU that is not both admitted and schedulable**
- **A schedulable CPU is always admitted**, so `epoch_enter()` would not fail-fast because of a hot-add race

This model is intentionally separate from `models/epoch/`:

- `models/epoch/` proves **reclamation safety**
- `models/epoch_hot_add/` proves **ring/election safety during hot-add**

Files:

- `EpochHotAddModel.tla`: the TLA+ spec (module `EpochHotAddModel`)
- `EpochHotAddModel.cfg`: the intended design; should pass
- `EpochHotAddModel_buggy_no_quiesce.cfg`: demonstrates why timer-driven computation must be quiesced before modifying the ring
- `EpochHotAddModel_buggy_early_resume.cfg`: demonstrates why quiescence must stay in effect until add-complete
- `CONFORMANCE.md`: mapping between the model and `libs/runtime/ebpf_epoch.c`

## What the model abstracts

The model starts with a stable admitted ring:

- CPU 0 -> CPU 1 -> CPU 0

Then it hot-adds CPU 2. The model includes:

- a **timer-driven** election request path
- a **passive synchronize** path modeled as a shared SRW lock
- a topology modifier that takes that same lock **exclusive**
- a CPU-0-owned **quiesce request** that blocks new timer-driven computations and
  completes only after any in-flight timer-driven computation drains
- a staged hot-add sequence: **begin -> quiesce -> splice -> add-complete -> resume**
- rollback before or after the splice

The hot-added CPU is only made **schedulable** at `AddComplete`.

## Run it (command line, Windows)

### 1) Install prerequisites

- Install a recent **Java** (Java 11+ is fine)
- Download `tla2tools.jar` from the TLA+ releases or install TLA+ Toolbox

### 2) Run TLC from the repo root

- Fixed design (expected to pass):
  - `java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\epoch_hot_add\EpochHotAddModel.cfg models\epoch_hot_add\EpochHotAddModel.tla`

- Buggy "no quiesce" design (expected to fail):
  - `java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\epoch_hot_add\EpochHotAddModel_buggy_no_quiesce.cfg models\epoch_hot_add\EpochHotAddModel.tla`

- Buggy "early resume" design (expected to fail):
  - `java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\epoch_hot_add\EpochHotAddModel_buggy_early_resume.cfg models\epoch_hot_add\EpochHotAddModel.tla`

Expected results:

- fixed config ends with `Model checking completed. No error has been found.`
- both buggy configs end with an invariant violation, typically `ElectionCursorSafe`

## Notes

This model intentionally focuses on a **single hot-added CPU** so the state space stays small and the safety argument stays readable.

It does **not** model concurrent multi-CPU hot-add serialization directly. The model’s purpose is narrower: prove that once topology modification is serialized, the split protocol is safe:

- passive synchronize is drained by the SRW lock
- timer-driven computation is drained by the CPU-0 quiesce message
