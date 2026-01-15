# EpochModel (TLA+)

This folder contains a small TLA+ model of the epoch reclamation protocol, focused on proving the key safety property:

- **No reclamation while any reader can still hold a reference**

Files:
- `EpochModel.tla`: the TLA+ spec (module `EpochModel`).
- `EpochModel.cfg`: TLC config for the **fixed** design (should PASS).
- `EpochModel_buggy.cfg`: TLC config for the **buggy** design (should FAIL with a counterexample).
- `CONFORMANCE.md`: mapping between the model and the implementation.

## Run it (command line, Windows)

### 1) Install prerequisites
- Install a recent **Java** (JDK includes a JRE). Java 11+ is fine.
  - Recommended (Microsoft OpenJDK 21): `winget install Microsoft.OpenJDK.21`
  - After installing, open a **new terminal** and verify: `java -version`
  - If `java` still isn't found, use the full path (example):
    - `"C:\Program Files\Microsoft\jdk-21.0.9.10-hotspot\bin\java.exe" -version`
- Download **TLA+ tools** (`tla2tools.jar`). Options:
  - Install **TLA+ Toolbox** (recommended) from https://lamport.azurewebsites.net/tla/toolbox.html
  - Or download `tla2tools.jar` from the TLA+ releases: https://github.com/tlaplus/tlaplus/releases

### 2) Run TLC from the repo root

From the repo root, run (replace the jar path with where you put it). If you already have `models\tla2tools.jar`, you can use that directly:

- Fixed design (expected to PASS):
  - `java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\epoch\EpochModel.cfg models\epoch\EpochModel.tla`

- Buggy design (expected to FAIL with a counterexample):
  - `java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\epoch\EpochModel_buggy.cfg models\epoch\EpochModel.tla`

What you should see:
- PASS case ends with `Model checking completed. No error has been found.`
- Buggy case ends with an invariant violation (Safety), plus a trace you can replay.

Invariants checked:
- `Safety`: no reader can still hold the object once reclaimed.
- `ReleaseNeverAhead`: release epoch never exceeds published epoch.
- `RetireStampIsMaxWhenEnabled`: when `UsePublishedEpochForRetire=TRUE`, retirement stamping is `Max(published_epoch, cpu_epoch[c])` (the model equivalent of `max(published_epoch, local_epoch)`).

## Run it (TLA+ Toolbox)

1. Open TLA+ Toolbox.
2. **File → Open Spec…**
   - Point it at `models/epoch/EpochModel.tla`.
3. Create a new model:
   - **TLC Model Checker → New Model…**
4. In the model:
   - Set **Model Parameters → Spec** to `Spec` (default if the file is open).
  - Add invariants: `TypeOK`, `ReleaseNeverAhead`, `RetireStampIsMaxWhenEnabled`, `Safety`.
   - Set constants to match either config:
     - Fixed: `NCPUS=2`, `MaxEpoch=4`, `UsePublishedEpochForReader=TRUE`, `UsePublishedEpochForRetire=TRUE`
     - Buggy: same but both flags `FALSE`
5. Click **Run TLC**.

## Notes / How this relates to the implementation

This model is designed to capture the specific failure mode that motivated the published-epoch fix:
- CPU0 can hand out a newer epoch to readers while another CPU still uses a stale cached epoch for retirement stamping.
- If retirement is stamped "too old", the global release computation can incorrectly permit reclamation while a reader still holds a reference.

If you want this model to track the implementation more closely (e.g., explicit propose/commit message states, per-CPU free lists, multiple objects), we can incrementally refine it while keeping the safety invariant as the anchor.
