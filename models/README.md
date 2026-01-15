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

The CI workflow downloads the TLA+ tools jar (`tla2tools.jar`) from the official TLA+ release. For local runs, download it (or use the Toolbox install):

```powershell
curl.exe -fsSL -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
```

Run TLC from the repo root using the model’s `.cfg` file:

```powershell
java -cp .\tla2tools.jar tlc2.TLC -config models\<model>\<config>.cfg models\<model>\<spec>.tla
```

Many models also run faster with multiple workers:

```powershell
java -cp .\tla2tools.jar tlc2.TLC -workers 8 -terse -nowarning -config models\<model>\<config>.cfg models\<model>\<spec>.tla
```

TLC writes state exploration artifacts into `states/` folders next to the model by default.

### TLATeX (LaTeX pretty-print)

For a typeset (mathematically formatted) version of each model, this repo checks in the generated `.tex` output under:

- `models/<model>/tlatex/<Spec>.tex`

To regenerate them, you need Java and a LaTeX toolchain installed (because TLATeX runs `latex` to compute alignment). On Ubuntu, this is typically:

```bash
sudo apt-get update
sudo apt-get install -y texlive-latex-base
```

Then run:

```bash
TLA2TOOLS_JAR=./tla2tools.jar scripts/generate_tlatex.sh
```

On Windows, you can run the PowerShell version:

```powershell
pwsh -File scripts\generate_tlatex.ps1 -Tla2ToolsJar .\tla2tools.jar
```

### Generating PDFs on Windows (from TLATeX output)

If you want a PDF rendering of a model, you can compile the generated TLATeX `.tex` file (for example `models\epoch\tlatex\EpochModel.tex`).

One straightforward option is **MiKTeX**:

```powershell
winget install MiKTeX.MiKTeX
```

After installation, open a new terminal so PATH updates are picked up.

Then, from the directory containing the `.tex` file:

- Preferred (handles multiple passes automatically):

```powershell
latexmk -pdf -interaction=nonstopmode -file-line-error EpochModel.tex
```

Note: on Windows with MiKTeX, `latexmk` typically requires a Perl runtime (e.g., Strawberry Perl). If `latexmk` fails with “MiKTeX could not find the script engine 'perl'”, either install Perl or use the `pdflatex` fallback below.

- If `latexmk` is not available, run `pdflatex` twice:

```powershell
pdflatex -interaction=nonstopmode -file-line-error EpochModel.tex
pdflatex -interaction=nonstopmode -file-line-error EpochModel.tex
```

This will produce `EpochModel.pdf` next to the `.tex` file.

The GitHub workflow `.github/workflows/tla-plus-models.yml` regenerates these files and fails the build if there are diffs.

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
