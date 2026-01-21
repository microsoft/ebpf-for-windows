# Simple TLA+ model (beginner friendly)

This folder contains a tiny TLA+ spec you can run with TLC.

## What it models

- One variable: `x`
- Two actions:
  - `Inc`: increment `x` if `x < Max`
  - `Dec`: decrement `x` if `x > Min`
- An invariant: `x` always stays within `Min..Max`

## Files

- `Counter.tla`: the TLA+ module
- `Counter.cfg`: TLC configuration (sets constants and checks invariant)
- `Failure.tla`: intentionally buggy model that violates the invariant
- `Failure.cfg`: TLC config for `Failure.tla` (expected to FAIL)

## How to run (VS Code)

1. Install the **TLA+** extension if you don’t have it.
2. Open `Counter.tla`.
3. Use the extension’s TLC/Model Checker command to run TLC using `Counter.cfg`.

## How to run (command line, Windows)

From the repo root:

`java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\simple\Counter.cfg models\simple\Counter.tla`

To see a real counterexample (expected to FAIL with an invariant violation):

`java -cp models\tla2tools.jar tlc2.TLC -workers auto -config models\simple\Failure.cfg models\simple\Failure.tla`

Note: TLC treats the filename you pass as the module name. If you run `... counter.tla`, TLC expects the top-level module to be `counter`, which will fail for this spec (module name is `Counter`).

## What to try next

- Change `Max` in `Counter.cfg` to a larger number.
- Break the model (for learning): edit `Inc` to allow `x' = x + 2` and see TLC find a counterexample to the invariant.
