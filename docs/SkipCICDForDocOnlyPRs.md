# Proposal: Skip CI/CD for Doc-Only PRs

## Problem

The `CI/CD` workflow (`cicd.yml`) contains ~30 jobs (builds, unit tests, fuzzers, driver tests, stress tests, etc.) and runs on every PR — even if the PR only touches `.md` files under `docs/`. This wastes significant compute resources and delays merge for trivial documentation fixes.

Other lightweight workflows (`Validate-YAML`, `Dependency Review`, `Scorecards`, `Local PR Checks`) also run unconditionally on every PR.

There is already a precedent in the repo: `reusable-build.yml` uses `fkirc/skip-duplicate-actions` with `paths_ignore: '["**.md", "**/docs/**"]'`, but that only skips *duplicate* runs, not doc-only runs.

## Requirements

1. When a PR contains **only doc changes** (scoped to `.md` files in `docs/`), CI/CD jobs are skipped.
2. All **required status checks** still report as passed so the PR can merge.

## Approach: Change Detection + Conditional Jobs + Status Gate

This is the standard GitHub Actions pattern for "skip CI but keep required checks green."

### Step 1: Add a `check_changes` detection job to `cicd.yml`

Add a new fast job at the top of the `jobs:` section that detects whether the PR contains code changes:

```yaml
  # Detect whether this PR only contains doc changes.
  check_changes:
    runs-on: ubuntu-latest
    outputs:
      has_code_changes: ${{ steps.filter.outputs.code }}
    steps:
      - uses: actions/checkout@0c366fd6a839edf440554fa01a7085ccba70ac98  # v4.2.2
      - uses: dorny/paths-filter@de90cc6fb38fc0963ad72b210f1f284cd68cea36  # v3.0.2
        id: filter
        with:
          filters: |
            code:
              - '!(docs/**/*.md)'
```

This job outputs `has_code_changes: 'true'` or `'false'`. On `schedule`/`push`/`workflow_dispatch` events, it defaults to reporting all files as changed, so those runs remain unaffected.

**Scope decision**: `docs/**/*.md` covers the stated scope. This can be broadened to `**/*.md` later if desired.

### Step 2: Make all heavy jobs conditional

Every build/test job adds `needs: [check_changes]` (alongside any existing needs) and extends its `if:` condition:

```yaml
  regular:
    needs: [check_changes]
    if: |
      needs.check_changes.outputs.has_code_changes == 'true' &&
      (github.event_name == 'schedule' || github.event_name == 'pull_request' || ...)
    uses: ./.github/workflows/reusable-build.yml
    ...
```

Jobs that already have `needs:` (e.g., `unit_tests` needs `regular`) are implicitly skipped when their upstream dependency is skipped. For clarity and safety, the explicit condition should be added to downstream jobs as well.

**Jobs to update** (all PR-triggered jobs in `cicd.yml`):

| Category | Jobs |
|----------|------|
| **Builds** | `regular`, `onebranch`, `regular_native-only`, `analyze`, `sanitize` |
| **Unit Tests** | `unit_tests`, `unit_tests_appverif`, `unit_tests_native_only`, `unit_tests_native_only_arm64`, `netebpf_ext_unit_tests`, `sanitize_unit_tests` |
| **Functional Tests** | `bpf2c`, `bpf2c_conformance`, `cilium_tests`, `stress` |
| **Driver Tests** | `driver_tests`, `driver_native_only_tests`, `driver_native_only_arm64_tests`, `regression_driver_ws2022` |
| **Fuzzers** | `bpf2c_fuzzer`, `execution_context_fuzzer`, `verifier_fuzzer`, `core_helper_fuzzer`, `netebpfext_fuzzer` |
| **Other** | `ossar`, `fault_injection`, `fault_injection_netebpfext_unit`, `quick_user_mode_multi_threaded_stress_test`, `get_bpf_conformance_version` |

Scheduled-only jobs (e.g. `fault_injection_full`, `km_mt_stress_tests`, `performance`) need no change — they don't run on PRs.

### Step 3: Add a `ci_gate` status-gate job

This is the critical piece. GitHub branch protection requires specific check names to pass. When jobs are **skipped**, they report as "skipped" — not "success" — which blocks merging if those jobs are listed as required checks.

The solution: add a single gate job that **always runs**, inspects aggregate results, and becomes the **only required check** in branch protection:

```yaml
  # Status gate for branch protection.
  # Configure branch protection to require ONLY this job.
  ci_gate:
    name: CI/CD Gate
    if: always()
    needs:
      - check_changes
      - regular
      - onebranch
      - regular_native-only
      - unit_tests
      - unit_tests_native_only
      - unit_tests_native_only_arm64
      - netebpf_ext_unit_tests
      - bpf2c
      - bpf2c_conformance
      - driver_tests
      - driver_native_only_tests
      - driver_native_only_arm64_tests
      - regression_driver_ws2022
      - ossar
      - analyze
      - sanitize
      - bpf2c_fuzzer
      - execution_context_fuzzer
      - verifier_fuzzer
      - core_helper_fuzzer
      - netebpfext_fuzzer
      - cilium_tests
      - stress
      - sanitize_unit_tests
      - fault_injection
      - fault_injection_netebpfext_unit
      - quick_user_mode_multi_threaded_stress_test
    runs-on: ubuntu-latest
    steps:
      - name: Check job results
        run: |
          # If this is a docs-only PR, all jobs were skipped — that's OK.
          if [ "${{ needs.check_changes.outputs.has_code_changes }}" != "true" ]; then
            echo "Docs-only change — all CI jobs skipped. Gate passes."
            exit 0
          fi

          # Otherwise, verify no job failed or was cancelled.
          failed=false
          for result in \
            "${{ needs.regular.result }}" \
            "${{ needs.onebranch.result }}" \
            "${{ needs.regular_native-only.result }}" \
            "${{ needs.unit_tests.result }}" \
            "${{ needs.unit_tests_native_only.result }}" \
            "${{ needs.unit_tests_native_only_arm64.result }}" \
            "${{ needs.netebpf_ext_unit_tests.result }}" \
            "${{ needs.bpf2c.result }}" \
            "${{ needs.bpf2c_conformance.result }}" \
            "${{ needs.driver_tests.result }}" \
            "${{ needs.driver_native_only_tests.result }}" \
            "${{ needs.driver_native_only_arm64_tests.result }}" \
            "${{ needs.regression_driver_ws2022.result }}" \
            "${{ needs.ossar.result }}" \
            "${{ needs.analyze.result }}" \
            "${{ needs.sanitize.result }}" \
            "${{ needs.bpf2c_fuzzer.result }}" \
            "${{ needs.execution_context_fuzzer.result }}" \
            "${{ needs.verifier_fuzzer.result }}" \
            "${{ needs.core_helper_fuzzer.result }}" \
            "${{ needs.netebpfext_fuzzer.result }}" \
            "${{ needs.cilium_tests.result }}" \
            "${{ needs.stress.result }}" \
            "${{ needs.sanitize_unit_tests.result }}" \
            "${{ needs.fault_injection.result }}" \
            "${{ needs.fault_injection_netebpfext_unit.result }}" \
            "${{ needs.quick_user_mode_multi_threaded_stress_test.result }}"
          do
            if [ "$result" = "failure" ] || [ "$result" = "cancelled" ]; then
              echo "FAIL: A required CI job reported: $result"
              failed=true
            fi
          done

          if [ "$failed" = "true" ]; then
            exit 1
          fi
          echo "All CI jobs passed. Gate passes."
```

### Step 4: Update branch protection rules

In the GitHub repo settings (**Settings → Branches → Branch protection rules** for `main`):

1. **Remove** all individual CI/CD job names from the required status checks list.
2. **Add** `CI/CD Gate` as the single required check from the CI/CD workflow.
3. Keep any other required checks from other workflows as-is (e.g., `Validate-YAML`, `Dependency Review`).

### Step 5 (Optional): Skip lightweight workflows too

For `validate-yaml.yml`, `dependency-review.yml`, and `scorecards-analysis.yml`, you could add `paths-ignore`:

```yaml
on:
  pull_request:
    paths-ignore:
      - 'docs/**/*.md'
```

Since these run in < 1 minute on `ubuntu-latest`, the cost savings are minimal. Recommendation: leave them as-is unless they also have required checks that need the gate pattern.

## Summary of Changes

| File | Change |
|------|--------|
| `.github/workflows/cicd.yml` | Add `check_changes` job; add `has_code_changes` condition to ~25 PR-triggered jobs; add `ci_gate` aggregation job |
| **GitHub repo settings** | Update required status checks to use `CI/CD Gate` instead of individual job names |

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| `dorny/paths-filter` doesn't detect changes on `schedule`/`workflow_dispatch` | It defaults to reporting all files as changed, so all jobs run — correct behavior |
| Merge queue (`merge_group`) base ref issues | `dorny/paths-filter` v3 supports `merge_group` events |
| A `.md` file outside `docs/` is changed and gets incorrectly skipped | Current scope is limited to `docs/**/*.md` only; `.md` files elsewhere still trigger CI |
| Forgotten job in the `ci_gate` `needs` list | Audit the `needs` list against all PR-triggered jobs before merging; add a comment in the YAML reminding maintainers to update the gate when adding new jobs |
| New required jobs added but not wired into the gate | Add an onboarding note to the workflow file and `CONTRIBUTING.md` |

## Estimated Effort

- Workflow file changes: one PR modifying `.github/workflows/cicd.yml`
- Branch protection update: manual repo settings change (coordinate with repo admins)
- Testing: open a test PR with only a `docs/` `.md` change and verify all checks show green
