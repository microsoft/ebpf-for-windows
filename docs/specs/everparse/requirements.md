<!-- Copyright (c) eBPF for Windows contributors -->
<!-- SPDX-License-Identifier: MIT -->

# EverParse Build Mitigation — Requirements Specification

## 1. Overview

This specification defines the repository workflow for EverParse-generated artifacts in `ebpf-for-windows`.
The goal is to reduce intermittent CI failures and developer friction caused by regeneration of `.c` and `.h`
files from `.3d` sources, while preserving `.3d` files as the authoritative input.

Today, the repository has two EverParse generation entry points:

- `libs\ioctl_spec\EbpfProtocol.3d`, which generates sources into `libs\ioctl_spec\generated\`
- `libs\elf_spec\Elf.3d`, which generates sources into `libs\elf_spec\generated\`

Both projects invoke `packages\EverParse.2022.6.13\lib\native\win-x86_64\everparse.cmd`.

## 2. Goals

The workflow defined by this specification must prioritize:

1. Reducing intermittent failures on 1ES runners.
2. Reducing developer inner-loop friction.
3. Minimizing runtime cost only where it materially affects developers.

## 3. Scope

### 3.1 In Scope

- Source-of-truth rules for `.3d` inputs and generated `.c`/`.h` outputs.
- Rules for when regeneration is required.
- CI behavior for authoritative regeneration and divergence detection.
- Divergence failure behavior and issue-tracking behavior.
- Determinism and tool-version pinning requirements.
- Repository policy for committed generated artifacts.

### 3.2 Out of Scope

- Changes to EverParse semantics or the `.3d` language.
- Hand-maintaining generated `.c` or `.h` files.
- Full CI YAML or script implementation details.
- Automatic remediation pull request creation.
- Performance work unrelated to developer workflow impact.

## 4. Definitions

| Term | Definition |
| --- | --- |
| `.3d` files | Authoritative EverParse input files. |
| Generated artifacts | The `.c`, `.h`, and wrapper files produced from `.3d` inputs. |
| Divergence | A mismatch between freshly generated output and the committed generated artifacts for the same pinned inputs. |
| Regeneration input set | All repository-tracked inputs that can change generated output, including `.3d` files, generation project files, and tool-version pins. |
| Generation unit | One logical EverParse generation boundary with one authoritative `.3d` root and its derived outputs. |
| Default path | The normal developer and CI path for routine changes. |
| 1ES runners | Self-hosted runners that are a first-order stability constraint for this effort. |

## 5. Current Repository Context

- `libs\ioctl_spec\ioctl_spec.vcxproj` defines a custom build step for `EbpfProtocol.3d` and emits:
  `EbpfProtocol.h`, `EbpfProtocolWrapper.h`, `EverParse.h`, `EverParseEndianness.h`, `EbpfProtocol.c`, and
  `EbpfProtocolWrapper.c`
  into `libs\ioctl_spec\generated\`.
- `libs\elf_spec\elf_spec.vcxproj` defines a custom build step for `Elf.3d` and emits:
  `Elf.h`, `ElfWrapper.h`, `EverParse.h`, `EverParseEndianness.h`, `Elf.c`, and `ElfWrapper.c`
  into `libs\elf_spec\generated\`.
- Both EverParse projects pin package version `2022.6.13` in `packages.config`.
- Existing GitHub-hosted build jobs run on `windows-2022`, while several driver and regression test jobs use self-hosted 1ES runners.

## 6. Functional Requirements

### 6.1 Source of Truth

- **REQ-SRC-001**: The repository **MUST** treat `.3d` files as the sole authoritative source for EverParse-generated artifacts.
  - **AC-1**: Repository documentation states that `.3d` files are authoritative.
  - **AC-2**: Generated `.c` and `.h` files are explicitly documented as derived artifacts.

- **REQ-GUARD-001**: The workflow **MUST NOT** treat committed generated `.c` and `.h` files as hand-maintained source.
  - **AC-1**: Direct manual edits to generated artifacts are documented as unsupported.
  - **AC-2**: Validation detects generated-artifact edits by treating committed generated outputs as protected paths that trigger authoritative comparison.

### 6.2 Committed Artifact Policy

- **REQ-ART-001**: The repository **MUST** permit generated `.c` and `.h` artifacts to be committed.
  - **AC-1**: The documented workflow for modifying EverParse-backed functionality includes committing generated artifacts.
  - **AC-2**: A clean checkout with committed generated artifacts is sufficient for the normal consumer build path without mandatory local regeneration.

### 6.3 Regeneration Triggers

- **REQ-TRG-001**: The workflow **MUST** require regeneration when any file in the regeneration input set changes.
  - **AC-1**: The workflow defines explicit trigger coverage for `.3d` changes.
  - **AC-2**: The workflow defines how non-`.3d` inputs that affect generation are included in the regeneration input set.

### 6.4 Divergence Detection

- **REQ-VAL-001**: CI **MUST** regenerate authoritative outputs and compare them against committed generated artifacts when regeneration is required.
  - **AC-1**: A change touching the regeneration input set causes regeneration and comparison.
  - **AC-2**: A change outside the regeneration input set does not require regeneration comparison in the default path.

- **REQ-VAL-002**: If CI detects divergence, the validation result **MUST** fail.
  - **AC-1**: Divergent generated output produces a failing status.
  - **AC-2**: The failure message identifies the affected generation unit or output set.

### 6.5 Divergence Tracking

- **REQ-ISSUE-001**: If trusted repository CI detects divergence, the workflow **MUST** open a new issue or update an existing issue.
  - **AC-1**: Divergence on trusted repository events such as `schedule`, `push`, or `merge_group` causes an issue-management action in addition to validation failure.
  - **AC-2**: Repeated divergence for the same underlying condition updates or deduplicates existing tracking instead of creating unbounded duplicates.
  - **AC-3**: Untrusted or developer-initiated contexts such as `pull_request` and ad hoc `workflow_dispatch` runs fail validation but do not write issues.

- **REQ-ISSUE-002**: A divergence issue **MUST** identify the affected generated artifact set and the triggering revision.
  - **AC-1**: The issue includes the commit or run identifier that observed divergence.
  - **AC-2**: The issue lists the diverged files or logical generation unit.

### 6.6 Developer Workflow

- **REQ-DEV-001**: The default developer workflow **SHOULD** avoid local regeneration on unrelated changes.
  - **AC-1**: Repository guidance distinguishes changes that require regeneration from those that do not.
  - **AC-2**: A developer changing code outside the regeneration input set can complete the normal local workflow without mandatory EverParse regeneration.

## 7. Non-Functional Requirements

- **REQ-REL-001**: The default validation path **MUST** minimize dependence on unstable 1ES runner behavior for unchanged generated artifacts.
  - **AC-1**: A change that does not touch the regeneration input set can pass required validation without executing EverParse regeneration on 1ES.
  - **AC-2**: The design explicitly identifies where 1ES-dependent regeneration is avoided, isolated, or made non-default.

- **REQ-DET-001**: The regeneration workflow **MUST** be deterministic with respect to the defined regeneration input set.
  - **AC-1**: The workflow defines the toolchain/version boundary that must be pinned or controlled.
  - **AC-2**: A change in pinned generation tooling is itself regeneration-triggering.

- **REQ-OPS-001**: Divergence signaling **SHOULD** be actionable for maintainers.
  - **AC-1**: Validation output distinguishes divergence from infrastructure failure.
  - **AC-2**: Issue content includes enough context to distinguish stale committed output, toolchain drift, and environment instability.

## 8. Constraints

- **CON-001**: The workflow must fit the existing `ebpf-for-windows` repository layout and build system.
- **CON-002**: 1ES runner instability is a first-order design constraint.
- **CON-003**: `.3d` files remain the sole source of truth.
- **CON-004**: Generated `.c` and `.h` artifacts are intended to be committed.
- **CON-005**: Divergence handling must both fail validation and create or update issue tracking.

## 9. Assumptions

- **ASM-001**: Generated `.c` and `.h` outputs are deterministic when the regeneration input set and toolchain are fixed.
- **ASM-002**: The repository can identify a finite regeneration input set beyond the `.3d` files alone.
- **ASM-003**: CI can distinguish infrastructure failure from genuine output divergence.
- **ASM-004**: Commit churn from generated artifacts is acceptable if it materially reduces intermittent failures and developer friction.

## 10. Open Questions

1. Which repository-tracked files belong in the complete regeneration input set beyond `.3d`, `packages.config`, and the `.vcxproj` custom-build definitions?
2. Should a future iteration add automated remediation pull requests, or should issue-only tracking remain the long-term boundary?

## 11. Revision History

| Version | Date | Author | Changes |
| --- | --- | --- | --- |
| 0.1 | 2026-06-12 | Copilot | Initial requirements specification. |
