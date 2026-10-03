# Changelog

## Unreleased

### Fixes

- Default phase calls to preview unless an explicit write is requested. Make the
  standalone `apply` CLI preview-only; byte changes use `run` with its verifier and
  rollback flow. P5 also rejects byte writes in switch mode or without vectors.
- Report switch-phase exceptions as a failed run and return a nonzero exit code.
- Add four in-memory regression cases (88 tests total); no live IDA validation.
- Remove remaining absolute-safety wording from errors and accept incorrect-patch
  reports consistently with the security policy.

### Documentation

- Align config, methodology and security notes with the current verifier limits;
  document external command execution, pickle trust requirements and missing
  repair/on-device modules. Describe the package as experimental analysis tooling.

- State the unflatten64 origin and current maintenance work in the README; remove
  the conflicting claim that the repository contains no third-party code.
- Put the unvalidated IDA pipeline status first, distinguish synthetic sample
  vectors from private target data, and correct claims of guaranteed safety and
  before/after verification.
- Align the implementation status, safety requirements and sample description
  with those limits. No runtime code or validation marker was changed.
- Replace the project-transfer wording with code provenance. The attribution does
  not assert a project handover or endorsement by the upstream author.

## 0.2.0

### Source and changes

This release is based on code from
[unflatten64](https://github.com/DumpA1n/unflatten64) `0.1.0` by **DumpA1n**, under
the MIT license. The analysis core, the methodology in
[`guides/METHODOLOGY.md`](guides/METHODOLOGY.md) and the safety model in
[`guides/SAFETY.md`](guides/SAFETY.md) are the original author's work; the copyright
notice is kept in [LICENSE](LICENSE) alongside the maintainer's.

What changed in this release, relative to upstream `0.1.0`: project, package, console
script and config files renamed to `branchloom`; the CLI restructured into a package;
the test suite grown from 16 cases to 84; `CHANGELOG.md`, `guides/VALIDATION_STATUS.md`
and CI added; the original author's local drive paths removed from module docstrings.

### Restructured

- **`console.py` (785 lines) is now the `console/` package.** The router was one file
  holding argument coercion, the IDA boundary, thirteen command handlers, the
  argparse wiring and the entry point. It is now:

  | module | holds |
  |--------|-------|
  | `console/__init__.py` | the entry point and the JSON/exit-code emitter |
  | `console/operations/` | the command registry and the handlers, grouped by job |
  | `console/arguments.py` | argparse wiring, generated from that registry |
  | `console/exchange_paths.py` | artifact filenames + the phase-module lookup |
  | `console/context.py` | the plumbing every handler shares |

- **One command registry.** A command's name, handler and help line used to live in
  three different places — the handler table, the argparse builder and a separate
  help dict — so adding a command meant editing all three and a mismatch was
  silent. They are one `OperationSpec` record in `console/operations/__init__.py`; the parser
  iterates it and the entry point looks up by name.

- Handlers are grouped by what they do rather than listed in definition order:
  `stage.py` (the six pipeline phases, one shared handler), `restoration.py` (revert,
  clean), `evidence.py` (trace, verify, regress), `survey.py` and `orchestrator.py`.

- Cleaned stale absolute paths out of 13 module docstrings. They pointed at a
  private toolchain that is not in this repository; the file basenames that name
  each algorithm are kept.

No behaviour changed in this restructure: the same thirteen commands, the same
options, the same help text, the same JSON output and exit codes.

### Tested

Unit tests went from 16 cases to **84**, all passing under `pytest` and under the
bundled dependency-free runner. New coverage:

- `checks/test_value_chains.py` (17) — every constant-derivation chain the resolver
  models (MOVZ/MOVN, MOVZ+MOVK slice merge, register copy, ADD/SUB/ORR/EOR chains,
  modular 32-bit arithmetic, WZR), and the other side of the contract: an
  unmodelled producer, a clobbering call, unmapped memory and an over-deep chain all
  return `None` rather than a guess.
- `checks/test_records.py` (15) — JSON round-trip for all four inter-phase artifacts,
  the `0x..` hex convention, optional addresses staying `None` instead of becoming
  `0`, and the `cls` ↔ `class` key rename.
- `checks/test_settings.py` (17) — the aggressive-mode gate (`linear`/`full` are
  refused without `verifier.known_vectors`, and a backend alone does not open it),
  `exec_segments` validation, and the `cff` accessor defaults and overrides.
- `checks/test_console.py` (19) — registry ↔ parser agreement, `--config` required on
  every command, the phase artifact chain linking up, `--dry-run` beating `--apply`,
  and that importing the CLI does not import `idaapi`.

One config behaviour is now pinned by test rather than changed:
`cff.dispatch_base_overrides` parses **every string key as hex**, so a
decimal-looking key such as `"8192"` means `0x8192`. That matches the `0x..`
convention used for addresses everywhere else in the project. Write addresses with
an explicit `0x` prefix.

### Unchanged

The analysis core is untouched: the six phases, the IDA adapter, the pattern
matchers, the resolution sources, the verifier and regression harness, and the
safety layer. They remain not-yet-IDA-validated, with 33 `TODO(validate)` markers.
**Do not trust the tool on a real binary until you have wired it to your IDA and
validated the pipeline on a neutral binary you control.**

## 0.1.0

Initial release.
