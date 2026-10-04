# Implementation status

This document separates implemented code from validated behaviour. **The
IDA-dependent phase layer is inherited from unflatten64 and has not been validated
in a live IDA session in this repository.** Its descriptions of a private reference
toolchain are not validation evidence for this implementation. The pure-Python
layers below have unit tests; recorded checks are in
[VALIDATION.md](VALIDATION.md); historical baseline runs remain in
[guides/VERIFICATION.md](guides/VERIFICATION.md).

Legend: ✅ implemented + tested · 🟡 implemented, needs IDA/on-target validation ·
⬜ specified, not yet written.

## Core (pure Python, no IDA) — testable in CI

| module | status | notes |
|--------|--------|-------|
| `arm_words/recognition.py` | ✅ | recognizers/extractors for BR/BLR/RET, dispatcher loads, state load/store, MOVZ/MOVN/MOVK, CSEL family + aliases, ALU-imm, ADR/ADRP, `loom_writes_reg` |
| `arm_words/emission.py` | ✅ | `emit_jump` / `emit_conditional_jump` / `emit_bit_jump` with range+alignment guards; skip-on-`None` contract |
| `arm_words/logical_fields.py` | ✅ | `DecodeBitMasks` logical-immediate decoder |
| `arm_words/value_chains.py` | ✅ | ALU-chain constant propagation (bounded, carry-safe); every derivation form + the never-guess contract are unit-tested |
| `records/shapes.py` | ✅ | dataclasses + JSON for dispatchers/predecessors/resolutions/patch-plan; all four round-trips unit-tested |
| `settings.py` | ✅ | YAML (PyYAML) or JSON config; validates segments + gates linear/full on a verifier — the gate is unit-tested |
| `console/` | ✅ | argparse router over one command registry; wiring + write-intent rules unit-tested (the handlers themselves still need IDA) |

**In the local 0.2.1 source checks, 94 cases pass with the optional Unicorn verifier
installed** (`pytest -q`). The dependency-free runner executes the other 92 cases
and passes without pytest or Unicorn. Exact-commit remote CI is a separate gate:

| file | cases | covers |
|------|-------|--------|
| `checks/test_arm_words.py` | 18 | recognition/emission/bitmask against hand-derived ARM ARM encodings |
| `checks/test_value_chains.py` | 17 | every constant-derivation chain, and that everything else is `None` |
| `checks/test_settings.py` | 17 | the aggressive-mode verifier gate, segment validation, cff accessors |
| `checks/test_records.py` | 17 | JSON round-trip for all four inter-phase artifacts |
| `checks/test_console.py` | 19 | command registry ↔ parser wiring, dry-run-wins, no `idaapi` at import |
| `checks/test_commit_boundary.py` | 4 | real CLI/P5 with an in-memory adapter: default preview, rejected standalone writes, mode checks and switch failure propagation |
| `checks/test_machine_oracle_completion.py` | 2 with Unicorn | synthetic AArch64 B-to-self must fail after the instruction budget; RET must pass; cached emulator completion resets between calls |

## The pipeline — implemented, needs live IDA validation

All modules below are written and pass a coherence gate here: `compileall` is clean,
and **every module imports successfully except `database/bridge.py`** (which needs a live
`idaapi`). These checks cover imports, not runtime behaviour. The pipeline has
**not been run against live IDA.** 33 `TODO(validate)` markers record assumptions
that still need validation; they are not an exhaustive list of possible defects —
`git grep -n "TODO(validate)" -- branchloom` (with a plain `grep -rn`, add `-I`, or the
byte matches inside `__pycache__` are counted too). Repository-wide there are 38;
[`guides/VALIDATION_STATUS.md`](guides/VALIDATION_STATUS.md) lists every one with the
evidence that exists and what would close it.

| module | status | source of truth |
|--------|--------|-----------------|
| `arm_words/neighbourhood.py` | 🟡 | bounded reverse-instruction iterator + clobber modelling |
| `database/bridge.py` | 🟡 | the ONLY `idaapi/ida_*` importer; segment select by name **or** range |
| `database/worker_process.py` | 🟡 | `execute_sync(MFF_WRITE)` bridge for long main-thread work |
| `pipeline/enumeration.py` … `graph_commit.py` | 🟡 | the six phases in METHODOLOGY.md §5 |
| `dispatch_shapes/indexed_routes.py` | 🟡 | Family-A matcher |
| `dispatch_shapes/register_routes.py` | 🟡 | Model-1 single-level matcher (behind `mode`) |
| `dispatch_shapes/comparison_routes.py` | 🟡 experimental | Model-2 — heuristic; 4 of the 33 `TODO(validate)` markers, tied with two other modules |
| `dispatch_shapes/filler_repair.py` | 🟡 | trap-BLR fold + dead-DCB NOP |
| `target_sources/image_tables.py` · `observed_routes.py` · `oracle_routes.py` | 🟡 | the three resolution sources |
| `equivalence/contracts.py` | 🟡 | the `evaluate_io(entry, input)->output` ABC |
| `equivalence/machine_oracle.py` | 🟡 | reference Unicorn backend (config-driven memory layout + shim registry); return-sentinel completion gate has synthetic Unicorn regression coverage, but target behavior remains unvalidated |
| `equivalence/batch_verdict.py` | 🟡 | batch verdict + oracle equivalence |
| `integrity/clobber_scan.py` · `site_validation.py` · `image_restore.py` | 🟡 | SAFETY.md §4, §9, §10 |
| `repair/boundary.py` · `eh_pads.py` | ⬜ | opt-in, off by default — not yet written |

### Validation hotspots (do these first, on a neutral binary)

1. **`database/bridge.py`** — the whole tool rides on it. Confirm `loom_get_dword` returns the
   LE instruction word, `exec_segments` resolves your config selectors, and
   `loom_add_jump_xref` renders the graph edge (it uses `fl_JN`; flip to `fl_JF` if IDA
   disagrees — see the TODO).
2. **`dispatch_shapes/indexed_routes.find_dispatchers`** — the P1 detector; verify it finds the
   real dispatchers and resolves both table bases before trusting anything downstream.
3. **`target_sources/image_tables`** — the `ea → reloc-image offset` mapping assumes a flat
   `ea - base` layout; validate table reads against a live dump.
4. **`equivalence/machine_oracle`** — memory-layout + IAT + shim registry + output extraction
   are the reference's shape parameterised; exercise it on a known I/O vector.
5. **`dispatch_shapes/comparison_routes`** — experimental; keep behind a flag until it has a
   neutral-binary corpus. Do not ship as a headline feature yet.

## Open decisions (carried from the design spec)

1. **v1 scope** — ship Family-A two-level + `switch` mode as the solid core; keep
   Model-1/Model-2 and `linear`/`full` behind flags until each has a neutral-binary
   regression corpus. (current lean: yes)
2. **Distribution** — `ida-pro-mcp py_exec_file` toolkit, standalone idapython
   package, or both? Decides whether `database/worker_process.py` is mandatory.
3. **Neutral demo corpus** — `examples/routeprobe/` includes synthetic AArch64 source,
   a build recipe and a Python reference for known-answer vectors, inherited with
   the upstream code. These provide test inputs, not a recorded end-to-end IDA run.
   The intended compiler output and table-layout caveats are described in the
   sample README; validate the generated binary for the toolchain actually used.
4. **`linear`/`full`** — ship in public v1 (gated on verifier + known vectors) or hold?
5. **Verifier `command` backend** — confirm `stdin=input / stdout=output` (hex option)
   is enough for on-device / IDA-debugger harnesses.

## Target data and fixtures

Synthetic fixtures, example configs and `examples/routeprobe/` source and known-answer
vectors are included. Third-party target binaries, private dumps, target-specific
tables, keys and regression baselines are outside the repository's scope. Keep
those in local configs and artifacts. `.gitignore` excludes common artifact paths;
it does not inspect or guarantee the contents of tracked files.
