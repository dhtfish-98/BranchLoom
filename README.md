# BranchLoom

BranchLoom analyzes AArch64 control-flow flattening and register-based dispatch
through an IDA adapter. Its six-stage pipeline and 13 commands retain the baseline
behavior, artifact JSON schemas, configuration fields and write gates.

## Install and use

Python 3.9 or newer. The core uses the standard library. YAML configuration and the
reference emulator remain optional extras.

```sh
python -m pip install -e ".[config,verify,dev]"
branchloom --help
branchloom census --config my.json
branchloom classify --config my.json --in cff_dispatchers.json
branchloom resolve --config my.json --in cff_predecessors.json --source static
branchloom plan --config my.json --in cff_resolutions.json
branchloom apply --config my.json --in cff_patch_plan.json
python -m pytest -q
python checks/orchestrator.py
```

Commands: `census`, `classify`, `resolve`, `plan`, `apply`, `switch`, `revert`,
`clean`, `trace`, `verify`, `regress`, `discover`, `run`.

`switch` retains metadata-only behavior. `linear` and `full` retain their
known-vector verifier gate. Standalone `apply` previews a plan; byte writes still
require the existing `run --apply` pipeline. `--dry-run` continues to override
write intent. No inherited write-policy gap has been silently changed.

## Source organization

- `arm_words/`: recognition, shared displacement packing, logical-field expansion,
  bounded instruction walks and constant chains.
- `records/`: renamed record shapes, a table-driven wire codec and JSON exchanges.
- `dispatch_shapes/`: indexed, register-table, comparison-tree and filler patterns.
- `target_sources/`: image-table, observed-trace and oracle-backed resolution.
- `pipeline/`: enumeration, categorization, destination lookup, rewrite design,
  byte commit and graph commit.
- `integrity/`: clobber scans, site checks and pristine-image restoration.
- `equivalence/`: process/Unicorn oracles, libc shims and batch verdicts.
- `database/`: IDA boundary and main-thread background execution.
- `console/`: arguments, operation registry, runtime context and command handlers.
- `examples/routeprobe/`: renamed synthetic C target and Python reference.

## Verification boundaries

The rewrite is compared with the current baseline, including its experimental
limitations. IDA-dependent code has not been claimed as validated on a live IDB.
The reference verifier's patched-byte integration and the inherited end-to-end
restore/rerun gap remain documented in `guides/` and the implementation status.
Synthetic fixtures and import checks cannot establish equivalence on arbitrary
third-party targets. See `VALIDATION.md`, `ORIGIN.md` and `LICENSE`.

Remaining implementation questions use `TODO(validate)` markers; the inventory
retains 38 occurrences, including 33 in package code.
