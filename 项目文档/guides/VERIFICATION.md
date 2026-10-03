> Historical baseline evidence: the runs and commits below belong to the upstream
> project recorded in `../ORIGIN.md`. Paths and current API names have been updated;
> current rewrite checks are recorded in `../VALIDATION.md`.

# Verification

This file maps the claims in [README.md](../README.md) and
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) to something a reader can
check, and says which of them were actually re-run for this revision.

## The test suite

```console
$ python3 checks/orchestrator.py            # or: python3 -m pytest -q
...
total=88 pass=88 fail=0
```

The bundled runner needs nothing installed. Re-run on Python 3.9.6 (macOS 26.7,
arm64) for the write-boundary fixes: 88 pass, 0 fail. CI runs the same suite on Linux 3.9 and
3.13 and on macOS 3.13, plus the dependency-free runner as its own job.

What the 88 cases cover — the ISA recognition/emission/bitmask layer, the bounded constant
resolver, the inter-phase artifact model, the config gate and the CLI wiring — is
listed per file in
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md#core-pure-python--no-ida--testable-in-ci).

The four write-boundary regressions use the real CLI and P5 with a disposable
in-memory adapter. They verify preview defaults, rejection of standalone writes,
mode checks and failure exit status. They do not run IDA.

## The validation inventory

```console
$ python3 utilities/inventory_validation.py --expect 38
```

Exits non-zero if the repository no longer contains the 38 `TODO(validate)` markers
that [guides/VALIDATION_STATUS.md](VALIDATION_STATUS.md) inventories. CI runs this
as a separate job, so a marker added or removed without updating the document fails
the build rather than silently leaving the document wrong. Exit status 0 for this
revision.

## What has never been run

**Nothing in the IDA-dependent phase layer has been executed against a live IDA, and
no target binary has been processed end to end.** The six phases, the IDA adapter,
the pattern matchers, the resolution sources, the verifier and the safety layer are
all 🟡 in `IMPLEMENTATION_STATUS.md`: written, import-checked, and never validated in
the environment they claim to support. `guides/VALIDATION_STATUS.md` inventories every
place the code assumes beyond its reference and what evidence exists for each.

Two supporting facts a reader can check directly:

- The whole package compiles, and every module imports except the deliberate
  `idaapi` seam in `branchloom/database/bridge.py`.
- The one sample, `examples/routeprobe/`, is a synthetic target written for this
  repository — it is not evidence about any real obfuscated binary.

If you run the phase layer against IDA, that is a validation data point worth
reporting; see [SECURITY.md](../.github/SECURITY.md) for how. Incorrect patches,
unexpected writes and failed restoration should be reported with a minimal sample
and the exact commit, including while the pipeline remains experimental.
