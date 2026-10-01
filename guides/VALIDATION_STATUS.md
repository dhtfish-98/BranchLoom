# Validation status — the `TODO(validate)` inventory

## Scope

This document inventories every `TODO(validate)` occurrence in the repository at
commit `ae0a9c3` (`main`, "Present the project under its current maintainer"), states
what each one claims is unverified, what evidence already exists for it in this
repo, and what environment would actually close it.

The source paths, API references and marker line locations were updated on
2026-10-01 for the rewrite. The evidence descriptions below remain historical.

It is a **point-in-time snapshot of that commit**, not a description of the current
tip: the files whose counts are recorded here (the `TODO(validate)` markers, the test
cases) have changed since, and later commits also added CI and the repository-wide
inventory script. Where this document and the code disagree, the code is the record.

The marker's meaning throughout the codebase is fixed: *the behaviour is asserted by
reading the code, or exercised only through a synthetic sample / emulator / test
double, and has not been confirmed against the real environment it claims to
support.*

## What this document is not

- It is **not a test report**. Nothing here validates anything.
- It **closes nothing**. No marker was removed, weakened, or reworded; no source
  module was modified.
- It records only what was read and counted. No IDA Pro session was opened, no
  target binary was loaded, no ARM64 sample was built, no trace or memory dump was
  produced, and `unicorn` was not run (it is not installed in this environment).

Verification actually performed for this document: the marker count and its
per-file/per-line locations; reading the code and comments around every marker;
reading the neighbouring tests and the sample documentation; an import-health check
over the package; and the repository's own test runner. Everything else in the
"how to close" fields is a proposal, not a result.

## How the markers were enumerated

```bash
# from a checkout of this repository
git grep -n "TODO(validate)" HEAD          # 38 lines
git grep -l "TODO(validate)" HEAD | wc -l  # 22 files
git grep -n "TODO(validate)" HEAD -- branchloom | wc -l   # 33 (package only)
git grep -n "TODO(validate)" ae0a9c3 -- . | wc -l       # 38 (same commit, whole tree)
```

`git grep` is used because it ignores the working tree's build artifacts and
`.git/` and therefore reproduces the same number on any checkout of that commit.
The count is also reproducible with the inventory script added alongside this
document:

```bash
python3 utilities/inventory_validation.py --expect 38
```

Two caveats about naive greps:

- **Working-tree grep is artifact-sensitive.** `grep -rn "TODO(validate)" branchloom`
  prints **45** lines in a tree that contains `__pycache__` (33 text lines plus 12
  `Binary file ... matches` lines, because compiled copies of the same sources carry
  the string). `grep -rnI` (text only) prints 33.
- **This document and the script quote the marker by design**, so once they are
  committed a repo-wide grep returns more than 38. At this snapshot, those were the
  two excluded paths. The current exclusions are listed in the re-checking section.

## Marker forms

| form | count | where |
|------|-------|-------|
| `TODO(validate):` annotation | 31 | `branchloom/**/*.py` |
| prose cross-reference inside source | 2 | `dispatch_shapes/comparison_routes.py:31`, `integrity/clobber_scan.py:89` |
| mention in project markdown | 5 | `CHANGELOG.md`, `IMPLEMENTATION_STATUS.md` (×3), `README.md` |
| **total occurrences** | **38** | **22 files** |

`guides/*.md` (CONFIG/METHODOLOGY/SAFETY), `checks/` and `examples/` contain none.

## Summary

Counts by area and by the environment that can actually close the marker. "Needs"
is the cheapest environment that retires the claim **as written**; where a cheaper
partial check exists it is named in that marker's entry.

| area | V-ids | count |
|------|-------|-------|
| ida adapter | V-01 | 1 |
| isa | V-02 | 1 |
| patterns | V-03 … V-10 | 8 |
| resolve | V-11 … V-15 | 5 |
| verify | V-16 … V-22 | 7 |
| phases | V-23 … V-27 | 5 |
| safety | V-28 … V-30 | 3 |
| cli | V-31 … V-33 | 3 |
| docs | V-34 … V-38 | 5 |
| **total** | | **38** |

| needs | V-ids | count |
|-------|-------|-------|
| macOS only (unit test / decision / doc fix, no IDA, no device) | V-06, V-08, V-15, V-25, V-26, V-28, V-29, V-30, V-31, V-34, V-35, V-36, V-37, V-38 | 14 |
| IDA Pro 9.x + a real AArch64 database | V-01, V-02, V-03, V-04, V-13, V-17, V-18, V-23, V-27, V-32, V-33 | 11 |
| a real toolchain / device / corpus (built sample, memory dump, tracer, on-device backend) | V-05, V-07, V-09, V-10, V-11, V-12, V-14, V-16, V-19, V-20, V-21, V-22, V-24 | 13 |

Test coverage context for the whole inventory: the five test modules import only
`branchloom.arm_words.*`, `branchloom.records`, `branchloom.settings` and `branchloom.console.*`. **No test
imports `branchloom.dispatch_shapes`, `branchloom.pipeline`, `branchloom.target_sources`, `branchloom.integrity`
or `branchloom.equivalence`**, so every marker in those areas sits in code that has never
been executed by the suite. The one exception in spirit is `arm_words/value_chains.py`,
which is unit-tested (17 cases) even though its tuning window is not.

---

# Inventory

## ida adapter

### V-01 — `branchloom/database/bridge.py:210`

**Unverified claim.** `loom_add_jump_xref` adds the synthetic edge with `fl_JN` (nearest
code jump), argued to be the semantically correct flavour for in-segment AArch64
branches; the only proven reference tool used `fl_JF` for EH landing pads. Whether
IDA renders the edge, the code cross-reference and the CFG the same way with `fl_JN`
has not been checked on a real install — "flip to `fl_JF` on-device if IDA's CFG
rendering disagrees."

**Evidence that exists.** The call site is the package's only xref-writing code
(`pipeline/graph_commit.loom_install` / `revert` add and delete these edges, `guides/SAFETY.md`
§8 documents the same `add_cref(fl_JN)` choice, and the log/revert path exists).
`checks/test_console.py::test_importing_the_cli_does_not_import_idaapi` pins only that no
IDA import happens outside a live session. Nothing in `checks/` imports
`branchloom.database.bridge`; the module cannot even be imported off-device — the checked
interpreter raises `ModuleNotFoundError: No module named 'idaapi'` for it. No
IDA-produced graph edge exists anywhere in the repo.

**How to close it.** In IDA Pro 9.x with an AArch64 database, run
`branchloom switch --config <cfg> --in cff_dispatchers.json --apply` on a real
dispatcher, then confirm in the graph and the xref list that each logged
`br_ea → target` edge appears, that `revert` removes exactly those edges without
undefining the targets, and that Hex-Rays' decompilation is unaffected. Switch to
`fl_JF` if the CFG disagrees.

**Needs.** IDA Pro.

**This is the marker that says the IDA-side behaviour has never been exercised on
a real IDA install.** It is the only `TODO(validate)` in `branchloom/database/bridge.py`,
and that module is the only place in the package that imports `idaapi`/`ida_*`. What
that means for a reader of the adapter: every wrapper in the file (`loom_get_dword`,
`loom_read_input_bytes`, `exec_segments`, `loom_func_at`, `loom_reanalyze`, `loom_make_code`,
`loom_clear_switch_info`, the xref pair, …) is written by reading IDA's API and has no
executed evidence behind it in this repo — no unit test, no recorded IDA run, and no
importable module to smoke-test outside IDA (it fails at import with
`ModuleNotFoundError: idaapi`). The marker itself scopes its doubt to the one call
with an IDA-visible side effect (`add_cref`), but the same absence of evidence
applies to the whole file; treat the adapter as a specification of the boundary,
not as a verified one.

## isa

### V-02 — `branchloom/arm_words/value_chains.py:161`

**Unverified claim.** `_SCAN_INSNS = 128` is a locally chosen back-walk window per
recursion level (the reference used ~400): too small and a distant MOVZ producer is
missed, too large and deep chains get slow. "Tune this window against a real
flattened function."

**Evidence that exists.** `checks/test_value_chains.py` (17 cases) covers every
derivation chain the resolver models — MOVZ/MOVN, MOVZ+MOVK slice merge, register
copy, ADD/SUB/ORR/EOR chains, modular 32-bit arithmetic, WZR, LSL#12 — plus the
never-guess contract (unmodelled producer, clobbering call, unmapped memory, depth
bound: `test_loom_depth_bound_is_enforced`). Those tests use hand-written word arrays, so
they pin behaviour at the window, not the fitness of its size.

**How to close it.** Run P2/P3 over a real flattened function and check that no
predecessor fails to resolve because its state producer lies beyond the window;
sweep the value (128/256/512) and compare classification counts and wall time.

**Needs.** IDA Pro.

## patterns

### V-03 — `branchloom/dispatch_shapes/register_routes.py:306`

**Unverified claim.** The local X-form masks `loom_is_add_imm64` (`ADD Xd, Xn, #imm`) and
`loom_is_mov_reg_x` (`MOV Xd, Xm`), used to walk a table base back to its ADRP/ADR, are
derived from the ARM ARM (C4.1) and not exercised against a binary — "confirm these
masks against a real dispatcher prologue on-device."

**Evidence that exists.** `branchloom/arm_words/recognition.loom_writes_reg` intentionally does not
model these 64-bit address forms, so no other layer validates them. Nothing in
`checks/` imports `branchloom.dispatch_shapes.register_routes`. The masks have no unit test at all.

**How to close it.** Cheapest partial: assemble the two forms with an AArch64
assembler and compare the words against the masks (macOS-only, `llvm-mc`/clang).
Full closure: run `loom_find_single_level` on a real single-level `CSEL → LDR → BR`
target in IDA and confirm the recovered table base equals a manual read of the
ADRP(+ADD)/MOV chain.

**Needs.** IDA Pro.

### V-04 — `branchloom/dispatch_shapes/register_routes.py:345`

**Unverified claim.** `loom_sets_flags` derives an NZCV-writer test from the
add/sub-with-S, logical-with-S (ANDS/BICS), conditional-compare and FP-compare
encodings. The set is described as faithful to the reference's `_FLAG_MOD_MNEMS`
list, but the raw masks are unverified on-device. The test is deliberately
inclusive, so a wrong mask can only cause a (safe) skip.

**Evidence that exists.** None: no test imports this module. The "inclusive ⇒ only
skips" argument is verifiable by reading `loom_flag_mod_in_gap` (its `True` result makes
`loom_classify_patch` refuse the site). `recognition.py` has no flag-modification predicate,
which is why the masks live here.

**How to close it.** Unit-test each mask family (ADDS/SUBS immediate and shifted,
ANDS/BICS, ANDS immediate, CCMP/CCMN, FCMP/FCMPE) against hand-assembled encodings,
with one negative case per family (macOS-only). Then confirm on a real binary that an
instruction in the `CSEL → BR` gap yields `flag_mod_csel_br = true` and a skip.

**Needs.** IDA Pro.

### V-05 — `branchloom/dispatch_shapes/register_routes.py:346`

**Unverified claim.** The reference also handled the "case-(b)" `[base, Xi]` load
shape preceded by `LSL Xi, Xj, #k` (variable entry size). Only the inline
`UXTW/LSL #3` 8-byte target load is ported; case-(b) is left for a follow-up "once a
case-(b) sample is available."

**Evidence that exists.** The gate is visible in code (`LOOM_D.loom_is_ldr_reg_x_lsl3`, with
everything else returning `None` from `loom_analyze_br`), so the gap is a known,
deliberate non-port rather than a silent failure. No test, no sample.

**How to close it.** Obtain or build a target whose dispatch table has a
register-scaled entry (e.g. an OLLVM-flattened AArch64 sample with a non-8-byte
entry), port the shape, and validate the resolved base/targets against a manual read
in IDA.

**Needs.** A real case-(b) sample (toolchain) plus IDA Pro.

### V-06 — `branchloom/dispatch_shapes/register_routes.py:347`

**Unverified claim.** The enable gate for single-level detection is a local choice —
`cff.single_level: true`, or `mode in ("linear", "full")` — defaulting to OFF so a
plain `switch` run never touches these sites. The marker asks to "confirm the desired
gate."

**Evidence that exists.** `checks/test_settings.py` (17 cases) pins the aggressive-mode
gate and the `cff` accessor defaults/overrides, but nothing imports `br_dispatch`, so
`loom_enabled`'s truth table is untested.

**How to close it.** Decide the product behaviour and pin `loom_enabled` with a unit test
over the (flag × mode) combinations — closable today on macOS. If the intent is that
aggressive modes should also touch Model-1 sites, confirm on a real target that a
`switch`-mode run leaves them untouched.

**Needs.** macOS only.

### V-07 — `branchloom/dispatch_shapes/comparison_routes.py:31`

**Unverified claim.** The module docstring says the Model-2 scan window is bounded by
a config knob rather than the true function end, because the Tier-1 adapter exposes
only a function's *start* (`loom_func_at`). It points at "the `TODO(validate)` notes and
`assumptions_todos`."

**Evidence that exists.** `bridge.loom_func_at` returns `(start_ea, name)` only (read
directly); `_DEFAULT_SCAN_INSNS = 4096`, overridable via `settings.loom_cff['ollvm_scan_insns']`.
The module is analysis-only (`applied: False`, `status: "experimental"`) and no test
imports it, so neither the window nor the traversal has ever run, even against
synthetic words. **`assumptions_todos` does not exist anywhere in the code**: the
identifier appears only in four prose references and is never defined or assigned —
the docstring points at a mechanism that is not implemented.

**How to close it.** Give the adapter a real function-end source (IDA's
`get_func(ea).end_ea`) or show that 4096 instructions cover the target functions, then
run Model-2 against a genuine OLLVM CMP-tree-flattened function. Either implement the
`assumptions_todos` reporting the docstring promises or delete the reference.

**Needs.** A real OLLVM-flattened sample (toolchain/device) plus IDA Pro.

### V-08 — `branchloom/dispatch_shapes/comparison_routes.py:156`

**Unverified claim.** The local `CMP` recognisers `loom_cmp_imm` and `loom_cmp_reg` (SUBS
immediate / shifted-register with `Rd == 31`) are derived from the ARM ARM and
unexercised; `recognition.py` exposes no CMP predicate.

**Evidence that exists.** Confirmed by reading `recognition.py`'s public API: it has
`loom_is_cbz_cbnz`, `loom_is_tbz_tbnz`, ALU-immediate and CSEL recognisers, but no CMP.
No test imports the module.

**How to close it.** Unit-test both masks with hand-assembled `CMP Wn,#imm`,
`CMP Xn,#imm`, `CMP Wn,Wm` words (plus shifted-register and negative cases) driven
through a synthetic `loom_read_word` — macOS-only, no IDA.

**Needs.** macOS only.

### V-09 — `branchloom/dispatch_shapes/comparison_routes.py:341`

**Unverified claim.** `loom_walk_dispatcher`'s BST-directed traversal is a simplified
port and "heuristic and unverified through this port": at each `CMP Wstate,K` +
`B.cc` it claims `magic[K] → handler` for the EQ case and the fall-through for NE,
queues non-EQ subtree targets, and deliberately does not scan handler bodies.

**Evidence that exists.** The simplification and its rationale are in the docstring;
unmodelled shapes are recorded in `result["unresolved"]` rather than guessed; the
recovered plan is never applied. No test imports the module.

**How to close it.** Run it against a real OLLVM Model-2 flattened function (or a word
dump from one) and diff the recovered `{magic → handler}` map against the true
mapping; ideally compare the proposed rewrite with a known-good unflattened build.

**Needs.** A real sample (toolchain/device) plus IDA Pro.

### V-10 — `branchloom/dispatch_shapes/comparison_routes.py:358`

**Unverified claim.** `loom_plan_cond` assumes the CSEL flags are still live at the
CSEL's own slot (true when the CSEL is the terminator's own compare); the reference's
shared-tail predecessor post-pass is not handled here.

**Evidence that exists.** The comment states the limitation. The single-level matcher
does carry a flag-clobber guard (`register_routes.loom_flag_mod_in_gap`), which the OLLVM
planner does not consult — verified by reading both modules. No test imports either.

**How to close it.** Build or locate a flattened function whose terminator shares a
tail with other predecessors; determine whether the condition is still valid at that
slot (or add the guard); validate the rewritten function against a known-good
unflattened binary.

**Needs.** A real sample (toolchain/device) plus IDA Pro.

## resolve

### V-11 — `branchloom/target_sources/oracle_routes.py:95`

**Unverified claim.** `loom_resolve_via_emu` drives only the verifier's configured default
entry; a per-dispatcher entry (e.g. `loom_dispatcher_value.loom_parent_fn_ea`) is deliberately not
assumed, because mid-function emulation would need a warmed-up machine state the
black-box `BehaviorOracle` interface does not model. "Wire an explicit entry through here
if a backend supports mid-function runs."

**Evidence that exists.** The code returns `None` (callers then fall back to
static/trace) whenever the verifier cannot introspect branches or has no entry.
`machine_oracle.evaluate_io(entry, input)` accepts an arbitrary entry but builds a fresh
call frame (it zeroes X0–X30 and resets SP/TPIDR — see V-22), so a mid-function entry
would start with an empty register file. No test imports `branchloom.target_sources`.

**How to close it.** A backend able to snapshot and restore machine state at the
dispatcher's function entry (or a trace observer that sees the state), then compare
its per-dispatcher targets with the static resolver on the same sites.

**Needs.** A device/emulator capable of mid-function runs (toolchain/device).

### V-12 — `branchloom/target_sources/image_tables.py:49`

**Unverified claim.** `MappedImage` treats the relocation-applied image as a flat
buffer whose file offset for an EA is `ea - base_ea`; a multi-segment image whose file
layout differs from its virtual layout would need a per-segment translator.

**Evidence that exists.** The assumption, plus two escapes, are documented: supply
pre-read bytes for the specific table span, or open IDA on the reloc image and pass
`use_reloc` with no registered image. `MappedImage.loom_slice` returns `None` out of range
and `loom_read_dword`/`loom_read_qword` then fall back to the database read. No test
constructs a `MappedImage`.

**How to close it.** Point `settings.loom_reloc_image` at a real multi-segment dump
(`dump_fix.bin`-style capture), resolve the same tables through it and through the
database, and require identical targets; if the layouts differ, add the per-segment
translator and pin it with a fixture.

**Needs.** A real memory dump (toolchain/device); the comparison itself is offline.

### V-13 — `branchloom/target_sources/image_tables.py:172`

**Unverified claim.** Rejecting a negative `state` before indexing is an addition over
the reference, which only ever fed non-negative CONST/COND2 states and did not guard;
if a target legitimately used signed states, this guard would silently drop them.

**Evidence that exists.** The behaviour is visible (`return (None, None)`), and callers
treat it as unresolved rather than patching. No test imports `target_sources/image_tables`.

**How to close it.** Inspect a real two-level target's state values (dispatcher state
table, traces, or the resolution log) for negative states; if they occur legitimately,
replace the guard with signed-offset handling and document it.

**Needs.** IDA Pro.

### V-14 — `branchloom/target_sources/observed_routes.py:148`

**Unverified claim.** Only the `{entry}` placeholder is substituted in
`settings.loom_trace['command']`; extending it (e.g. per-input vectors) is left for later. The
file-source path mirrors the reference's `br_targets_*.json`, but the command source
itself is an added convenience the reference never exercised ("the reference produced
traces out-of-band").

**Evidence that exists.** The command path is complete (substitution, `loom_shlex.split`,
`loom_subprocess.orchestrator`, stdout parsed as one document or a list), and the file-source path is
the default. No test imports `branchloom.target_sources.observed_routes`.

**How to close it.** Run a real tracing command against the target on a device/emulator
and feed the resulting trace document through `loom_load_traces`/`loom_verdict` for a target whose
branch behaviour is known; extend the substitution map only if the command needs it.

**Needs.** A device/emulator with a working tracer (toolchain/device).

### V-15 — `branchloom/target_sources/observed_routes.py:149`

**Unverified claim.** `loom_verdict()` returns `UNVERIFIED` when `static_target is None`
rather than inventing a verdict, on the assumption that the caller reports an
unresolved/invalid target as `INVALID` upstream (`records.LOOM_VERDICTS`).

**Evidence that exists.** The assumption is true in the current caller:
`pipeline/destination_lookup.loom_grade` returns `"INVALID"` when the target is `None`, before the
trace gate is consulted, and `records.LOOM_VERDICTS` is
`("OK", "UNVERIFIED", "MISMATCH", "INVALID")` (`records/shapes.py:190`). It is not pinned by any
test — the trace gate never returns `INVALID` itself.

**How to close it.** Unit-test `destination_lookup.loom_grade` with a `None` target under each
source (`static`/`trace`/`emu`) and assert `INVALID`, plus
`loom_verdict(None, pc, traces) == "UNVERIFIED"` to pin the division of labour — macOS-only.

**Needs.** macOS only.

## verify

### V-16 — `branchloom/equivalence/contracts.py:190`

**Unverified claim.** The `ondevice` backend is imported **by convention** as
`branchloom.equivalence.ondevice:OnDeviceVerifier`; the marker asks to confirm that module
path and class name when the backend is implemented.

**Evidence that exists.** `branchloom/equivalence/` contains only `__init__.py`,
`contracts.py`, `batch_verdict.py` and `machine_oracle.py` — there is no `ondevice.py`, so
`verifier.backend: ondevice` always ends in the `ValueError` branch today. That branch
is code-complete (ImportError → explanatory `ValueError`). No test imports
`branchloom.equivalence`.

**How to close it.** Implement (or rename) the backend, confirm the import path and
class name, and run the pipeline on a device.

**Needs.** A real device (toolchain/device).

### V-17 — `branchloom/equivalence/batch_verdict.py:274`

**Unverified claim.** The pass-report shape consumed by `loom_classify_sites`
(`sites=[{kind, br_ea, reason, self_check_ok, self_check_errors}]`) is ported from the
reference's expectations of `deobf_br_dispatch.orchestrator()`; the Tier-3 apply phase that
plays the `rerun_pass` role must emit exactly these keys, and they are unconfirmed.

**Evidence that exists.** The repo's own site producer (`dispatch_shapes/register_routes.loom_analyze_br`)
does build those keys — plus `model`, `ldr_ea`, `patch`, … — for the single-level model.
But nothing here produces a *rerun* pass report: `console/operations/orchestrator.loom_verifier_gate` calls
`batch_verdict.loom_run_regression(adapter, cfg, verifier, None)` (i.e. `rerun_pass=None`), and
`pipeline/byte_commit` has no re-orchestrator/report step. No test imports `branchloom.equivalence`.

**How to close it.** Wire the apply phase's re-run report into `loom_run_regression`, then
run one full `branchloom run --apply` on a real target and confirm the key names and the
patched/skipped counts.

**Needs.** IDA Pro.

### V-18 — `branchloom/equivalence/batch_verdict.py:275`

**Unverified claim.** `SAFETY.md` §11 asks for byte-identical behaviour *before vs
after* the patch; the Unicorn backend reads its own image (image / reloc_image /
segments dump), which does not reflect database patches, so this step compares
`evaluate_io` output against the captured expected vectors instead of against the patched
bytes. The comment proposes re-dumping a patched image or using the `ondevice` backend.

**Evidence that exists.** The code path is explicit, `loom_oracle_equivalence` compares
against `verifier.known_vectors()`, and `guides/SAFETY.md` §11 states the stronger
requirement. Neither proposed alternative is implemented or wired anywhere in the repo.
No test imports `branchloom.equivalence`.

**How to close it.** After an apply batch, re-dump the patched image (or use an
on-device backend) and compare before/after outputs byte-for-byte on the known vectors.

**Needs.** IDA Pro (to re-dump the patched database).

### V-19 — `branchloom/equivalence/machine_oracle.py:619`

**Unverified claim.** The reference read a single pickle of segments dumped from IDA;
this port generalises the source to pickle/JSON/ELF, and the ELF path assumes the entry
EA and table addresses live in the same space as the ELF `p_vaddr` — true for a `.so`
IDA maps at base 0, but a runtime-based dump needs `reloc_image`.

**Evidence that exists.** The loader priority is implemented and readable; `unicorn` is
an optional extra that is **not installed** in the checked environment
(`ModuleNotFoundError: No module named 'unicorn'`), so this module has never been
executed here. No test imports `branchloom.equivalence`.

**How to close it.** Run the backend against `librouteprobe.so` (or a real AArch64
`.so`/segment dump) with a known-answer vector and confirm the loaded ranges and the
entry address line up.

**Needs.** A built sample plus `unicorn` (toolchain/device).

### V-20 — `branchloom/equivalence/machine_oracle.py:620`

**Unverified claim.** `loom_place_input`'s default (write a NUL-terminated buffer at
INPUT_PTR and pass it in X0) reproduces the reference; the other modes
(`bytes_ptr_x0`, `scalar_x0`, `retval_x0`) and the `len_reg`/`ptr_reg` knobs are a
config-driven generalisation the reference target never exercised.

**Evidence that exists.** The sample's documented vector
(`in: 756e666c61743634`, `out: 2f3b4a4b5751969f`, `ret: 0xfc`) matches the default
pointer-in-X0 shape. Not executed here (no `unicorn`, no built `.so`).

**How to close it.** Run each input mode against a target whose ABI is known, starting
with the documented vector on `librouteprobe.so`.

**Needs.** A built sample plus `unicorn` (toolchain/device).

### V-21 — `branchloom/equivalence/machine_oracle.py:621`

**Unverified claim.** Default output extraction (read the NUL-terminated C string at
the X0 return pointer) reproduces the reference; `bytes_x0`, `retval`, `region`,
`cstr_ptr` and `max_len` are config-driven generalisations for other output ABIs.

**Evidence that exists.** The modes are implemented and readable. Worth noting for
whoever runs this first: `examples/routeprobe/README.md` documents its answer as both an
output buffer (`out: 2f3b4a4b5751969f`) and a register return (`ret: 0xfc`), so the
one sample shipped in this repo may naturally need a non-default extraction mode. That
has **not** been checked by running anything.

**How to close it.** Run each output mode against a target with a known ABI and compare
against `examples/routeprobe/probe_reference.py`.

**Needs.** A built sample plus `unicorn` (toolchain/device).

### V-22 — `branchloom/equivalence/machine_oracle.py:622`

**Unverified claim.** The reference reused the emulator across calls and set only X0,
relying on the analysed function not reading other input registers; this port
additionally zeroes X0–X30 each run for determinism. The marker asks to confirm that
the analysed function does not expect a live non-X0 argument register that the zeroing
would clobber.

**Evidence that exists.** The reset block is explicit (`for i in range(31)` writing
zero, then SP/TPIDR setup). Not executed here (no `unicorn`).

**How to close it.** Run a function that takes arguments in X1 or later and compare
results with and without the zeroing; or make the register preload configurable and
document the requirement.

**Needs.** A built sample plus `unicorn` (toolchain/device).

## phases

### V-23 — `branchloom/pipeline/categorization.py:238`

**Unverified claim.** `_XFORM_ALU_OPS` admits `AND`/`ORR`-immediate into the XFORM
scrambler chain although the reference modelled only `ADD`/`SUB`/`EOR`; the marker asks
for on-device confirmation that AND/ORR-immediate really appear, otherwise to restrict
back.

**Evidence that exists.** The broadening is argued in the comment (XFORM is not
patched, and CONST/COND2 are checked first, so it only affects labelling). The decoder
`recognition.loom_alu_imm_w` supports these forms and is unit-tested
(`checks/test_arm_words.py::test_alu_imm_add_and_eor_logical`). No test imports
`branchloom.pipeline`.

**How to close it.** Run P2 on a real flattened target and inspect the XFORM
`class_detail` for AND/ORR-immediate steps in the state-rewrite chain.

**Needs.** IDA Pro.

### V-24 — `branchloom/pipeline/destination_lookup.py:218`

**Unverified claim.** The emu backend reports one target per `BR`, not per leg, so a
COND2 leg whose single observed emu target disagrees is graded `UNVERIFIED` rather than
`MISMATCH`; to be revisited if a backend ever exposes per-leg (per-state) observation.

**Evidence that exists.** `target_sources/oracle_routes.loom_resolve_via_emu` returns a single target
(or `None` on any ambiguity), and `observed_routes.loom_verdict` is a per-PC membership test —
both read directly. No test imports `branchloom.target_sources` or `branchloom.pipeline`.

**How to close it.** A backend or trace that distinguishes which leg/state was taken,
then a real COND2 site graded both ways.

**Needs.** A per-leg-capable backend (toolchain/device).

### V-25 — `branchloom/pipeline/destination_lookup.py:219`

**Unverified claim.** The stand-alone recompute path imports `p2_classify`'s private
`loom_make_reader`/`loom_classify` — the locked Phase-2 seam — coupling to private names; the
marker says to switch to a public "classify all" helper if one appears.

**Evidence that exists.** The coupling is visible and the row-building block in
`loom_build_predecessors` is a line-for-line copy of the same loop inside `categorization.orchestrator`.
This marker is **partially stale**: a public all-dispatcher classifier now exists
(`categorization.orchestrator`, exported via `__all__ = ["run"]`), so the marker's trigger condition
is arguably met — but `execute_stage()` returns only a summary (`count`, `classes`) and discards
the `IncomingBlock` rows unless `out_path` is written, so it cannot replace the current
in-memory coupling without a refactor. The marker is not wrong, only closer to its
trigger than its wording suggests. No test covers either path.

**How to close it.** Give `p2_classify` a row-returning public helper (or have
`loom_build_predecessors` call `execute_stage(..., out_path=...)` and reload), then unit-test the
recompute path with a fake adapter — macOS-only.

**Needs.** macOS only.

### V-26 — `branchloom/pipeline/byte_commit.py:238`

**Unverified claim.** `DEFAULT_PLAN_NAME` (cwd-relative `cff_patch_plan.json`) is a
convention, not read from `AnalysisSettings`, because `AnalysisSettings` carries no artifact-path map; it
only matters for bare `execute_stage()` calls, since the CLI always passes an explicit `in_path`.

**Evidence that exists.** Confirmed by reading `settings.py` (no artifact-path member) and
`console/exchange_paths.py` (the CLI owns the default names).
`checks/test_console.py::test_artifact_defaults_resolve_and_are_distinct` covers
`console/exchange_paths.LOOM_DEFAULTS`, not this constant. No test imports `branchloom.pipeline`.

**How to close it.** Decide whether `AnalysisSettings` should own artifact paths; pin the
fallback with a unit test either way — macOS-only.

**Needs.** macOS only.

### V-27 — `branchloom/pipeline/graph_commit.py:255`

**Unverified claim.** The default cap of 256 target-table entries mirrors the
reference's `loom_enumerate_targets(max_entries)` and is overridable with
`cff.max_switch_entries`; whether 256 fits real tables is unconfirmed (enumeration also
stops at the first invalid slot).

**Evidence that exists.** `loom_max_entries` and `loom_enumerate_targets` are implemented and
readable; the slot filter is the shared `target_sources.image_tables.loom_target_valid`.
`max_switch_entries` is read raw via `settings.loom_cff.get(...)`, not through a named accessor,
so the `cff` accessor tests do not touch it. No test imports `branchloom.pipeline`.

**How to close it.** Run P6 against a real dispatcher whose target table exceeds 256
valid entries (or measure real table lengths) and confirm no truncation; pin the
override with a test.

**Needs.** IDA Pro.

## safety

### V-28 — `branchloom/integrity/clobber_scan.py:70`

**Unverified claim.** `loom_store_base` "intentionally" does not match SIMD/FP (`V == 1`)
stores, so an FP store inside a collapsed A→B gap would not be reported as an
externally observable hazard. The comment points at "`TODO(validate)` in the module
notes."

**Evidence that exists.** The masks only cover the `V == 0` integer store families
(unsigned-immediate, unscaled/pre/post, register-offset, pair). No test imports
`branchloom.integrity`, and `guides/SAFETY.md` §4 lists "non-stack store" as a hazard category
without mentioning FP stores. **The pointer is dangling:** the module docstring contains
no `TODO(validate)`, and line 89 is this module's only occurrence — the referenced note
does not exist. Reportable as-is, no environment needed.

**How to close it.** Either mark `V == 1` stores as hazards (conservative; closable
today with a unit test over hand-assembled FP store encodings on macOS) or confirm on a
real function that no FP store can sit in a collapsed gap. Fix or remove the dangling
pointer either way.

**Needs.** macOS only.

### V-29 — `branchloom/integrity/site_validation.py:88`

**Unverified claim.** TBZ/TBNZ `imm14` (bits[18:5]) target arithmetic is derived locally
in `loom_tb_target` because the locked decode contract exposes no `tbz_target` helper.

**Evidence that exists.** Still true: `recognition.py` exports `loom_is_tbz_tbnz` but no target
helper. `emission.emit_bit_jump` exists with range/alignment guards, but no unit test
round-trips it (`checks/test_arm_words.py` covers `emit_jump`/`emit_conditional_jump` only), and no test
imports `branchloom.integrity.site_validation`, so `loom_verify_branch_roundtrip` has never seen a
TBZ/TBNZ word.

**How to close it.** Unit-test `loom_verify_branch_roundtrip` with hand-assembled TBZ/TBNZ
words at positive/negative displacements and at the `imm14` boundary — macOS-only.

**Needs.** macOS only.

### V-30 — `branchloom/integrity/site_validation.py:89`

**Unverified claim.** CBZ/CBNZ `imm19` (bits[23:5]) target arithmetic is derived locally
in `loom_cb_target` for the same reason: no `cbz_target` helper in the decode contract.

**Evidence that exists.** Same as V-29: `recognition.loom_is_cbz_cbnz` exists without a target
helper, `emission.py` has no CBZ/CBNZ encoder, and no test imports
`branchloom.integrity.site_validation`.

**How to close it.** Unit-test both widths against hand-assembled CBZ/CBNZ words,
including the `imm19` boundary — macOS-only.

**Needs.** macOS only.

## cli

### V-31 — `branchloom/console/exchange_paths.py:30`

**Unverified claim.** The `p{N}_{name}` phase-module names follow `METHODOLOGY.md` §5
and the Tier-3 interface, and `loom_load_phase()` raises a clear error if a module is
missing.

**Evidence that exists.** Mostly verifiable by reading, and read: the six names match
`guides/METHODOLOGY.md` §5, the six modules exist (`p1_census` … `p6_switch`), and
`checks/test_console.py` pins the registry ↔ `PHASE_MODULE` ↔ `PHASE_IO` wiring in three
cases (`test_loom_phase_wiring_covers_exactly_the_phase_commands`,
`test_loom_the_six_phase_commands_share_one_handler`,
`test_loom_phase_io_chains_each_output_into_the_next_input`). The ImportError → `RuntimeError`
branch of `loom_load_phase` is **not** covered by any test.

**How to close it.** Add a test that forces a missing module name (e.g. by
monkeypatching `PHASE_MODULE`) and asserts the error text — macOS-only, no IDA.

**Needs.** macOS only.

### V-32 — `branchloom/console/operations/orchestrator.py:28`

**Unverified claim.** `loom_verifier_gate` audits the current (patched) database plus oracle
equivalence on the known vectors with `rerun_pass=None`; it does not itself
pristine-restore and re-diff, which the comment justifies by `run` having restored
pristine before applying and by the oracle check being image-based.

**Evidence that exists.** The flow is readable: `loom_rollback` runs before apply in a
writing aggressive run, and again if the gate is not `PASS`. Note that `guides/SAFETY.md`
§11 literally asks for "restore pristine, re-run, and require `delta_skipped ≤ 0`" —
this gate skips that step, so the safety document describes a stricter procedure than
the code performs. No test imports `branchloom.console.operations.orchestrator`'s gate (the CLI tests
cover wiring, `loom_will_write`, and `loom_phase_kwargs`).

**How to close it.** Wire the apply phase's `rerun_pass` report into the gate (the
literal §11 procedure) and validate one full aggressive run in IDA; or narrow §11's
wording. Either way the decision should be recorded in both places.

**Needs.** IDA Pro.

### V-33 — `branchloom/console/context.py:111`

**Unverified claim.** For `clean`, the segment scope is a genuine superset of the one
function being cleaned; the marker suggests passing an explicit segment `range` in the
config to narrow it.

**Evidence that exists.** `loom_scoped_ranges` narrows to the segment containing
`parent_fn`, and `image_restore.loom_restore_range` counts and rewrites only dwords that actually
drifted, so the superset costs no extra writes (it does re-read the segment).
`checks/test_console.py` covers `loom_phase_kwargs`, not `loom_scoped_ranges`; nothing can exercise it
without a live adapter.

**How to close it.** On a real database, run `clean` for one parent function and confirm
from the returned drifted-dword count that no bytes outside that function were
rewritten; or narrow the scope with a config range and compare.

**Needs.** IDA Pro.

## docs

These five are mentions of the marker inside project documentation, not assertions
about behaviour. Their "unverified claim" is the doc's own characterisation of the
gaps; all five are closable by editing the documents, and none is a code change.

### V-34 — `CHANGELOG.md:108`

**Claim as written.** "They remain not-yet-IDA-validated, with 33 `TODO(validate)`
markers."

**Evidence.** 33 is exactly the number of occurrences under `branchloom/`
(`git grep -n "TODO(validate)" HEAD -- branchloom` → 33), and the sentence's subject is
the analysis core, so it agrees with the code.

**How to close it.** Optionally qualify as "33 in `branchloom/` (38 repository-wide)".

**Needs.** macOS only.

### V-35 — `IMPLEMENTATION_STATUS.md:43`

**Claim as written.** "**…not yet run against IDA.** 33 `TODO(validate)` markers flag
every place the code assumes beyond the reference."

**Evidence.** The count matches the package. "Every place" is not something a marker
count can establish, and at least one assumption is documented without a working
marker: the SIMD/FP store exclusion in `integrity/clobber_scan.py` points at a marker that does
not exist (V-28), and Model-2's promised `assumptions_todos` mechanism does not exist
either (V-07). The claim is directionally right, slightly overstated in scope.

**How to close it.** Reword to "33 markers record the assumptions made beyond the
reference" and fix the two dangling references.

**Needs.** macOS only.

### V-36 — `IMPLEMENTATION_STATUS.md:45`

**Claim as written.** The enumeration command `grep -rn "TODO(validate)" branchloom`.

**Evidence.** Correct text, imprecise command: on a clean checkout it prints 33, but in
a working tree containing `__pycache__` it prints **45** lines here (33 text + 12
`Binary file … matches`, since compiled copies of the same sources contain the string).
`grep -rnI` (or a `git grep`) reproduces 33 deterministically.

**How to close it.** Add `-I`, or quote the git-scoped command.

**Needs.** macOS only.

### V-37 — `IMPLEMENTATION_STATUS.md:58`

**Claim as written.** "`dispatch_shapes/comparison_routes.py` | 🟡 experimental | Model-2 —
heuristic, most `TODO(validate)`s live here."

**Evidence.** This **overstates the concentration and disagrees with the code**:
`comparison_routes.py` holds 4 of the 33, the same as `dispatch_shapes/register_routes.py` (4) and
`equivalence/machine_oracle.py` (4). By area, `patterns` holds 8 across two modules and `verify`
holds 7. "Most" is not supported.

**How to close it.** Reword to "4 of the 33 markers; the largest cluster is
`dispatch_shapes/` (8)".

**Needs.** macOS only.

### V-38 — `README.md:56`

**Claim as written.** "See `IMPLEMENTATION_STATUS.md` for the validation hotspots and
the 33 `TODO(validate)` markers."

**Evidence.** 33 is the package count, but the sentence sits in a repository-status
bullet with no scope qualifier. A repository-wide grep returns 38: 33 in `branchloom/`
plus five in the root markdown, three of those in `IMPLEMENTATION_STATUS.md` — one of
which, line 41, is the quoted grep command itself. This **understates the
repository-wide number**.

**How to close it.** Say "33 markers in `branchloom/`".

**Needs.** macOS only.

---

# Consistency with the other project documents

Checked by reading the three documents and the code they describe. The check used the
same commands as the enumeration plus an import sweep of the package.

| document claim | what the code shows | verdict |
|---|---|---|
| `IMPLEMENTATION_STATUS.md` — "every module imports successfully except `database/bridge.py`" | 45 modules imported; the only failure is `branchloom.database.bridge` (`ModuleNotFoundError: No module named 'idaapi'`) | **agrees** (verified) |
| `IMPLEMENTATION_STATUS.md` / `README.md` / `CHANGELOG.md` — "84 tests, all passing" | `python3 checks/orchestrator.py` → `total=84 pass=84 fail=0`; `pytest` is not installed in either interpreter available here, so `python3 -m pytest` cannot be run in this environment | **agrees via the bundled runner only**; the pytest path is unverified here |
| `IMPLEMENTATION_STATUS.md:58` — "most `TODO(validate)`s live here" (Model-2) | 4 of 33, tied with two other modules | **overstates** (see V-37) |
| `README.md:56` / `CHANGELOG.md:108` — "the 33 `TODO(validate)` markers" | 33 in `branchloom/`, 38 repository-wide | **understates repo-wide** in `README.md` (V-38); `CHANGELOG.md` is scoped to the analysis core and agrees (V-34) |
| `IMPLEMENTATION_STATUS.md:45` — `grep -rn "TODO(validate)" branchloom` | 45 lines in a tree with `__pycache__`, 33 with `-I` | **imprecise command** (see V-36) |
| `IMPLEMENTATION_STATUS.md` — "every module below … faithful ports of the reference toolchain, not yet run against IDA" | consistent with the code: the only IDA importer cannot be imported off-device and no recorded IDA run exists in the repo | **agrees** |
| `guides/SAFETY.md` §11 — "restore pristine, re-run, and require `delta_skipped ≤ 0` … byte-identical before/after" | `console/operations/orchestrator.loom_verifier_gate` calls the regression harness with `rerun_pass=None` and the oracle reads its own (unpatched) image | **overstates** what the code enforces (see V-32, V-18) |
| `guides/SAFETY.md` §8 — "Phase 6 uses tolerant `add_cref(fl_JN)` jump xrefs … `del_cref` revert" | matches `patterns`-side call sites and `database/bridge.loom_add_jump_xref` / `loom_del_jump_xref` | **agrees**; only the IDA rendering is unverified (V-01) |
| `guides/SAFETY.md` §9 — target filter incl. `idx in [0, 0xFFFF]` | implemented: `image_tables.loom_resolve_state` bounds `idx`, `integrity/site_validation.loom_self_check_targets` checks alignment/BADADDR/exec | **agrees** |

## Stale or dangling markers (reported, not removed)

1. **`branchloom/integrity/clobber_scan.py:70` — dangling pointer.** It tells the reader to see
   "`TODO(validate)` in the module notes"; the module docstring contains no marker and
   this is the module's only occurrence.
2. **`branchloom/dispatch_shapes/comparison_routes.py:31` — dangling pointer.** It references
   `assumptions_todos`; the identifier appears four times in prose and is never defined
   anywhere in the package.
3. **`branchloom/pipeline/destination_lookup.py:219` — trigger condition arguably met.** Its stated
   exit ("if p2_classify grows a public 'classify all' helper, switch to it") now exists
   as `categorization.orchestrator`, but that helper returns a summary and drops the rows, so the
   private-name coupling cannot be removed without a refactor.
4. **`branchloom/console/exchange_paths.py:30` — partly self-verifying.** The module-name half of
   the marker is confirmed by reading `METHODOLOGY.md` §5 and the existing modules and is
   pinned by three CLI tests; only the untested error branch keeps it open.

No marker was deleted, weakened, or moved.

## Re-checking this document

```bash
python3 utilities/inventory_validation.py --expect 38
```

The script prints every `path:line: text` record, the file count, the total, and the
per-area counts, and exits non-zero if the total is not 38. It is read-only, uses the
standard library only, lives outside the installable package (`pyproject.toml` packages
only `branchloom*`), and prints the three paths it currently excludes because they
quote the marker by design: `guides/VALIDATION_STATUS.md`, `guides/VERIFICATION.md`
and `utilities/inventory_validation.py`.
