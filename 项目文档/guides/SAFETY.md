# Safety requirements and validation limits

These requirements come from DumpA1n's unflatten64 safety model. They describe the
intended constraints on analysis and rewriting, not a proof that this implementation
enforces them. Rewriting control flow can silently change a binary's behaviour.
The current IDA pipeline has not been validated end to end; known differences from
the requirements are recorded in [VALIDATION_STATUS.md](VALIDATION_STATUS.md).

## 1. Only patch provably single- or binary-valued predecessors

A dispatcher's `BR Xt` is patched to a direct branch **only** when the state that
reaches it is:

- **`CONST`** — one static next-state (`MOVZ/MOVN Wt,#imm ; STR Wt,[slot]`), or
- **`COND2`** — a two-way select of two constants
  (`MOVZ ; MOVZ ; CSEL Wc,Wa,Wb,cond ; STR`).

`XFORM` (the obfuscator's self-scrambler, `state = (state ^ K) + C`), `OPAQUE`
(anything else), and any `BR` the verifier ever observed take **more than one**
target are **genuine one-to-many dispatch** and are never byte-patched — they get a
read-only graph xref in Phase 6 and nothing more.

## 2. Never rewrite the dispatcher `BR` itself as a guess

The dispatcher `BR Xt` is one-to-many by construction. It is only ever collapsed to
a direct branch when Phase 3 has *resolved* the single/binary target set and Phase 4
proved the encode is in range. A residual `BR` (e.g. a real VM interpreter loop) is
left exactly as-is.

## 3. Never touch cross-function shared helpers

Handlers frequently `BL` into shared primitives. A reverse walk that hits a `BL`
must treat all AAPCS64 caller-saved registers (`X0–X18`, `X30`) as clobbered and
**stop**; it must never follow into or patch the shared callee.

## 4. `loom_a_path_hazard` — never bypass an observable side effect

A two-instruction `COND2` rewrite lets one path *skip* the instructions between the
freed `LDR` slot and the `BR`. Before emitting it, scan that gap. If any skipped
instruction is externally observable — a call/branch, a barrier (`DMB/DSB/ISB`), a
system/cache/TLB op (`MSR/MRS/SYS/IC/DC/AT/TLBI`), an exclusive or acquire/release
(`LDXR/STXR/LDAR/STLR/…`), an exception (`SVC/BRK/HLT/…`), or a **non-stack store**
(base not `SP`/`WSP`/`X29`) — **skip the site** with a recorded reason. Only a
stack-local store may be safely skipped.

## 5. `COND2` must preserve the flag producer

The emitted `B.loom_cond` reuses the exact `NZCV` the original `CMP` set, so no
flag-setting instruction between the compare and the branch is ever touched.

## 6. Back-edge rewrite requires a literal `B scrambler_start`

A back-edge `STUR` is rewritten only when the instruction immediately after it is
*literally* `B scrambler_start`. A fall-through `STUR` that writes state is **never**
rewritten. (This is the exact rule whose absence once deleted a live state write.)

## 7. Never NOP load-bearing or shared instructions

Only provably-dead state-machine plumbing is NOP'd (the `MOVZ`/`CSEL` producer, the
`STR`-to-slot, the state load, the idx/tgt table loads). Intervening `ADRP/ADD`
address setups and any store other code may read are deliberately left intact.

## 8. Never install a partial `switch_info_t`

Hex-Rays validates a switch descriptor and **aborts the entire decompile** on
incomplete data. Phase 6 uses tolerant `add_cref(fl_JN)` jump xrefs instead, and
logs each one for a clean `del_cref` revert. Stale descriptors are scrubbed with
`del_switch_info`.

## 9. Target validity filter, everywhere a target is trusted

A target is accepted only if it is nonzero, `!= BADADDR`, 4-byte aligned, inside an
executable segment, with `idx` in `[0, 0xFFFF]`. Branch encoders range-check the
displacement and return `None` (→ skip) rather than emit a wrong branch.

## 10. Pristine-first, strict-orig-verify, idempotent, batch-rollback

- **Pristine-first:** every pass first restores its byte range from the on-disk
  original, so runs are idempotent and start clean. The on-disk image is the single
  source of truth.
- **Strict orig verify:** apply re-reads current bytes and refuses to write unless
  they equal the recorded originals. If the DB drifted, regenerate the plan. Never
  blind-write. `strict_orig_check` is on by default; disabling it is documented as
  dangerous.
- **Idempotent:** a patch whose current bytes already equal the target is skipped.
- **Batch scope + rollback:** apply/revert are per parent function. `revert` reads
  pristine bytes straight from the on-disk image, independent of any patch log.

## 11. Verifier gate — required before/after comparison

The design requires the following after each apply batch: restore pristine, re-run,
and require `delta_skipped ≤ 0` (coverage never regresses), no unexpected/missing skips, sample
sites disassembling to the expected mnemonic+target, and all per-site self-checks
passing. **Independently**, re-run the known I/O vectors through the verifier
(`evaluate_io`) and require **byte-identical** output. Any mismatch — self-check,
regression, or oracle — means **roll back to pristine and investigate**. Do not ship
the batch.

**Current implementation gap:** the `run` command invokes the regression harness
with `rerun_pass=None`, so that gate does not perform the restore-and-rerun
comparison. The reference verifier reads its configured image; it does not
automatically execute the patched IDA bytes. A passing known-vector check therefore
does not establish before/after equivalence. These gaps remain open (V-18 and V-32
in [VALIDATION_STATUS.md](VALIDATION_STATUS.md)).

## 12. Mode gating

`switch` is the default and is intended to leave instruction bytes unchanged. It
does modify IDA metadata, and its effect on analysis and decompilation is unvalidated.
`linear`/`full` actually rewrite bytes and are refused by the config loader unless a
verifier backend and known I/O vectors are configured. That config requirement is
unit-tested, but does not establish the correctness of the runtime verifier or of
the resulting patches.
