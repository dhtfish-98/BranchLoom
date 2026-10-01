# METHODOLOGY

The analysis design inherited from unflatten64 for flattened control flow and
VM dispatch. The patterns below describe intended behaviour, not a validated
end-to-end deobfuscation result. Target settings live in configs. The IDA phase
layer remains experimental; see [implementation status](../IMPLEMENTATION_STATUS.md)
and [safety limits](SAFETY.md).

## 1. The obfuscation models

### Family-A — two-level indexed-table CFF

State is an `int32` kept in a stack slot. The **dispatcher** is an invariant triplet:

```
LDURSW/LDRSW/LDR  Xs, [X29|SP, #K]        ; load state
LDRSW             Xi, [X_idxtbl, Xs, LSL #2]   ; idx_tbl : int32[state] -> handler idx
LDR               Xt, [X_tgttbl, Xi, LSL #3]   ; tgt_tbl : uint64[idx] -> handler EA
BR                Xt
```

The two field cross-checks that gate a *true* dispatcher (and reject coincidental
byte sequences) are `LDRSW.Rt == LDR.Rm` and `LDR.Rt == BR.Rn`. Each **predecessor**
is the tail of a handler that computes the next state, writes it to the same slot,
and falls through (or `B`s) to the dispatcher.

### Model-1 — single-level BR-through-table

```
CSEL/CSET/CSINC/CSINV/CSNEG/CINC/CINV/CNEG  Wi, ...   ; 2-way index select
[ LSL/UBFIZ Wi, #k ]                                  ; optional scale
LDR   Xt, [Xbase, Wi, UXTW/SXTW #k]                   ; dispatch table
BR    Xt
```

plus an alternate `LDARB + SBFX #0,#1 + AND #K` flag-byte shape that rewrites to
`TBZ/TBNZ`.

### Model-2 — OLLVM CMP-tree state machine

Loop-head + prologue-magic + a binary-search-tree of `CMP/B.loom_cond` mapping state
magics to handlers, with a scrambler `state = (state ^ K_XOR) + K_ADD` in
shared / per-handler / interleaved variants. The exit `RET` handler is never touched.

## 2. Predecessor taxonomy

| class | shape | successors |
|-------|-------|-----------|
| `CONST` | `MOVZ/MOVN Wt,#imm ; STR Wt,[slot]` | 1 (one static state) |
| `COND2` | `MOVZ ; MOVZ ; CSEL Wc,Wa,Wb,cond ; [MOV] ; STR` | 2 (flag-selected) |
| `XFORM` | `LDR Wt,[slot] ; EOR Wt,#K ; ADD/SUB Wt,#C ; STR` | self-scramble (not patched) |
| `OPAQUE` | anything else | unknown (not patched) |

Only `CONST` and `COND2` carry statically-known next-state(s), so only they are ever
resolved and patched. The single-level select-op families (`CSET/CSETM/CINC/…`) fold
into `COND2`.

## 3. Constant resolution (never guesses)

`arm_words/value_chains` propagates constants through `MOV/MOVZ/MOVN`, `MOVK` 16-bit slice
merges, `WZR/XZR`, register copies, `ORR/EOR` reg|imm and reg|reg, the carry-safe
`ADD+EOR` idiom, and multi-pass `ADD/SUB #imm` — bounded to a small back-window. If a
value can't be resolved to a concrete constant, the site becomes `OPAQUE`, not a
guess.

## 4. Resolution sources (complementary)

Phase 3 can resolve a state's target three ways; they cross-check each other:

- **static-table** — `idx = int32[idx_tbl + state*4]`, `target = uint64[tgt_tbl + idx*8]`.
  ⚠️ Table entries in a raw `.so` are **not relocated**; read them from a
  relocation-applied image (`config.reloc_image`) or a live dump.
- **trace single-target gate** — run the function under an instrumented executor,
  record `{pc: {target: count}}`, and admit a `BR` **only if it resolves to exactly
  one target across every observed input**. This is the core dynamic safety invariant.
- **emulation** — step the scrambler→dispatcher under the verifier backend, read the
  resolved index, optionally BFS the state machine to grow the edge map.

A resolution is `OK` when static and observed agree, `UNVERIFIED` when static-only
(never observed), `MISMATCH` (dropped) when they disagree, `INVALID` when the target
fails the validity filter.

## 5. The six phases (each emits one JSON)

| phase | reads | writes | effect |
|-------|-------|--------|--------|
| **P1 census** | config | `cff_dispatchers.json` | scan exec segments for the dispatcher signature; resolve tables, state slot, parent fn, predecessors. read-only |
| **P2 classify** | dispatchers | `cff_predecessors.json` | bucket each predecessor CONST/COND2/XFORM/OPAQUE |
| **P3 resolve** | predecessors + trace/emu | `cff_resolutions.json` | state→idx→target with OK/UNVERIFIED/MISMATCH/INVALID verdicts |
| **P4 plan** | resolutions | `cff_patch_plan.json` | synthesize same-size byte patches (read-only, no DB writes) |
| **P5 apply** | patch plan | mutated IDB | dry-run default; strict orig-verify; restore helpers exist but are unvalidated in live IDA |
| **P6 switch** | dispatchers (un-patched) | `cff_switch_info_log.json` | tolerant `BR→target` graph xrefs, zero byte changes |

Patch shapes:

- **CONST** → NOP the dead plumbing, rewrite `BR` to `B <target>`.
- **COND2** → NOP CSEL/STR/state-load/idx-load; `B.loom_cond <then>` in the freed `LDR`
  slot + `B <else>` in the `BR` slot (NZCV preserved), gated by `loom_a_path_hazard`.

## 6. Verification

The design calls for structural regression checks and behavioural comparison on
known I/O vectors. The current `run` gate passes `rerun_pass=None` to the regression
harness, and the Unicorn verifier loads its configured image rather than the
patched IDA database. These paths do not establish before/after equivalence of
the actual rewrite. See [SAFETY.md](SAFETY.md) §11 for the remaining work.

## 7. Function-boundary artifacts

After a `BR→B` rewrite Hex-Rays often shows the orphaned handler body as `JUMPOUT`.
This can result from function-boundary metadata, but it is not evidence that a
rewrite is correct. Boundary repair (`repair/boundary.py`) and EH repair are design
items only: those modules have not been implemented.
