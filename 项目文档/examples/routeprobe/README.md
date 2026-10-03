# routeprobe — a neutral CFF test target

A **synthetic, MIT-licensed** AArch64 sample included with the upstream unflatten64
code, for testing and demonstrating branchloom. It contains no competition artifact. It is a
tiny deterministic keyed byte-mixing routine written as a control-flow-**flattened**
state machine with a genuine **two-level dispatch table**, so it reproduces the
"Family-A" shape a devirtualizer targets — without needing OLLVM.

## The state machine

```
INIT --[CONST]--> LOOP
LOOP --[COND2]--> BODY   (if i < len)
                  DONE   (else)
BODY --[CONST]--> LOOP
DONE : return acc & 0xff
```

State lives in a stack slot; each handler tail re-enters the dispatcher via
`goto *tgt_tbl[idx_tbl[state]]`.

## Build

```bash
ANDROID_NDK_HOME=/path/to/ndk ./compile_probe.sh      # -> librouteprobe.so (git-ignored)
```

`compile_probe.loom_sh` uses the NDK's `aarch64-linux-android<API>-clang` at `-O2`. The `.so` is a
build artifact and is **never** committed (`.gitignore` blocks `*.so`).

## What the compiler emits (verified, clang 21 / NDK r29, `-O2`)

clang tail-duplicates the dispatch into **four** sites, each exactly the two-level
dispatcher branchloom detects:

```
ldrsw x10, [sp, #0xc]          ; load state
ldrsw x11, [x9, x10, lsl #2]   ; idx = idx_tbl[state]      (int32 table, .rodata)
ldr   x14, [x10, x11, lsl #3]  ; tgt = tgt_tbl[idx]        (uint64 target table)
br    x14                      ; dispatch
```

Field cross-checks hold (`LDRSW.Rt == LDR.Rm`, `LDR.Rt == BR.Rn`), and the handler
tails give `CONST` (`mov #imm ; str [slot]`) and conditional-select predecessors —
so the sample is intended to exercise the P1 detector and CONST/COND2
classification. The compiler output check is not an end-to-end IDA validation;
that run has not been recorded in this repository.

Note: at `-O2` this computed-`goto` form keeps the **first-level** table (`idx_tbl`)
in `.rodata` but materialises the **second-level** `tgt_tbl` on the stack. That
provides a case for testing detection and trace/emulation resolution. For a *static*
second-level table in `.content.loom_rel.ro` (the textbook OLLVM layout), build with an
obfuscator's flattening pass (see the note at the bottom of `compile_probe.loom_sh`).

## Known-answer vector (for the verifier)

`probe_reference.py` is a bit-identical Python port, so you can compute
`verifier.known_vectors` without executing the aarch64 binary:

```
in  : 756e666c61743634   ("unflat64")
out : 2f3b4a4b5751969f
ret : 0xfc
```

```bash
python probe_reference.py                 # default vector above
python probe_reference.py 00112233        # any hex input
```

## Point branchloom at it

Load `librouteprobe.so` in IDA, then use `branchloom.yml` here as a starting config
(fill in `verifier.entry` with the address of `routeprobe` once loaded).
