# Rewrite verification

The baseline is the exact local source commit recorded in ORIGIN.md.

- 88 baseline regression tests passed before the rewrite; all 88 renamed tests plus four missing/null-field and invalid-numeric regressions pass (92 total).
- The standalone runner also passes all 92 tests without requiring pytest on Python 3.12 and 3.14.
- The instruction recognizer was compared on 282,282 instruction/function pairs;
  register-write recognition adds 1,500 comparisons.
- All 16,384 architectural logical-immediate input combinations were compared.
- Branch emission adds 21,000 boundary/random comparisons; word serialization adds 7,000.
- 1,000 mapped-image reads and package constants/imports were compared.
- Five record codecs were separately compared with the original on 2,500 inputs,
  including omitted/default/null fields, invalid inputs, exact JSON key order and exception behavior.
- The renamed synthetic C target, original C target and new Python reference agree
  on 1,500 inputs, including empty and longer buffers, at O0 and O2.
- All original retained executable functions are covered by a structural audit
  after independently undoing identifier changes. Replaced wire codecs and emitters
  are covered by regression and differential tests rather than that structural check.
- Undefined-name checks and Python 3.9 grammar checks pass; wheel/source packages
  and an installed consumer are checked separately.

The IDA import seam is tested with inert module names and synthetic adapters.
No live IDB run is claimed. The inherited reference-verifier integration and
restore/rerun limitations remain in the implementation status and guides/.
Original artifact/configuration schemas and write gates remain unchanged.

The 2026-10-01 recheck fixed the omitted `class_detail` default to preserve the
original empty object. Explicit null remains null, and defaults are independent
between records. Public exports and current documentation references were also checked.

412 numeric edge cases compare return values and exception behavior with the
original emitters, word codec and logical-field decoder. Noninteger branch/word
inputs retain the original bitwise TypeError instead of being silently skipped
or producing a different exception. Source distributions include tests, guides,
utilities, provenance and the synthetic sample.

## 0.2.1 local checks (2026-10-04 UTC)

The optional Unicorn verifier now requires its configured return sentinel before
it reports output. Two new synthetic AArch64 integration tests cover a four-byte
B-to-self instruction exhausting a 16-instruction budget, a four-byte RET reaching
the sentinel, and a cached emulator rerun after a successful return. With Python
3.14.6 and Unicorn 2.1.4, all 94 pytest cases pass; the dependency-free runner
passes its 92 cases. The B-to-self CLI control returns `ok:false` with exit code 1;
the RET control returns `ok:true` with exit code 0. The validation-marker inventory
remains 38, and the 0.2.1 wheel and source distribution build locally.

These checks use only self-created code bytes and do not establish real-target,
patched-IDB, live-IDA, device or CVP outcomes. Remote CI and release assets need
their own exact-commit and byte-identity evidence.
