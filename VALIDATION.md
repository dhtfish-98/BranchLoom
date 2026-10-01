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
