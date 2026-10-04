"""
branchloom — a target-agnostic ARM64 (AArch64) control-flow-flattening /
VM-dispatch devirtualizer for IDA Pro.

The package is layered so the reusable, IDA-free parts can be unit-tested on
their own:

    arm_words/        pure-Python AArch64 recognition/emission/bitmask primitives (no IDA)
    records/shapes.py    dataclasses + JSON (de)serializers for every inter-phase artifact
    settings.py   the single home of every target-specific value
    database/        thin IDA adapter (the only place idaapi/ida_* is imported)
    pipeline/     the 6-phase pipeline (census -> classify -> resolve -> plan ->
                apply -> switch-info)
    dispatch_shapes/   per-family dispatcher matchers (two-level CFF, single-level
                BR-through-table, OLLVM CMP-tree)
    target_sources/    resolution sources (static table, trace single-target gate, emu)
    equivalence/     the pluggable behavioural verifier (reference: Unicorn)
    integrity/     hazard scan, per-site self-check, pristine-first restore

Design rule: the code ships ZERO target addresses, ZERO binaries, ZERO known
I/O vectors. Everything target-specific lives in a user-supplied YAML config.
"""
__version__ = '0.2.1'

__all__ = [export_binding for export_binding in [] if export_binding in globals()]
