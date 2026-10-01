"""
branchloom.target_sources.oracle_routes — thin, optional emulation cross-check.

The static table walk (:mod:`static_table`) and the trace gate
(:mod:`trace_gate`) are the load-bearing resolvers. This module adds a *thin*
third opinion: drive the behavioural :class:`~branchloom.equivalence.contracts.BehaviorOracle`
and read back the concrete target a dispatcher's ``BR`` actually takes.

The reference ``trace_br_targets.py`` obtained this by installing a ``UC_HOOK_CODE``
hook that logged every ``BR Xn`` target while emulating. The published tool keeps
the Verifier a black box (``evaluate_io`` + ``known_vectors``), so branch observation
is an *optional capability*: a backend that can report per-branch targets exposes
one of the duck-typed methods below

    verifier.observe_branches(entry, input_bytes) -> {br_pc: {target: count}}
    verifier.branch_targets(entry, input_bytes)   -> {br_pc: iterable[target]}

(the reference Unicorn backend is the natural home for it). When the configured
verifier offers neither, :func:`loom_resolve_via_emu` returns ``None`` — the emu
cross-check is simply unavailable, never a guess.

IDA-free: the ``adapter`` is handed in only to validate the resolved target.
"""
from __future__ import annotations as loom_annotations
from typing import Optional as loom_Optional, Set as loom_Set
from .. import records as LOOM_M
from .image_tables import loom_target_valid as loom_target_valid
__all__ = ['loom_resolve_via_emu']
LOOM__OBSERVE_METHODS = ('observe_branches', 'branch_targets')

def loom_hits_for(loom_sites, loom_br_ea: int) -> loom_Set[int]:
    """Extract the observed target set for ``br_ea`` from an observation dict.

    Tolerates int or ``0x``-hex-string PC keys, and per-PC values that are either
    a ``{target: count}`` mapping (reference shape) or a bare iterable of targets.
    """
    if not isinstance(loom_sites, dict):
        return set()
    loom_val = loom_sites.get(loom_br_ea)
    if loom_val is None:
        loom_val = loom_sites.get(LOOM_M.loom_hx_value(loom_br_ea))
    if loom_val is None:
        return set()
    loom_keys = loom_val.keys() if isinstance(loom_val, dict) else loom_val
    output: loom_Set[int] = set()
    for loom_t_value in loom_keys:
        output.add(int(loom_t_value, 16) if isinstance(loom_t_value, str) else int(loom_t_value))
    return output

def loom_resolve_via_emu(loom_verifier, bridge, loom_dispatcher_value) -> loom_Optional[int]:
    """Resolve ``dispatcher``'s single branch target by emulation, or ``None``.

    Returns a concrete, validated target address only when the verifier can
    report branch targets AND every driven run agrees on exactly one executable
    target for ``loom_dispatcher_value.loom_br_ea``. Any ambiguity (multi-target, missing
    capability, no entry, non-executable result) yields ``None`` so callers fall
    back to the static/trace resolvers rather than trusting a guess.
    """
    loom_br_ea = getattr(loom_dispatcher_value, 'loom_br_ea', None)
    if loom_br_ea is None:
        return None
    loom_observe = None
    for label in LOOM__OBSERVE_METHODS:
        loom_cand = getattr(loom_verifier, label, None)
        if callable(loom_cand):
            loom_observe = loom_cand
            break
    if loom_observe is None:
        return None
    try:
        loom_entry_value = loom_verifier.loom_entry_value()
    except Exception:
        loom_entry_value = None
    if loom_entry_value is None:
        return None
    try:
        loom_vectors = loom_verifier.loom_known_vectors()
    except Exception:
        loom_vectors = []
    loom_inputs = [loom_inp for loom_inp, loom_out in loom_vectors] or [b'']
    loom_seen: loom_Set[int] = set()
    for loom_inp in loom_inputs:
        try:
            loom_sites = loom_observe(loom_entry_value, loom_inp)
        except Exception:
            continue
        loom_seen |= loom_hits_for(loom_sites, loom_br_ea)
        if len(loom_seen) > 1:
            return None
    if len(loom_seen) != 1:
        return None
    destination = next(iter(loom_seen))
    return destination if loom_target_valid(bridge, destination) else None

# TODO(validate): resolve_via_emu drives from the verifier's configured
