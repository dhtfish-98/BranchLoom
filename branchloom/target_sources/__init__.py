"""
branchloom.target_sources — resolution sources for a dispatcher's concrete target.

Three independent, composable oracles turn a classified (predecessor, dispatcher)
into a branch target and a confidence verdict:

  * :mod:`static_table` — the primary, pure-static ``state -> idx -> target`` two
    level table walk plus target-validity (ported from the Part3 ``cff_resolve``
    reference). Table reads optionally come from a relocation-applied image so a
    raw, un-relocated ``.so`` GOT/table never poisons the result.
  * :mod:`trace_gate` — a cross-check gate: load one-or-more BR-target traces,
    union the observed targets per branch PC, and grade a static target as
    ``OK`` / ``UNVERIFIED`` / ``MISMATCH``. Also exposes the ``loom_single_target``
    patchability test.
  * :mod:`emu_resolve` — a thin, optional emulation cross-check driven through the
    behavioural :class:`~branchloom.equivalence.contracts.BehaviorOracle`.

None of these import IDA: the adapter is always handed in at call time, exactly
like :mod:`branchloom.integrity.image_restore`.
"""
from .image_tables import loom_resolve_state as loom_resolve_state, loom_target_valid as loom_target_valid
from .observed_routes import loom_load_traces as loom_load_traces, loom_single_target as loom_single_target, loom_verdict as loom_verdict
from .oracle_routes import loom_resolve_via_emu as loom_resolve_via_emu
__all__ = ['loom_resolve_state', 'loom_target_valid', 'loom_load_traces', 'loom_single_target', 'loom_verdict', 'loom_resolve_via_emu']
