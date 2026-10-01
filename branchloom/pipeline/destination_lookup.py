"""
branchloom.pipeline.destination_lookup — Phase 3: resolve each dispatcher's state -> target.

For every ``CONST`` / ``COND2`` predecessor produced by Phase 2 the concrete
next-state(s) are known, so the two-level dispatch can be walked statically::

    idx    = sign32( read32(idx_tbl_ea + (state << idx_scale)) )
    target =         read64(tgt_tbl_ea + (idx   *  entry_size))

The per-state walk (plus target validity) lives in
:func:`branchloom.target_sources.image_tables.loom_resolve_state` — the load-bearing resolver.
Every resolved target is then *graded* against an out-of-band oracle so a static
guess is never trusted blindly. Which oracle grades the verdict is selected by
``--source`` (``kw['source']``):

  ============  ================================================================
  source        verdict authority
  ============  ================================================================
  ``trace``     :func:`branchloom.target_sources.observed_routes.loom_verdict` — the observed
                (default)   ``BR`` targets from one or more traces. OK when the
                static target is in the observed set, MISMATCH when the branch was
                observed but never taking it, UNVERIFIED when the branch was never
                traced. This reproduces the reference ``cff_resolve.py`` behaviour;
                with no traces configured every resolution is UNVERIFIED.
  ``emu``       :func:`branchloom.target_sources.oracle_routes.loom_resolve_via_emu` — drive the
                configured behavioural verifier and read back the single target the
                ``BR`` actually takes.
  ``static``    no oracle — the static target is emitted as UNVERIFIED (cross-check
                deliberately skipped).
  ============  ================================================================

A state whose table walk yields no valid target is graded ``INVALID`` regardless
of source. Phase 4 drops both ``INVALID`` and ``MISMATCH``.

Faithful port of ``cff_resolve.py::run`` from
the private reference toolchain — re-expressed
against the locked, target-agnostic seams of this package:

  * the ``state * 4`` (index) / ``idx * 8`` (target) scales are read from the
    AnalysisSettings (``cff.idx_table_scale`` / ``cff.entry_size``), never hard-coded;
  * un-relocated table reads are served from an optional reloc image registered
    from ``settings.loom_reloc_image`` (``image_tables.loom_open_reloc``);
  * the two ``br_targets_*.json`` cross-check files become the config-driven
    :mod:`trace_gate`, and an optional emulation cross-check is added.
"""
from __future__ import annotations as loom_annotations
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from .. import records as LOOM_M
from ..arm_words import recognition as LOOM_D
from ..dispatch_shapes import indexed_routes as indexed_routes
from ..target_sources import oracle_routes as oracle_routes
from ..target_sources import image_tables as image_tables
from ..target_sources import observed_routes as observed_routes
LOOM__VALID_SOURCES = ('static', 'trace', 'emu')

class HubProjection:
    """The only field :func:`oracle_routes.loom_resolve_via_emu` reads is ``br_ea``."""
    __slots__ = ('loom_br_ea',)

    def __init__(record, loom_br_ea: int) -> None:
        record.loom_br_ea = loom_br_ea

def loom_reloc_base(settings) -> int:
    """Module load base under which ``settings.loom_reloc_image`` was captured (0 == file==EA).

    Target-specific, so it comes from config (``cff.reloc_base``) and is never
    baked in. Accepts an ``int`` or a ``0x``-hex / decimal string.
    """
    loom_v = (settings.loom_cff or {}).get('reloc_base', 0)
    if isinstance(loom_v, str):
        loom_v = loom_v.strip()
        return int(loom_v, 16) if loom_v.lower().startswith('0x') else int(loom_v or '0')
    return int(loom_v or 0)

def loom_grade(loom_source: str, loom_via_class: str, destination: loom_Optional[int], loom_br_pc: int, loom_traces: loom_Dict[int, set], loom_emu_target: loom_Optional[int]) -> str:
    """Grade a statically-resolved ``target`` to one of :data:`records.LOOM_VERDICTS`."""
    if destination is None:
        return 'INVALID'
    if loom_source == 'trace':
        return observed_routes.loom_verdict(destination, loom_br_pc, loom_traces)
    if loom_source == 'emu':
        if loom_emu_target is None:
            return 'UNVERIFIED'
        if loom_emu_target == destination:
            return 'OK'
        return 'MISMATCH' if loom_via_class == 'CONST' else 'UNVERIFIED'
    return 'UNVERIFIED'

def loom_build_predecessors(bridge, settings, loom_in_path: loom_Optional[str]) -> loom_List[LOOM_M.IncomingBlock]:
    """Load the Phase-2 artifact, or recompute the predecessors on the fly.

    Mirrors the way :mod:`p2_classify` recomputes the census from
    :func:`cff_twolevel.find_dispatchers` when handed no input path, so Phase 3 is
    runnable stand-alone. The recompute reuses the *locked* Phase-2 classifier
    rather than reimplementing it.
    """
    if loom_in_path:
        return LOOM_M.read_incoming(loom_in_path)
    from . import categorization as categorization
    loom_dispatchers = indexed_routes.loom_find_dispatchers(bridge, settings)
    loom_read_value = categorization.loom_make_reader(bridge)
    items: loom_List[LOOM_M.IncomingBlock] = []
    for loom_disp in loom_dispatchers:
        record_type, loom_detail, loom_str_ea, loom_pred_start_ea, loom_reason = categorization.loom_classify(loom_read_value, loom_disp)
        items.append(LOOM_M.IncomingBlock(loom_dispatcher_br_ea=loom_disp.loom_br_ea, loom_parent_fn_ea=loom_disp.loom_parent_fn_ea, loom_parent_fn_name=loom_disp.loom_parent_fn_name, loom_idx_tbl_ea=loom_disp.loom_idx_tbl_ea, loom_tgt_tbl_ea=loom_disp.loom_tgt_tbl_ea, loom_state_slot=loom_disp.loom_state_slot, loom_state_base=loom_disp.loom_state_base, record_type=record_type, loom_class_detail=loom_detail, loom_str_ea=loom_str_ea, loom_pred_start_ea=loom_pred_start_ea, loom_reason=loom_reason))
    return items

def loom_resolve_all(bridge, settings, loom_preds: loom_List[LOOM_M.IncomingBlock], loom_source: str='trace') -> loom_Tuple[loom_List[LOOM_M.DestinationSet], loom_Dict[str, int]]:
    """Resolve every CONST/COND2 predecessor to ``DestinationSet`` rows + stats.

    Registers the (optional) reloc image for the duration of the walk and always
    clears it afterwards. ``source`` selects the verdict oracle (see module docs).
    """
    loom_source = (loom_source or 'trace').strip().lower()
    if loom_source not in LOOM__VALID_SOURCES:
        raise ValueError('source must be one of %r, got %r' % (LOOM__VALID_SOURCES, loom_source))
    loom_entry_size = settings.loom_entry_size
    loom_idx_scale = settings.loom_idx_table_scale
    loom_reloc = image_tables.loom_open_reloc(settings, loom_reloc_base(settings))
    loom_use_reloc = loom_reloc is not None
    loom_traces: loom_Dict[int, set] = {}
    if loom_source == 'trace':
        try:
            loom_traces = observed_routes.loom_load_traces(settings)
        except Exception:
            loom_traces = {}
    loom_verifier = None
    if loom_source == 'emu':
        try:
            from ..equivalence.contracts import make_oracle as make_oracle
            loom_verifier = make_oracle(settings)
        except Exception:
            loom_verifier = None
    loom_stats_value: loom_Dict[str, int] = {'CONST': 0, 'COND2': 0, 'UNRESOLVED': 0}
    for loom_v in LOOM_M.LOOM_VERDICTS:
        loom_stats_value[loom_v] = 0
    items: loom_List[LOOM_M.DestinationSet] = []
    try:
        for loom_p in loom_preds:
            if loom_p.record_type not in ('CONST', 'COND2'):
                continue
            if loom_p.loom_idx_tbl_ea is None or loom_p.loom_tgt_tbl_ea is None:
                loom_stats_value['UNRESOLVED'] += 1
                continue
            loom_br_pc = loom_p.loom_dispatcher_br_ea
            loom_det = loom_p.loom_class_detail or {}
            loom_emu_target: loom_Optional[int] = None
            if loom_source == 'emu' and loom_verifier is not None:
                try:
                    loom_emu_target = oracle_routes.loom_resolve_via_emu(loom_verifier, bridge, HubProjection(loom_br_pc))
                except Exception:
                    loom_emu_target = None

            def loom_entry(loom_state: int, loom_cond_case: loom_Optional[str], loom_cond_name: loom_Optional[str]) -> LOOM_M.DestinationChoice:
                loom_idx, loom_tgt = image_tables.loom_resolve_state(bridge, loom_p.loom_idx_tbl_ea, loom_p.loom_tgt_tbl_ea, loom_state, loom_entry_size, loom_idx_scale, loom_use_reloc)
                loom_vd = loom_grade(loom_source, loom_p.record_type, loom_tgt, loom_br_pc, loom_traces, loom_emu_target)
                loom_stats_value[loom_vd] = loom_stats_value.get(loom_vd, 0) + 1
                return LOOM_M.DestinationChoice(loom_state=loom_state, loom_idx=loom_idx, destination=loom_tgt, equivalence=loom_vd, loom_cond=loom_cond_name, loom_cond_case=loom_cond_case)
            loom_entries: loom_List[LOOM_M.DestinationChoice] = []
            if loom_p.record_type == 'CONST':
                loom_imm = loom_det.get('imm')
                if loom_imm is None:
                    loom_stats_value['UNRESOLVED'] += 1
                    continue
                loom_entries.append(loom_entry(int(loom_imm), None, None))
                loom_stats_value['CONST'] += 1
            else:
                loom_c1, loom_c2 = (loom_det.get('c1'), loom_det.get('c2'))
                if loom_c1 is None or loom_c2 is None:
                    loom_stats_value['UNRESOLVED'] += 1
                    continue
                loom_cond_raw = loom_det.get('cond')
                loom_cond_name = loom_det.get('cond_name')
                if loom_cond_name is None and isinstance(loom_cond_raw, int):
                    loom_cond_name = LOOM_D.loom_cond_name(loom_cond_raw)
                loom_entries.append(loom_entry(int(loom_c1), 'then', loom_cond_name))
                loom_entries.append(loom_entry(int(loom_c2), 'else', loom_cond_name))
                loom_stats_value['COND2'] += 1
            items.append(LOOM_M.DestinationSet(loom_dispatcher_br_ea=loom_br_pc, loom_parent_fn_ea=loom_p.loom_parent_fn_ea, loom_parent_fn_name=loom_p.loom_parent_fn_name, loom_via_class=loom_p.record_type, loom_state_slot=loom_p.loom_state_slot, loom_state_base=loom_p.loom_state_base, loom_idx_tbl_ea=loom_p.loom_idx_tbl_ea, loom_tgt_tbl_ea=loom_p.loom_tgt_tbl_ea, loom_str_ea=loom_p.loom_str_ea, loom_pred_start_ea=loom_p.loom_pred_start_ea, loom_entries=loom_entries))
    finally:
        image_tables.loom_clear_reloc_image()
    return (items, loom_stats_value)

def execute_stage(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, **loom_kw) -> loom_Dict[str, loom_Any]:
    """Resolve every CONST/COND2 dispatcher and grade each target.

    Parameters
    ----------
    adapter :
        The Tier-1 IDA boundary (needs ``loom_get_dword`` / ``loom_get_qword`` / ``loom_is_exec``;
        ``exec_segments`` / ``loom_func_at`` only when ``in_path`` is None and the
        predecessors must be recomputed in-memory).
    cfg :
        A loaded :class:`~branchloom.settings.AnalysisSettings`.
    in_path :
        Path to the ``predecessors`` JSON produced by Phase 2. When ``None`` the
        predecessors are recomputed on the fly (P1 census -> P2 classify) so the
        phase is runnable stand-alone.
    out_path :
        Where to write the ``resolutions`` JSON. When ``None`` the resolutions are
        computed and summarised but not persisted.
    kw['source'] :
        Verdict oracle: ``'trace'`` (default) / ``'emu'`` / ``'static'``.

    Returns
    -------
    dict
        A small summary: resolution count, chosen source, reloc usage and stats.
    """
    loom_source = loom_kw.get('source') or 'trace'
    loom_preds = loom_build_predecessors(bridge, settings, loom_in_path)
    items, loom_stats_value = loom_resolve_all(bridge, settings, loom_preds, loom_source=loom_source)
    if loom_out_path:
        LOOM_M.write_destinations(items, loom_out_path, loom_stats_value)
    return {'phase': 'resolve', 'count': len(items), 'source': str(loom_source).strip().lower(), 'use_reloc': bool(getattr(settings, 'loom_reloc_image', None)), 'stats': loom_stats_value, 'in_path': loom_in_path, 'out_path': loom_out_path}
__all__ = ['execute_stage', 'loom_resolve_all', 'loom_build_predecessors']

# TODO(validate): the emu backend reports one target per BR, not per leg;
# TODO(validate): recompute path reuses p2_classify's module-level classifier
