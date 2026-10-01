"""
branchloom.pipeline.enumeration — Phase 1: enumerate two-level CFF dispatchers.

Thin, read-only orchestration around the Family-A detector core
:func:`branchloom.dispatch_shapes.indexed_routes.loom_find_dispatchers`. It runs the detector
over the configured exec segments, writes the ``cff_dispatchers.json`` artifact
via :func:`branchloom.records.write_hubs`, and returns a small summary dict
for the CLI / caller.

Faithful port of the ``run`` driver in
the private reference toolchain (``cff_census.py``)
(the scan + JSON-emit + parent-fn tally), re-expressed against this package's
target-agnostic seams:

  * the dispatcher-triplet recognition, state-load back-scan and table-base
    resolution all live in ``dispatch_shapes.indexed_routes`` (locked ``arm_words.recognition``
    predicates, no hand-rolled masks here);
  * segment ranges come from ``bridge.loom_exec_segments(cfg)`` — never a hardcoded
    ``.text`` name or absolute address;
  * the artifact schema is ``records.RouteHub`` (not an ad-hoc dict).

No DB writes, no analysis mutation — census is purely observational.
"""
from __future__ import annotations as loom_annotations
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional
from .. import records as LOOM_M
from ..dispatch_shapes import indexed_routes as indexed_routes

def loom_segment_meta(bridge, settings) -> loom_List[loom_Dict[str, loom_Any]]:
    """Concrete exec ranges scanned, as JSON-able ``{start,end,name}`` records."""
    output: loom_List[loom_Dict[str, loom_Any]] = []
    try:
        for loom_s, loom_e, loom_nm_value in bridge.loom_exec_segments(settings):
            output.append({'start': LOOM_M.loom_hx_value(loom_s), 'end': LOOM_M.loom_hx_value(loom_e), 'name': loom_nm_value})
    except Exception:
        pass
    return output

def loom_top_parents(items: loom_List[LOOM_M.RouteHub], loom_limit: int=20) -> loom_List[loom_Dict[str, loom_Any]]:
    """The ``limit`` parent functions carrying the most dispatchers (desc)."""
    loom_tally: loom_Dict[str, int] = {}
    for loom_d_value in items:
        loom_key_value = loom_d_value.loom_parent_fn_name or LOOM_M.loom_hx_value(loom_d_value.loom_parent_fn_ea) or '?'
        loom_tally[loom_key_value] = loom_tally.get(loom_key_value, 0) + 1
    loom_ordered = sorted(loom_tally.items(), key=lambda loom_kv: (-loom_kv[1], loom_kv[0]))[:loom_limit]
    return [{'parent': label, 'count': loom_cnt_value} for label, loom_cnt_value in loom_ordered]

def execute_stage(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, **loom_kw) -> loom_Dict[str, loom_Any]:
    """Scan the configured exec segments for two-level CFF dispatchers.

    Parameters
    ----------
    adapter :
        The Tier-1 IDA boundary (``branchloom.database.bridge`` or a compatible
        stub exposing ``loom_get_dword`` / ``exec_segments`` / ``loom_func_at`` /
        ``loom_xrefs_to_code``).
    cfg :
        A loaded :class:`~branchloom.settings.AnalysisSettings`.
    in_path :
        Unused for census (P1 is the pipeline source). Accepted for a uniform
        phase signature.
    out_path :
        Where to write ``cff_dispatchers.json``. When ``None`` the census is
        computed and summarised but not persisted (dry inspection).

    Returns
    -------
    dict
        A small summary: dispatcher count, state-load coverage, table-resolution
        coverage, the scanned segments and the busiest parent functions.
    """
    loom_dispatchers = indexed_routes.loom_find_dispatchers(bridge, settings)
    loom_with_state = sum((1 for loom_d_value in loom_dispatchers if loom_d_value.loom_state_load_ea is not None))
    loom_with_idx_tbl = sum((1 for loom_d_value in loom_dispatchers if loom_d_value.loom_idx_tbl_ea is not None))
    loom_with_tgt_tbl = sum((1 for loom_d_value in loom_dispatchers if loom_d_value.loom_tgt_tbl_ea is not None))
    loom_segments = loom_segment_meta(bridge, settings)
    loom_meta = {'phase': 'census', 'count': len(loom_dispatchers), 'with_state_load': loom_with_state, 'without_state_load': len(loom_dispatchers) - loom_with_state, 'with_idx_tbl': loom_with_idx_tbl, 'with_tgt_tbl': loom_with_tgt_tbl, 'segments': loom_segments}
    if loom_out_path:
        LOOM_M.write_hubs(loom_dispatchers, loom_out_path, loom_meta=loom_meta)
    loom_summary = dict(loom_meta)
    loom_summary['out_path'] = loom_out_path
    loom_summary['top_parents'] = loom_top_parents(loom_dispatchers)
    return loom_summary
__all__ = ['execute_stage']
