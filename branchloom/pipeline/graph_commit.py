"""
branchloom.pipeline.graph_commit — Phase 6: switch-view xrefs for un-patched dispatchers.

For every dispatcher that P5 did **not** rewrite into a direct branch — the
multi-target ones (several predecessors feeding one ``BR Xt``) and the
unresolved ``XFORM`` / ``OPAQUE`` ones — teach IDA the outgoing edges by adding
a code cross-reference from the ``BR Xt`` site to each handler target found in
the dispatcher's target table. That makes the graph view render the indirect
branch with its N successors and gives Hex-Rays enough to keep decompiling down
each arm, *without changing a single byte*.

Faithful port of
the private reference toolchain (``cff_add_switch_info.py``)
(``install`` / ``revert`` / ``loom_enumerate_targets``) and
``.../tools/switch_view_minimal.py`` (the byte-free, range-merge-free variant),
re-expressed against the target-agnostic interfaces:

  * dispatchers come from :func:`branchloom.records.read_hubs`;
  * "un-patched" is decided from the P5 patch plan when available (a dispatcher
    whose ``br_ea`` was turned into a direct branch is excluded), else from the
    predecessor classification (``XFORM``/``OPAQUE`` or multi-predecessor);
  * table enumeration uses ``bridge.loom_get_qword`` with the config's
    ``entry_size`` stride and the shared ``target_sources.image_tables.loom_target_valid``
    (stop-on-first-invalid), so nothing target-specific is baked in;
  * edges are added with ``bridge.loom_add_jump_xref`` after ``bridge.loom_make_code``
    on both the branch and each target.

We deliberately **never install a ``switch_info_t``**: Hex-Rays validates switch
metadata strictly and can abort decompilation on anything incomplete, whereas a
plain set of code xrefs is tolerant of partial tables (per the reference's
reasoning). Every edge added is recorded in ``cff_switch_info_log.json`` so
:func:`revert` can drop exactly those edges with ``bridge.loom_del_jump_xref``.
"""
from __future__ import annotations as loom_annotations
import json as loom_json
import os as loom_os
from typing import Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Set as loom_Set
from .. import records as LOOM_M
from ..target_sources.image_tables import loom_target_valid as loom_target_valid
__all__ = ['execute_stage', 'loom_install', 'loom_revert']
LOOM_DEFAULT_DISP_NAME = 'cff_dispatchers.json'
LOOM_DEFAULT_LOG_NAME = 'cff_switch_info_log.json'
LOOM__DEFAULT_MAX_ENTRIES = 256

def loom_disp_path(loom_in_path: loom_Optional[str]) -> str:
    return loom_in_path if loom_in_path else LOOM_DEFAULT_DISP_NAME

def loom_log_path(loom_out_path: loom_Optional[str]) -> str:
    return loom_out_path if loom_out_path else LOOM_DEFAULT_LOG_NAME

def loom_max_entries(settings, loom_override: loom_Optional[int]) -> int:
    if loom_override is not None:
        return int(loom_override)
    try:
        return int(settings.loom_cff.get('max_switch_entries', LOOM__DEFAULT_MAX_ENTRIES))
    except Exception:
        return LOOM__DEFAULT_MAX_ENTRIES

def loom_enumerate_targets(bridge, loom_tgt_tbl_ea: int, loom_entry_size: int, loom_max_entries_value: int) -> loom_List[int]:
    """Collect in-exec-segment qwords from ``tgt_tbl_ea``, stop on first invalid.

    Mirrors the reference ``loom_enumerate_targets`` with ``stop_on_invalid=True``:
    each slot is read at ``tgt_tbl_ea + i * entry_size`` and validated with the
    shared :func:`target_sources.image_tables.loom_target_valid` (non-zero, not BADADDR,
    4-byte aligned, executable segment). The first slot that fails ends the run,
    which is how these compiler-emitted tables terminate.
    """
    output: loom_List[int] = []
    for loom_i in range(loom_max_entries_value):
        loom_v = bridge.loom_get_qword(loom_tgt_tbl_ea + loom_i * loom_entry_size)
        if not loom_target_valid(bridge, loom_v):
            break
        output.append(loom_v)
    return output

def loom_patched_dispatchers(loom_plan_path_value: loom_Optional[str]) -> loom_Optional[loom_Set[int]]:
    """Set of dispatcher br_eas P5 turned into direct branches, or None.

    Returns ``None`` when no patch plan is available (then P6 falls back to the
    predecessor-class heuristic). ``records.ByteRewrite.loom_dispatcher_pc`` records the
    owning dispatcher for every planned patch, so the set of distinct
    ``dispatcher_pc`` values is exactly the dispatchers P5 rewrote.
    """
    if not loom_plan_path_value or not loom_os.path.exists(loom_plan_path_value):
        return None
    loom_patched: loom_Set[int] = set()
    for loom_p in LOOM_M.read_rewrites(loom_plan_path_value):
        if loom_p.loom_dispatcher_pc is not None:
            loom_patched.add(loom_p.loom_dispatcher_pc)
    return loom_patched

def loom_pred_index(loom_preds_path: loom_Optional[str]):
    """Build ``{br_ea: set(classes)}`` and ``{br_ea: n_preds}`` from predecessors.

    Returns ``(classes_by_br, count_by_br)`` — both empty when no predecessors
    file is available.
    """
    loom_classes_by_br: loom_Dict[int, loom_Set[str]] = {}
    loom_count_by_br: loom_Dict[int, int] = {}
    if not loom_preds_path or not loom_os.path.exists(loom_preds_path):
        return (loom_classes_by_br, loom_count_by_br)
    for loom_pr in LOOM_M.read_incoming(loom_preds_path):
        loom_classes_by_br.setdefault(loom_pr.loom_dispatcher_br_ea, set()).add(loom_pr.record_type)
        loom_count_by_br[loom_pr.loom_dispatcher_br_ea] = loom_count_by_br.get(loom_pr.loom_dispatcher_br_ea, 0) + 1
    return (loom_classes_by_br, loom_count_by_br)

def loom_is_unpatched(loom_d_value: LOOM_M.RouteHub, loom_patched: loom_Optional[loom_Set[int]], loom_classes_by_br: loom_Dict[int, loom_Set[str]], loom_count_by_br: loom_Dict[int, int]) -> bool:
    """Decide whether ``d`` is a P6 switch-view candidate (un-patched by P5).

    * If a patch plan is available, authoritative: ``loom_d_value.loom_br_ea`` is un-patched iff
      it is not among the dispatchers P5 rewrote.
    * Otherwise, classify from predecessors: a dispatcher is un-patched when it
      is fed by more than one predecessor (multi-target — a single ``BR`` cannot
      become one direct branch) or any predecessor is ``XFORM``/``OPAQUE`` (no
      resolvable constant state). A lone ``CONST``/``COND2`` predecessor is the
      case P5 handles, so it is excluded. An unknown dispatcher (no predecessor
      row) is treated as un-patched so its edges are still surfaced.
    """
    if loom_patched is not None:
        return loom_d_value.loom_br_ea not in loom_patched
    loom_classes = loom_classes_by_br.get(loom_d_value.loom_br_ea)
    if not loom_classes:
        return True
    if loom_classes & {'XFORM', 'OPAQUE'}:
        return True
    loom_n_preds = max(loom_count_by_br.get(loom_d_value.loom_br_ea, 0), len(loom_d_value.loom_predecessor_eas))
    if loom_n_preds > 1:
        return True
    return False

def loom_parent_label(loom_d_value: LOOM_M.RouteHub) -> loom_Optional[str]:
    if loom_d_value.loom_parent_fn_name:
        return loom_d_value.loom_parent_fn_name
    return LOOM_M.loom_hx_value(loom_d_value.loom_parent_fn_ea)

def loom_install(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, *, loom_parent_fn=None, loom_dry_run: bool=True, loom_plan_path_value: loom_Optional[str]=None, loom_preds_path: loom_Optional[str]=None, loom_max_entries_value: loom_Optional[int]=None) -> loom_Dict:
    """Add switch-view code xrefs to every un-patched dispatcher's ``BR`` site.

    Parameters
    ----------
    adapter : Tier-1 IDA boundary module.
    cfg : AnalysisSettings — supplies ``entry_size`` (target-table stride) and, optionally,
        ``cff.max_switch_entries``.
    in_path : path to ``cff_dispatchers.json`` (``records.write_hubs`` file).
    out_path : path for the audit/reversal log (``cff_switch_info_log.json``).
    parent_fn : optional filter by parent function name.
    dry_run : if True (default) log intentions, add **no** xrefs, still writing
        the preview log so a subsequent ``revert`` has data to act on.
    plan_path : optional P5 patch plan; when given, "un-patched" == not rewritten.
    preds_path : optional predecessors file; the fallback classifier when no plan.
    max_entries : hard cap on target-table entries scanned (else from config).
    """
    loom_entry_size = settings.loom_entry_size
    loom_cap = loom_max_entries(settings, loom_max_entries_value)
    loom_dispatchers = LOOM_M.read_hubs(loom_disp_path(loom_in_path))
    loom_patched = loom_patched_dispatchers(loom_plan_path_value)
    loom_classes_by_br, loom_count_by_br = loom_pred_index(loom_preds_path)
    loom_selected: loom_List[LOOM_M.RouteHub] = []
    for loom_d_value in loom_dispatchers:
        if loom_parent_fn and loom_d_value.loom_parent_fn_name != loom_parent_fn:
            continue
        if not loom_is_unpatched(loom_d_value, loom_patched, loom_classes_by_br, loom_count_by_br):
            continue
        loom_selected.append(loom_d_value)
    print('[p6] %d/%d dispatchers are un-patched candidates (dry_run=%s, parent_fn=%r, plan=%s)' % (len(loom_selected), len(loom_dispatchers), loom_dry_run, loom_parent_fn, 'yes' if loom_patched is not None else 'no'))
    loom_log: loom_List[loom_Dict] = []
    loom_added = 0
    loom_skipped_no_tbl = 0
    loom_touched_fns: loom_Set[int] = set()
    for loom_d_value in loom_selected:
        if loom_d_value.loom_tgt_tbl_ea is None:
            loom_skipped_no_tbl += 1
            continue
        loom_targets = loom_enumerate_targets(bridge, loom_d_value.loom_tgt_tbl_ea, loom_entry_size, loom_cap)
        if not loom_targets:
            loom_skipped_no_tbl += 1
            continue
        loom_entry_value = {'br_ea': LOOM_M.loom_hx_value(loom_d_value.loom_br_ea), 'parent': loom_parent_label(loom_d_value), 'targets': [LOOM_M.loom_hx_value(loom_t_value) for loom_t_value in loom_targets]}
        loom_log.append(loom_entry_value)
        if loom_dry_run:
            print('  [dry] %s: +%d xrefs  (%s)' % (LOOM_M.loom_hx_value(loom_d_value.loom_br_ea), len(loom_targets), loom_parent_label(loom_d_value)))
            continue
        bridge.loom_make_code(loom_d_value.loom_br_ea)
        for loom_t_value in loom_targets:
            bridge.loom_make_code(loom_t_value)
            bridge.loom_add_jump_xref(loom_d_value.loom_br_ea, loom_t_value)
            loom_added += 1
        if loom_d_value.loom_parent_fn_ea is not None:
            loom_touched_fns.add(loom_d_value.loom_parent_fn_ea)
    if not loom_dry_run:
        for loom_fs in sorted(loom_touched_fns):
            bridge.loom_reanalyze(loom_fs)
        bridge.loom_auto_wait()
    loom_log_path_value = loom_log_path(loom_out_path)
    loom_write_log(loom_log_path_value, loom_log)
    print('[p6] %s %d xrefs across %d dispatchers; skipped(no table)=%d; log=%s' % ('would add' if loom_dry_run else 'added', loom_added if not loom_dry_run else sum((len(loom_e['targets']) for loom_e in loom_log)), len(loom_log), loom_skipped_no_tbl, loom_log_path_value))
    return {'dry_run': loom_dry_run, 'candidates': len(loom_selected), 'dispatchers_xreffed': len(loom_log), 'xrefs_added': loom_added, 'skipped_no_table': loom_skipped_no_tbl, 'reanalyzed_fns': len(loom_touched_fns), 'log_path': loom_log_path_value}

def loom_write_log(loom_log_path_value: str, loom_log: loom_List[loom_Dict]) -> None:
    loom_d_value = loom_os.path.dirname(loom_log_path_value)
    if loom_d_value:
        loom_os.makedirs(loom_d_value, exist_ok=True)
    with open(loom_log_path_value, 'w', encoding='utf-8') as stream:
        loom_json.dump({'log': loom_log}, stream, indent=2)

def loom_revert(bridge, settings, loom_out_path: loom_Optional[str]=None, *, loom_parent_fn=None) -> loom_Dict:
    """Remove every xref recorded in the switch-info log via ``loom_del_jump_xref``.

    Idempotent: an already-absent edge is a no-op. ``loom_del_jump_xref`` drops only
    the edge (``expand=0``), never the target code, so reverting is byte-neutral
    just like install.
    """
    loom_log_path_value = loom_log_path(loom_out_path)
    if not loom_os.path.exists(loom_log_path_value):
        print('[p6] no switch-info log at %s; nothing to revert' % loom_log_path_value)
        return {'removed': 0}
    with open(loom_log_path_value, 'r', encoding='utf-8') as stream:
        loom_entries = loom_json.load(stream).get('log', [])
    if loom_parent_fn:
        loom_entries = [loom_e for loom_e in loom_entries if loom_e.get('parent') == loom_parent_fn]
    loom_removed = 0
    loom_touched: loom_Set[int] = set()
    for loom_e in loom_entries:
        loom_br_ea = LOOM_M.loom_unhx(loom_e['br_ea'])
        for loom_t_s in loom_e.get('targets', []):
            bridge.loom_del_jump_xref(loom_br_ea, LOOM_M.loom_unhx(loom_t_s))
            loom_removed += 1
        loom_fa = None
        try:
            loom_fa = bridge.loom_func_at(loom_br_ea)
        except Exception:
            loom_fa = None
        if loom_fa is not None:
            loom_touched.add(loom_fa[0])
    for loom_fs in sorted(loom_touched):
        bridge.loom_reanalyze(loom_fs)
    bridge.loom_auto_wait()
    print('[p6] removed %d switch-view xrefs' % loom_removed)
    return {'removed': loom_removed, 'reanalyzed_fns': len(loom_touched)}

def execute_stage(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, **loom_kw) -> loom_Dict:
    """Tier-3 entry point. ``kw`` honoured:

      * ``revert=True``  -> delegate to :func:`revert` (uses ``out_path`` log).
      * ``parent_fn``    -> filter by parent function name.
      * ``dry_run`` (default True)
      * ``plan_path``    -> P5 patch plan (authoritative un-patched test).
      * ``preds_path``   -> predecessors file (fallback classifier).
      * ``max_entries``  -> per-dispatcher table scan cap.
    """
    if loom_kw.get('revert'):
        return loom_revert(bridge, settings, loom_out_path, loom_parent_fn=loom_kw.get('parent_fn'))
    return loom_install(bridge, settings, loom_in_path, loom_out_path, loom_parent_fn=loom_kw.get('parent_fn'), loom_dry_run=loom_kw.get('dry_run', True), loom_plan_path_value=loom_kw.get('plan_path'), loom_preds_path=loom_kw.get('preds_path'), loom_max_entries_value=loom_kw.get('max_entries'))

# TODO(validate): default cap 256 mirrors the reference (_enumerate_targets
