"""``discover`` — the bulk driver.

Census the exec segments, group the two-level dispatchers by dispatch base, then run
the per-function pipeline once per group. Each group gets its own artifact set so a
failure in one group never contaminates another; the first failing stage stops that
group and the rest keep going.
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
import os as loom_os
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Tuple as loom_Tuple
from ... import records as LOOM_M
from ...settings import AnalysisSettings as AnalysisSettings
from ..exchange_paths import LOOM_DEFAULTS as LOOM_DEFAULTS, loom_load_phase as loom_load_phase
from ..context import loom_dump_json as loom_dump_json, loom_open_adapter as loom_open_adapter, loom_phase_kwargs as loom_phase_kwargs, loom_will_write as loom_will_write
__all__ = ['loom_cmd_discover']

def loom_census(bridge, settings, loom_outdir: str) -> loom_List['LOOM_M.RouteHub']:
    """Produce the dispatcher census for ``discover``.

    Prefers the P1 phase (so ``discover`` routes through the same code path as
    ``census``); falls back to the pattern matcher directly so the bulk driver is
    still usable before the phase layer lands.
    """
    loom_disp_path_value = loom_os.path.join(loom_outdir, LOOM_DEFAULTS['dispatchers'])
    try:
        loom_p1 = loom_load_phase('census')
        loom_p1.execute_stage(bridge, settings, loom_in_path=None, loom_out_path=loom_disp_path_value)
        return LOOM_M.read_hubs(loom_disp_path_value)
    except Exception:
        from ...dispatch_shapes.indexed_routes import loom_find_dispatchers as loom_find_dispatchers
        items = loom_find_dispatchers(bridge, settings)
        LOOM_M.write_hubs(items, loom_disp_path_value)
        return items

def loom_dispatch_key(loom_d_value: 'LOOM_M.RouteHub'):
    """Grouping key: the dispatch base (two-level target table), else the parent
    function, else the BR itself — so every dispatcher lands in exactly one group."""
    if loom_d_value.loom_tgt_tbl_ea is not None:
        return loom_d_value.loom_tgt_tbl_ea
    if loom_d_value.loom_parent_fn_ea is not None:
        return loom_d_value.loom_parent_fn_ea
    return loom_d_value.loom_br_ea

def loom_group(items: loom_List['LOOM_M.RouteHub']) -> loom_List[loom_Tuple[loom_Any, loom_List['LOOM_M.RouteHub']]]:
    loom_groups: loom_Dict[loom_Any, loom_List['LOOM_M.RouteHub']] = {}
    for loom_d_value in items:
        loom_groups.setdefault(loom_dispatch_key(loom_d_value), []).append(loom_d_value)
    return sorted(loom_groups.items(), key=lambda loom_kv: loom_kv[0] if isinstance(loom_kv[0], int) else 1 << 63)

def loom_run_group(bridge, settings, options, loom_outdir: str, loom_key_value: loom_Any, items: loom_List['LOOM_M.RouteHub']) -> loom_Dict[str, loom_Any]:
    loom_tag = '0x%x' % loom_key_value if isinstance(loom_key_value, int) else str(loom_key_value)
    loom_base_value = loom_os.path.join(loom_outdir, 'grp_' + loom_tag.replace('0x', ''))
    loom_disp_p = loom_base_value + '_dispatchers.json'
    loom_pred_p = loom_base_value + '_predecessors.json'
    loom_res_p = loom_base_value + '_resolutions.json'
    loom_plan_p = loom_base_value + '_patch_plan.json'
    LOOM_M.write_hubs(items, loom_disp_p)
    loom_g: loom_Dict[str, loom_Any] = {'key': loom_tag, 'dispatch_base': loom_tag if isinstance(loom_key_value, int) else None, 'dispatcher_count': len(items), 'br_eas': [LOOM_M.loom_hx_value(loom_r.loom_br_ea) for loom_r in items], 'parent_fns': sorted({LOOM_M.loom_hx_value(loom_r.loom_parent_fn_ea) for loom_r in items if loom_r.loom_parent_fn_ea is not None}), 'artifacts': {'dispatchers': loom_disp_p}, 'stages': {}, 'errors': []}
    loom_kw = loom_phase_kwargs(options)
    loom_pipeline = [('classify', loom_disp_p, loom_pred_p), ('resolve', loom_pred_p, loom_res_p), ('plan', loom_res_p, loom_plan_p)]
    for loom_cmd, loom_ip, loom_op in loom_pipeline:
        try:
            stage = loom_load_phase(loom_cmd)
            loom_g['stages'][loom_cmd] = stage.execute_stage(bridge, settings, loom_in_path=loom_ip, loom_out_path=loom_op, **loom_kw)
            loom_g['artifacts'][loom_cmd] = loom_op
        except Exception as loom_exc:
            loom_g['errors'].append('%s: %r' % (loom_cmd, loom_exc))
            return loom_g
    try:
        loom_sw = loom_load_phase('switch')
        loom_sp = loom_base_value + '_switch_info_log.json'
        loom_g['stages']['switch'] = loom_sw.execute_stage(bridge, settings, loom_in_path=loom_disp_p, loom_out_path=loom_sp, **loom_kw)
        loom_g['artifacts']['switch'] = loom_sp
    except Exception as loom_exc:
        loom_g['errors'].append('switch: %r' % (loom_exc,))
    if settings.loom_mode in ('linear', 'full') and loom_will_write(options):
        try:
            loom_ap = loom_load_phase('apply')
            loom_g['stages']['apply'] = loom_ap.execute_stage(bridge, settings, loom_in_path=loom_plan_p, loom_out_path=None, **loom_kw)
        except Exception as loom_exc:
            loom_g['errors'].append('apply: %r' % (loom_exc,))
    return loom_g

def loom_cmd_discover(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    bridge = loom_open_adapter()
    loom_outdir = options.out_path or 'discover_out'
    loom_os.makedirs(loom_outdir, exist_ok=True)
    loom_dispatchers = loom_census(bridge, settings, loom_outdir)
    loom_groups = loom_group(loom_dispatchers)
    loom_index: loom_Dict[str, loom_Any] = {'command': 'discover', 'mode': settings.loom_mode, 'wrote': loom_will_write(options), 'outdir': loom_outdir, 'dispatcher_count': len(loom_dispatchers), 'group_count': len(loom_groups), 'groups': []}
    for loom_key_value, items in loom_groups:
        loom_index['groups'].append(loom_run_group(bridge, settings, options, loom_outdir, loom_key_value, items))
    loom_dump_json(loom_os.path.join(loom_outdir, 'discover_index.json'), loom_index)
    loom_index['errors'] = [loom_e for loom_g in loom_index['groups'] for loom_e in loom_g.get('errors', [])]
    return loom_index
