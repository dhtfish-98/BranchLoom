"""Byte-level recovery and cleanup: ``revert`` and ``clean``.

``revert`` is the escape hatch — it restores the pristine on-disk bytes and so
restores unless ``--dry-run`` is given. ``clean`` folds anti-disassembly filler and,
like every other mutating command, writes only on an explicit ``--apply``.
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List
from ... import records as LOOM_M
from ...settings import AnalysisSettings as AnalysisSettings
from ..context import loom_count_drift as loom_count_drift, loom_open_adapter as loom_open_adapter, loom_parse_int as loom_parse_int, loom_scoped_ranges as loom_scoped_ranges, loom_will_write as loom_will_write
__all__ = ['loom_cmd_revert', 'loom_cmd_clean']

def loom_cmd_revert(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    from ...integrity import image_restore as image_restore
    bridge = loom_open_adapter()
    loom_parent_fn = loom_parse_int(options.parent_fn)
    loom_ranges = loom_scoped_ranges(bridge, settings, loom_parent_fn)
    loom_write_value = not bool(options.dry_run)
    loom_restored = 0
    loom_per: loom_List[loom_Dict[str, loom_Any]] = []
    for loom_s, loom_e, loom_nm_value in loom_ranges:
        if loom_write_value:
            loom_c = image_restore.loom_restore_range(bridge, loom_s, loom_e)
        else:
            loom_c = loom_count_drift(bridge, loom_s, loom_e)
        loom_restored += loom_c
        loom_per.append({'segment': loom_nm_value, 'start': LOOM_M.loom_hx_value(loom_s), 'end': LOOM_M.loom_hx_value(loom_e), 'restored_dwords': loom_c})
    if loom_write_value and loom_parent_fn is not None:
        bridge.loom_reanalyze(loom_parent_fn)
        bridge.loom_auto_wait()
    return {'command': 'revert', 'dry_run': bool(options.dry_run), 'wrote': loom_write_value, 'parent_fn': LOOM_M.loom_hx_value(loom_parent_fn) if loom_parent_fn is not None else None, 'restored_dwords': loom_restored, 'ranges': loom_per}

def loom_cmd_clean(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    from ...dispatch_shapes import filler_repair as filler_repair
    bridge = loom_open_adapter()
    loom_parent_fn = loom_parse_int(options.parent_fn)
    loom_ranges = loom_scoped_ranges(bridge, settings, loom_parent_fn)
    loom_write_value = loom_will_write(options)
    output: loom_Dict[str, loom_Any] = {'command': 'clean', 'wrote': loom_write_value, 'folded': 0, 'nopped': 0, 'ranges': []}
    if not loom_write_value:
        output['note'] = "dry-run: pass --apply to fold trap-BLR literals and NOP DCB filler (reversible with 'revert')"
        for loom_s, loom_e, loom_nm_value in loom_ranges:
            output['ranges'].append({'segment': loom_nm_value, 'start': LOOM_M.loom_hx_value(loom_s), 'end': LOOM_M.loom_hx_value(loom_e)})
        return output
    for loom_s, loom_e, loom_nm_value in loom_ranges:
        loom_r = filler_repair.loom_clean_range(bridge, loom_s, loom_e)
        output['folded'] += int(loom_r.get('folded', 0))
        output['nopped'] += int(loom_r.get('nopped', 0))
        output['ranges'].append({'segment': loom_nm_value, 'start': LOOM_M.loom_hx_value(loom_s), 'end': LOOM_M.loom_hx_value(loom_e), 'folded': loom_r.get('folded', 0), 'nopped': loom_r.get('nopped', 0)})
    if loom_parent_fn is not None:
        bridge.loom_reanalyze(loom_parent_fn)
        bridge.loom_auto_wait()
    return output
