"""The evidence commands: ``trace``, ``verify`` and ``regress``.

None of these rewrite bytes. They answer the three questions the safety model asks
before a batch is allowed to stand: what did we actually observe at each branch
(``trace``), does the oracle still reproduce the known I/O vectors (``verify``), and
what is the batch verdict (``regress``, SAFETY.md §11).
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
import os as loom_os
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List
from ... import records as LOOM_M
from ...settings import AnalysisSettings as AnalysisSettings
from ..exchange_paths import LOOM_DEFAULTS as LOOM_DEFAULTS, loom_load_phase as loom_load_phase
from ..context import loom_dump_json as loom_dump_json, loom_open_adapter as loom_open_adapter, loom_will_write as loom_will_write
__all__ = ['loom_cmd_trace', 'loom_cmd_verify', 'loom_cmd_regress']

def loom_cmd_trace(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    from ...target_sources import observed_routes as observed_routes
    loom_traces = observed_routes.loom_load_traces(settings)
    loom_sites: loom_List[loom_Dict[str, loom_Any]] = []
    loom_singles = 0
    for location in sorted(loom_traces):
        loom_tgts = loom_traces[location]
        loom_st = observed_routes.loom_single_target(loom_traces, location)
        if loom_st is not None:
            loom_singles += 1
        loom_sites.append({'br_pc': LOOM_M.loom_hx_value(location), 'targets': [LOOM_M.loom_hx_value(loom_t_value) for loom_t_value in sorted(loom_tgts)], 'single_target': LOOM_M.loom_hx_value(loom_st) if loom_st is not None else None})
    loom_summary = {'command': 'trace', 'source': (settings.loom_trace or {}).get('source', 'file'), 'branch_count': len(loom_traces), 'single_target_count': loom_singles, 'sites': loom_sites}
    if options.out_path:
        loom_dump_json(options.out_path, loom_summary)
        loom_summary['written'] = options.out_path
    return loom_summary

def loom_cmd_verify(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    from ...equivalence.contracts import make_oracle as make_oracle
    loom_verifier = make_oracle(settings)
    loom_vectors = loom_verifier.loom_known_vectors()
    loom_entry_value = loom_verifier.loom_entry_value()
    output: loom_Dict[str, loom_Any] = {'command': 'verify', 'backend': getattr(loom_verifier, 'loom_backend', '?'), 'entry': LOOM_M.loom_hx_value(loom_entry_value) if loom_entry_value is not None else None, 'vector_count': len(loom_vectors), 'results': []}
    if not loom_vectors:
        output['ok'] = True
        output['note'] = 'no verifier.known_vectors configured — nothing to check'
        return output
    if loom_entry_value is None:
        output['ok'] = False
        output['error'] = 'verifier.entry not set but known_vectors present'
        return output
    loom_all_ok = True
    for loom_i, (loom_inp, loom_expected) in enumerate(loom_vectors):
        loom_rec: loom_Dict[str, loom_Any] = {'index': loom_i, 'in_len': len(loom_inp), 'out_len': len(loom_expected)}
        try:
            loom_got = bytes(loom_verifier.evaluate_io(loom_entry_value, bytes(loom_inp)))
            loom_ok = loom_got == bytes(loom_expected)
            loom_rec['ok'] = loom_ok
            if not loom_ok:
                loom_rec['got'] = loom_got.hex()
                loom_rec['expected'] = bytes(loom_expected).hex()
        except Exception as loom_exc:
            loom_ok = False
            loom_rec['ok'] = False
            loom_rec['error'] = repr(loom_exc)
        loom_all_ok = loom_all_ok and loom_ok
        output['results'].append(loom_rec)
    output['ok'] = loom_all_ok
    return output

def loom_cmd_regress(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    from ...equivalence import batch_verdict as batch_verdict
    from ...equivalence.contracts import make_oracle as make_oracle
    bridge = loom_open_adapter()
    try:
        loom_verifier = make_oracle(settings)
    except Exception as loom_exc:
        loom_verifier = None
        loom_verifier_error = repr(loom_exc)
    else:
        loom_verifier_error = None
    loom_rerun = None
    loom_plan_path_value = options.in_path or LOOM_DEFAULTS['plan']
    if loom_will_write(options) and loom_plan_path_value and loom_os.path.exists(loom_plan_path_value):

        def loom_rerun(loom_a, loom_c, loom_pp=loom_plan_path_value):
            loom_p5 = loom_load_phase('apply')
            return loom_p5.execute_stage(loom_a, loom_c, loom_in_path=loom_pp, loom_out_path=None, apply=True, dry_run=False) or {}
    loom_result_path = options.out_path or (settings.batch_verdict or {}).get('result_path')
    output = batch_verdict.loom_run_regression(bridge, settings, loom_verifier, loom_rerun, loom_result_path=loom_result_path)
    if isinstance(output, dict):
        output.setdefault('command', 'regress')
        if loom_verifier_error:
            output['verifier_error'] = loom_verifier_error
    return output
