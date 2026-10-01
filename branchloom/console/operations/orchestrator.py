"""``run`` — the P1..P6 end-to-end pass.

The order is load-bearing. A writing aggressive run restores pristine bytes first so
it is idempotent, walks the read-only artifact chain, then applies bytes only behind
the verifier/regression gate — and rolls back to pristine the moment that gate does
not PASS. The metadata-only switch pass runs last and never changes a byte.
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
import os as loom_os
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List
from ...settings import AnalysisSettings as AnalysisSettings
from ..exchange_paths import LOOM_DEFAULTS as LOOM_DEFAULTS, loom_load_phase as loom_load_phase
from ..context import loom_open_adapter as loom_open_adapter, loom_phase_kwargs as loom_phase_kwargs, loom_will_write as loom_will_write
__all__ = ['loom_cmd_run']

def loom_rollback(bridge, settings) -> int:
    """Restore every configured exec segment to pristine on-disk bytes."""
    from ...integrity import image_restore as image_restore
    loom_n_value = 0
    for loom_s, loom_e, loom_nm in bridge.loom_exec_segments(settings):
        loom_n_value += image_restore.loom_restore_range(bridge, loom_s, loom_e)
    return loom_n_value

def loom_verifier_gate(bridge, settings) -> loom_Dict[str, loom_Any]:
    """SAFETY.md §11 batch verdict used to gate an aggressive ``run``.

    TODO(validate): this audits the *current* (patched) DB plus oracle equivalence
    on the known vectors (``rerun_pass=None``); it does not itself pristine-restore
    and re-diff. That is sufficient as a go/no-go gate here because ``run`` already
    restored pristine before applying, and the oracle check is image-based.
    """
    from ...equivalence import batch_verdict as batch_verdict
    from ...equivalence.contracts import make_oracle as make_oracle
    try:
        loom_verifier = make_oracle(settings)
    except Exception as loom_exc:
        return {'verdict': 'FAIL', 'error': 'verifier load failed: %r' % (loom_exc,)}
    return batch_verdict.loom_run_regression(bridge, settings, loom_verifier, None)

def loom_cmd_run(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    bridge = loom_open_adapter()
    loom_write_value = loom_will_write(options)
    loom_aggressive = settings.loom_mode in ('linear', 'full')
    loom_outdir = options.out_path or '.'
    if loom_outdir and loom_outdir != '.':
        loom_os.makedirs(loom_outdir, exist_ok=True)
    loom_paths = {loom_k: loom_os.path.join(loom_outdir, loom_v) for loom_k, loom_v in LOOM_DEFAULTS.items()}
    loom_steps: loom_List[loom_Dict[str, loom_Any]] = []
    loom_result: loom_Dict[str, loom_Any] = {'command': 'run', 'mode': settings.loom_mode, 'wrote': loom_write_value, 'outdir': loom_outdir, 'steps': loom_steps}
    if loom_write_value and loom_aggressive:
        loom_result['pristine_restored_dwords'] = loom_rollback(bridge, settings)
    loom_kw = loom_phase_kwargs(options)
    loom_chain = [('census', None, loom_paths['dispatchers']), ('classify', loom_paths['dispatchers'], loom_paths['predecessors']), ('resolve', loom_paths['predecessors'], loom_paths['resolutions']), ('plan', loom_paths['resolutions'], loom_paths['plan'])]
    for loom_cmd, loom_ip, loom_op in loom_chain:
        try:
            stage = loom_load_phase(loom_cmd)
            loom_summ = stage.execute_stage(bridge, settings, loom_in_path=loom_ip, loom_out_path=loom_op, **loom_kw)
            loom_steps.append({'phase': loom_cmd, 'ok': True, 'out': loom_op, 'summary': loom_summ})
        except Exception as loom_exc:
            loom_steps.append({'phase': loom_cmd, 'ok': False, 'error': repr(loom_exc)})
            loom_result['verdict'] = 'FAIL'
            loom_result['error'] = 'phase %s failed: %r' % (loom_cmd, loom_exc)
            return loom_result
    if loom_aggressive and loom_write_value:
        try:
            loom_ap = loom_load_phase('apply')
            loom_summ = loom_ap.execute_stage(bridge, settings, loom_in_path=loom_paths['plan'], loom_out_path=None, **loom_kw)
            loom_steps.append({'phase': 'apply', 'ok': True, 'summary': loom_summ})
        except Exception as loom_exc:
            loom_steps.append({'phase': 'apply', 'ok': False, 'error': repr(loom_exc)})
            loom_result['verdict'] = 'FAIL'
            loom_result['error'] = 'apply failed: %r' % (loom_exc,)
            loom_result['rolled_back_dwords'] = loom_rollback(bridge, settings)
            return loom_result
        loom_gate = loom_verifier_gate(bridge, settings)
        loom_result['regression'] = loom_gate
        if loom_gate.get('verdict') != 'PASS':
            loom_result['rolled_back_dwords'] = loom_rollback(bridge, settings)
            loom_steps.append({'phase': 'rollback', 'ok': True})
            loom_result['verdict'] = 'FAIL'
            loom_result['error'] = 'verifier/regression gate did not PASS — rolled back to pristine'
            return loom_result
    try:
        loom_sw = loom_load_phase('switch')
        loom_summ = loom_sw.execute_stage(bridge, settings, loom_in_path=loom_paths['dispatchers'], loom_out_path=loom_paths['switch_log'], **loom_kw)
        loom_steps.append({'phase': 'switch', 'ok': True, 'out': loom_paths['switch_log'], 'summary': loom_summ})
    except Exception as loom_exc:
        loom_steps.append({'phase': 'switch', 'ok': False, 'error': repr(loom_exc)})
        loom_result['verdict'] = 'FAIL'
        loom_result['error'] = 'phase switch failed: %r' % (loom_exc,)
        return loom_result
    loom_result.setdefault('verdict', 'PASS')
    return loom_result
