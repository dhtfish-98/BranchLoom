"""
branchloom.equivalence.batch_verdict — the batch PASS/FAIL verdict (SAFETY.md §11).

Ports the checklist mechanised by the private reference ``misc/deobf/regress_deobf.py``
into a target-agnostic, config-driven form. After the devirtualizer applies a batch,
this harness independently re-proves the batch is safe by combining:

  1. **baseline delta** — coverage may never regress (``delta_skipped <= 0``);
  2. **skip-map diff** — the set of *skipped* sites (and their reasons) must match the
     configured expectations (no unexpected new skips, none silently dropped);
  3. **sample disassembly** — configured sample sites must decode to the expected
     branch mnemonic + target after patching;
  4. **self-check aggregation** — every per-site self-check the pass reported must pass;
  5. **oracle equivalence** — the configured known I/O vectors, re-run through the
     behavioural :class:`~branchloom.equivalence.contracts.BehaviorOracle`, must reproduce their
     expected outputs byte-for-byte.

Everything target-specific (the baseline counts, the ``reason -> [ea]`` skip map, the
sample sites, the I/O vectors, and the segment selection) comes from the ``AnalysisSettings``;
nothing is hard-coded. No address, no vector, no segment name lives in this file.

This module is **IDA-free**: it reaches the database only through the Tier-1
``adapter`` passed in (``loom_get_dword`` / ``exec_segments`` and, via
:mod:`branchloom.integrity.image_restore`, the pristine-restore primitives), so it is
testable off-device with a fake adapter.

Contract for ``rerun_pass``
---------------------------
``rerun_pass(adapter, cfg) -> report`` re-runs the full deflatten+apply pass over the
configured segments and returns a summary dict. Recognised (all optional) keys:

  * ``patched``  — int count of patched dispatch sites (else derived from ``sites``);
  * ``skipped``  — int count of skipped sites (else derived from ``sites``);
  * ``sites``    — list of per-site dicts, each with ``kind`` in {``patched``,
    ``skipped``}, a ``br_ea`` (int or hex-string), a ``reason`` (for skips), and for
    patched sites the optional ``self_check_ok`` / ``self_check_errors`` fields.

Passing ``rerun_pass=None`` evaluates the *current* database state without restoring
pristine or re-running the pass (useful for a stand-alone sample+oracle audit).
"""
from __future__ import annotations as loom_annotations
import json as loom_json
import os as loom_os
import time as loom_time
from typing import Any as loom_Any, Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from ..arm_words import recognition as LOOM_D
from ..integrity import image_restore as image_restore

def loom_as_int(loom_v, loom_default=None):
    if loom_v is None:
        return loom_default
    if isinstance(loom_v, bool):
        return int(loom_v)
    if isinstance(loom_v, int):
        return loom_v
    if isinstance(loom_v, str):
        loom_s = loom_v.strip()
        if not loom_s:
            return loom_default
        return int(loom_s, 0)
    return int(loom_v)

def loom_classify_sites(loom_sites: loom_List[loom_Dict[str, loom_Any]]) -> loom_Tuple[int, loom_Dict[int, str]]:
    """Split a pass report's ``sites`` into (patched_count, {br_ea: reason})."""
    loom_skipped: loom_Dict[int, str] = {}
    loom_patched = 0
    for loom_s in loom_sites or []:
        loom_kind_value = loom_s.get('kind')
        if loom_kind_value == 'skipped':
            address = loom_as_int(loom_s.get('br_ea'), 0)
            loom_skipped[address] = loom_s.get('reason', '')
        elif loom_kind_value:
            loom_patched += 1
    return (loom_patched, loom_skipped)

def loom_diff_skips(loom_got: loom_Dict[int, str], loom_expected: loom_Dict[str, loom_List[loom_Any]]) -> loom_Tuple[loom_List[dict], loom_List[dict]]:
    """Compare actual skip map (ea->reason) vs expected (reason->[ea]).

    Returns ``(unexpected, missing)``: sites skipped that were not expected (or with a
    changed reason), and sites expected-skipped that are no longer skipped.
    """
    loom_expected_flat: loom_Dict[int, str] = {}
    for loom_reason, loom_eas in (loom_expected or {}).items():
        for address in loom_eas or []:
            loom_expected_flat[loom_as_int(address)] = loom_reason
    loom_unexpected: loom_List[dict] = []
    for address, loom_reason in loom_got.items():
        loom_exp = loom_expected_flat.get(address)
        if loom_exp is None:
            loom_unexpected.append({'br_ea': hex(address), 'reason': loom_reason, 'note': 'new skip'})
        elif loom_exp != loom_reason:
            loom_unexpected.append({'br_ea': hex(address), 'reason': loom_reason, 'note': 'reason changed (expected "%s")' % loom_exp})
    loom_missing: loom_List[dict] = []
    for address, loom_reason in loom_expected_flat.items():
        if address not in loom_got:
            loom_missing.append({'br_ea': hex(address), 'reason': loom_reason, 'note': 'no longer skipped'})
    return (loom_unexpected, loom_missing)

def loom_collect_self_check_failures(loom_sites: loom_List[loom_Dict[str, loom_Any]]) -> loom_List[dict]:
    loom_failures: loom_List[dict] = []
    for loom_s in loom_sites or []:
        if loom_s.get('kind') != 'patched':
            continue
        if loom_s.get('self_check_ok') is False:
            loom_failures.append({'br_ea': hex(loom_as_int(loom_s.get('br_ea'), 0)), 'errors': list(loom_s.get('self_check_errors') or [])})
    return loom_failures

def loom_mnem(address: int, opcode: int) -> str:
    """Best-effort short disassembly string for diagnostics (decode-only)."""
    if LOOM_D.loom_is_b(opcode):
        return 'B 0x%x' % LOOM_D.loom_b_target(address, opcode)
    if LOOM_D.loom_is_bcond(opcode):
        return 'B.%s 0x%x' % (LOOM_D.loom_cond_name(LOOM_D.loom_bcond_cond(opcode)), LOOM_D.loom_bcond_target(address, opcode))
    if LOOM_D.loom_is_bl(opcode):
        return 'BL 0x%x' % LOOM_D.loom_b_target(address, opcode)
    if LOOM_D.loom_is_br(opcode):
        return 'BR X%d' % LOOM_D.loom_br_rn(opcode)
    if LOOM_D.loom_is_ret(opcode):
        return 'RET'
    return '0x%08x' % opcode

def loom_check_branch(address: int, opcode: int, loom_prefix: str, destination: int) -> loom_Tuple[bool, str]:
    """Decode ``word`` at ``ea`` and check it is a ``prefix`` branch to ``target``.

    ``prefix`` is a mnemonic such as ``"B"`` (unconditional) or ``"B.NE"`` (a
    conditional). The check is decode-based (not string-matching against IDA), so it
    is exact and IDA-free.
    """
    opcode &= 4294967295
    loom_p = str(loom_prefix).upper().strip()
    if loom_p == 'B':
        if LOOM_D.loom_is_b(opcode):
            return (LOOM_D.loom_b_target(address, opcode) == destination, loom_mnem(address, opcode))
        return (False, loom_mnem(address, opcode))
    if loom_p.startswith('B.'):
        loom_want = LOOM_D.loom_cond_num(loom_p[2:])
        if LOOM_D.loom_is_bcond(opcode) and loom_want is not None:
            loom_got_cond = LOOM_D.loom_bcond_cond(opcode) & 15
            loom_ok = loom_got_cond == loom_want and LOOM_D.loom_bcond_target(address, opcode) == destination
            return (loom_ok, loom_mnem(address, opcode))
        return (False, loom_mnem(address, opcode))
    return (False, loom_mnem(address, opcode) + ' (unhandled prefix %r)' % loom_prefix)

def loom_sample_fields(loom_s: loom_Any) -> loom_Tuple[int, str, int]:
    """Accept a sample as a dict {ea,prefix,target} or a (ea, prefix, target) tuple."""
    if isinstance(loom_s, dict):
        return (loom_as_int(loom_s.get('ea')), str(loom_s.get('prefix', '')), loom_as_int(loom_s.get('target')))
    return (loom_as_int(loom_s[0]), str(loom_s[1]), loom_as_int(loom_s[2]))

def loom_verify_samples(bridge, loom_samples: loom_List[loom_Any]) -> loom_List[dict]:
    loom_results: loom_List[dict] = []
    for loom_s in loom_samples or []:
        address, loom_prefix, destination = loom_sample_fields(loom_s)
        opcode = bridge.loom_get_dword(address) & 4294967295
        loom_ok, loom_disasm = loom_check_branch(address, opcode, loom_prefix, destination)
        loom_results.append({'br_ea': hex(address), 'expected_prefix': loom_prefix, 'expected_target': hex(destination) if destination is not None else None, 'disasm': loom_disasm, 'raw': '%#010x' % opcode, 'ok': bool(loom_ok)})
    return loom_results

def loom_oracle_equivalence(loom_verifier, loom_entry_value: int, loom_vectors: loom_List[loom_Tuple[bytes, bytes]]) -> loom_Tuple[bool, loom_List[dict]]:
    """Re-run each known I/O vector and require byte-identical output."""
    loom_results: loom_List[dict] = []
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
        loom_results.append(loom_rec)
    return (loom_all_ok, loom_results)

def loom_write_result(location_path: str, output: dict) -> None:
    loom_d_value = loom_os.path.dirname(location_path)
    if loom_d_value:
        loom_os.makedirs(loom_d_value, exist_ok=True)
    with open(location_path, 'w', encoding='utf-8') as stream:
        loom_json.dump(output, stream, indent=2, default=str)

def loom_run_regression(bridge, settings, loom_verifier, loom_rerun_pass: loom_Optional[loom_Callable[[loom_Any, loom_Any], dict]], loom_result_path: loom_Optional[str]=None) -> dict:
    """Produce a PASS/FAIL verdict for the just-applied batch (SAFETY.md §11).

    ``adapter`` is the Tier-1 IDA adapter; ``cfg`` a loaded :class:`AnalysisSettings`;
    ``verifier`` a :class:`~branchloom.equivalence.contracts.BehaviorOracle` (its
    ``known_vectors`` + ``entry`` drive the oracle check); ``rerun_pass`` re-runs the
    deflatten+apply pass (see the module docstring for its report contract) or is
    ``None`` to audit the current DB state without touching it. The returned dict
    carries the full evidence and a top-level ``loom_verdict`` of ``'PASS'`` or ``'FAIL'``.
    """
    output: loom_Dict[str, loom_Any] = {'started_at': loom_time.time()}
    loom_reg = dict(getattr(settings, 'batch_verdict', None) or {})
    loom_baseline = dict(loom_reg.get('baseline') or {})
    loom_base_patched = int(loom_baseline.get('patched', 0))
    loom_base_skipped = int(loom_baseline.get('skipped', 0))
    loom_skip_expect = loom_reg.get('skip_expectations') or {}
    loom_samples = loom_reg.get('samples') or []
    loom_ranges = bridge.loom_exec_segments(settings)
    output['segments'] = [[hex(loom_s), hex(loom_e), loom_nm_value] for loom_s, loom_e, loom_nm_value in loom_ranges]
    if loom_rerun_pass is not None:
        loom_restored = 0
        for loom_s, loom_e, loom_nm in loom_ranges:
            loom_restored += image_restore.loom_restore_range(bridge, loom_s, loom_e)
        output['pristine_restored_dwords'] = loom_restored
        loom_t0 = loom_time.time()
        loom_rep = loom_rerun_pass(bridge, settings) or {}
        output['elapsed_pass_s'] = round(loom_time.time() - loom_t0, 3)
    else:
        loom_rep = {}
        output['pristine_restored_dwords'] = 0
        output['elapsed_pass_s'] = None
    loom_sites = loom_rep.get('sites', []) or []
    loom_patched_seen, loom_skipped_map = loom_classify_sites(loom_sites)
    loom_patched_reported = loom_rep.get('patched')
    loom_skipped_reported = loom_rep.get('skipped')
    if loom_patched_reported is None:
        loom_patched_reported = loom_patched_seen
    if loom_skipped_reported is None:
        loom_skipped_reported = len(loom_skipped_map)
    output['patched'] = loom_patched_reported
    output['skipped'] = loom_skipped_reported
    output['sites_total'] = len(loom_sites)
    output['sites_patched_seen'] = loom_patched_seen
    output['sites_skipped'] = [{'br_ea': hex(address), 'reason': loom_r} for address, loom_r in sorted(loom_skipped_map.items())]
    output['delta_patched'] = int(loom_patched_reported or 0) - loom_base_patched
    output['delta_skipped'] = int(loom_skipped_reported or 0) - loom_base_skipped
    loom_unexpected, loom_missing = loom_diff_skips(loom_skipped_map, loom_skip_expect)
    output['skip_unexpected'] = loom_unexpected
    output['skip_missing'] = loom_missing
    output['samples'] = loom_verify_samples(bridge, loom_samples)
    output['samples_all_ok'] = all((loom_s['ok'] for loom_s in output['samples'])) if output['samples'] else True
    output['self_check_failures'] = loom_collect_self_check_failures(loom_sites)
    output['self_check_all_ok'] = not output['self_check_failures']
    loom_vectors: loom_List[loom_Tuple[bytes, bytes]] = []
    loom_entry_value: loom_Optional[int] = None
    if loom_verifier is not None:
        try:
            loom_vectors = loom_verifier.loom_known_vectors()
        except Exception as loom_exc:
            output['oracle_error'] = repr(loom_exc)
            loom_vectors = []
        try:
            loom_entry_value = loom_verifier.loom_entry_value()
        except Exception:
            loom_entry_value = None
    if loom_vectors and loom_entry_value is None:
        output['oracle_all_ok'] = False
        output['oracle'] = [{'ok': False, 'error': 'verifier.entry not set but known_vectors present'}]
    elif loom_vectors:
        loom_oracle_ok, loom_oracle_results = loom_oracle_equivalence(loom_verifier, loom_entry_value, loom_vectors)
        output['oracle_all_ok'] = loom_oracle_ok
        output['oracle'] = loom_oracle_results
    else:
        output['oracle_all_ok'] = True
        output['oracle'] = []
    loom_ok = output['samples_all_ok'] and output['self_check_all_ok'] and (not loom_unexpected) and (not loom_missing) and (output['delta_skipped'] <= 0) and output['oracle_all_ok']
    output['ok'] = bool(loom_ok)
    output['verdict'] = 'PASS' if loom_ok else 'FAIL'
    output['finished_at'] = loom_time.time()
    loom_rp = loom_result_path or loom_reg.get('result_path')
    if loom_rp:
        try:
            loom_write_result(loom_rp, output)
        except Exception as loom_exc:
            output['result_write_error'] = repr(loom_exc)
    return output

# TODO(validate): the pass-report shape (sites=[{kind, br_ea, reason, self_check_ok,
# TODO(validate): SAFETY.md §11 wants byte-identical output *before vs after* the

__all__ = [export_binding for export_binding in ['LOOM_D', 'image_restore', 'loom_Any', 'loom_Callable', 'loom_Dict', 'loom_List', 'loom_Optional', 'loom_Tuple', 'loom_annotations', 'loom_json', 'loom_os', 'loom_run_regression', 'loom_time'] if export_binding in globals()]
