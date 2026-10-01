"""
branchloom.target_sources.observed_routes — the observed-target cross-check gate.

A trace is a JSON document of the shape produced by the Part3 reference
``trace_br_targets.py``::

    { "token": "d49d1c4e",
      "sites": { "0x11b0e0": { "0x11b1d0": 42, "0x11b204": 7 }, ... } }

i.e. ``sites`` maps each indirect-branch PC (``BR Xn``) to the concrete targets
it was observed taking, with hit counts. This module loads one *or more* such
traces (globbed and/or command-produced), unions the observed target set per
branch PC across every input, and grades a statically-resolved target against
that union — exactly the ``_load_br_traces`` / observed-set logic of the
reference ``cff_resolve.py``:

  * ``OK``          — the static target is among the observed targets.
  * ``MISMATCH``    — the branch PC was observed, but never taking the static
                      target (leave for manual review; do not patch).
  * ``UNVERIFIED``  — the branch PC never appeared in any trace (static-only).

It also exposes :func:`loom_single_target`, the "patchable" test from the reference
trace summary: a branch PC observed taking exactly one target.

IDA-free: consumes only the AnalysisSettings (``settings.loom_trace``) and the filesystem/subprocess.
"""
from __future__ import annotations as loom_annotations
import glob as loom_glob
import json as loom_json
import shlex as loom_shlex
import subprocess as loom_subprocess
from typing import Any as loom_Any, Dict as loom_Dict, Iterable as loom_Iterable, List as loom_List, Optional as loom_Optional, Set as loom_Set
__all__ = ['loom_load_traces', 'loom_single_target', 'loom_verdict']

def loom_iter_target_keys(loom_hits: loom_Any) -> loom_Iterable[str]:
    """Yield the target keys from a ``sites[pc]`` value.

    The reference format is ``{target_hex: count}`` (a mapping); a bare list of
    target hex strings is tolerated too so hand-written or count-less traces work.
    """
    if isinstance(loom_hits, dict):
        return loom_hits.keys()
    if isinstance(loom_hits, (list, tuple, set)):
        return [str(loom_t_value) for loom_t_value in loom_hits]
    return []

def loom_fold_doc(loom_doc: loom_Dict[str, loom_Any], loom_union: loom_Dict[int, loom_Set[int]]) -> None:
    """Fold one trace document's ``sites`` into the running per-PC union."""
    loom_sites = loom_doc.get('sites', {}) or {}
    for loom_pc_s, loom_hits in loom_sites.items():
        location = int(loom_pc_s, 16) if isinstance(loom_pc_s, str) else int(loom_pc_s)
        loom_bucket = loom_union.setdefault(location, set())
        for loom_t_s in loom_iter_target_keys(loom_hits):
            loom_bucket.add(int(loom_t_s, 16) if isinstance(loom_t_s, str) else int(loom_t_s))

def loom_load_file_docs(loom_pattern: str) -> loom_List[loom_Dict[str, loom_Any]]:
    loom_docs: loom_List[loom_Dict[str, loom_Any]] = []
    for location_path in sorted(loom_glob.glob(loom_pattern)):
        with open(location_path, 'r', encoding='utf-8') as stream:
            loom_docs.append(loom_json.load(stream))
    return loom_docs

def loom_load_command_docs(settings) -> loom_List[loom_Dict[str, loom_Any]]:
    """Run ``settings.loom_trace['command']`` and parse its stdout as trace JSON.

    stdout is parsed as either a single trace document or a JSON array of them.
    A ``{entry}`` placeholder in the command is substituted with the verifier's
    configured entry (``settings.loom_verifier['entry']``) when present, so the same
    template drives both tracing and emulation.
    """
    loom_tcfg = getattr(settings, 'loom_trace', None) or {}
    loom_cmd = loom_tcfg.get('command') or ''
    if not loom_cmd:
        return []
    loom_entry_value = ''
    loom_vcfg = getattr(settings, 'loom_verifier', None) or {}
    loom_e = loom_vcfg.get('entry')
    if loom_e is not None:
        loom_entry_value = f'0x{loom_e:x}' if isinstance(loom_e, int) else str(loom_e)
    tokens = loom_shlex.split(loom_cmd.format(entry=loom_entry_value))
    loom_proc = loom_subprocess.run(tokens, stdout=loom_subprocess.PIPE, stderr=loom_subprocess.PIPE, check=False)
    if loom_proc.returncode != 0:
        loom_err_value = (loom_proc.stderr or b'').decode('utf-8', 'replace').strip()
        raise RuntimeError(f'trace command exited {loom_proc.returncode}: {tokens!r}' + (f'\n{loom_err_value}' if loom_err_value else ''))
    loom_parsed = loom_json.loads((loom_proc.stdout or b'').decode('utf-8', 'replace') or '{}')
    if isinstance(loom_parsed, list):
        return [loom_d_value for loom_d_value in loom_parsed if isinstance(loom_d_value, dict)]
    return [loom_parsed] if isinstance(loom_parsed, dict) else []

def loom_load_traces(settings) -> loom_Dict[int, loom_Set[int]]:
    """Load every configured trace and return ``{br_pc: union-of-targets}``.

    ``settings.loom_trace['source']`` selects the input(s):

      * ``"file"`` (default) — glob ``settings.loom_trace['path']`` and load each match.
      * ``"command"`` — run ``settings.loom_trace['command']`` and parse its stdout.

    Targets are unioned per branch PC across *all* inputs (multiple traces /
    tokens strengthen the cross-check exactly as the reference merged its two
    ``br_targets_*.json`` runs). An absent/empty source yields ``{}`` — callers
    then treat every static resolution as ``UNVERIFIED``.
    """
    loom_tcfg = getattr(settings, 'loom_trace', None) or {}
    loom_source = (loom_tcfg.get('source') or 'file').strip().lower()
    loom_docs: loom_List[loom_Dict[str, loom_Any]] = []
    if loom_source == 'file':
        loom_pattern = loom_tcfg.get('path')
        if loom_pattern:
            loom_docs = loom_load_file_docs(loom_pattern)
    elif loom_source == 'command':
        loom_docs = loom_load_command_docs(settings)
    else:
        raise ValueError(f"unknown trace.source {loom_source!r}; expected 'file' or 'command'")
    loom_union: loom_Dict[int, loom_Set[int]] = {}
    for loom_doc in loom_docs:
        loom_fold_doc(loom_doc, loom_union)
    return loom_union

def loom_single_target(loom_traces: loom_Dict[int, loom_Set[int]], loom_br_pc: int) -> loom_Optional[int]:
    """Return the sole observed target for ``br_pc``, or ``None``.

    ``None`` when the branch PC was never traced or took more than one target —
    i.e. only a single-observed-target branch is directly "patchable" from the
    trace alone (the reference's single-target/multi-target split).
    """
    loom_observed = loom_traces.get(loom_br_pc)
    if loom_observed and len(loom_observed) == 1:
        return next(iter(loom_observed))
    return None

def loom_verdict(loom_static_target: loom_Optional[int], loom_br_pc: int, loom_traces: loom_Dict[int, loom_Set[int]]) -> str:
    """Grade a statically-resolved ``static_target`` against the traces.

    Returns one of ``"OK"`` / ``"UNVERIFIED"`` / ``"MISMATCH"``:

      * ``UNVERIFIED`` — ``br_pc`` never appears in any trace (no observation to
        check against), or ``static_target`` is ``None`` (nothing to compare).
      * ``OK``         — ``static_target`` is in the observed target set.
      * ``MISMATCH``   — the branch was observed but never taking that target.
    """
    loom_observed = loom_traces.get(loom_br_pc)
    if not loom_observed:
        return 'UNVERIFIED'
    if loom_static_target is None:
        return 'UNVERIFIED'
    return 'OK' if loom_static_target in loom_observed else 'MISMATCH'

# TODO(validate): only the {entry} placeholder is substituted; extend the
# TODO(validate): the caller normally reports an unresolved/invalid target
