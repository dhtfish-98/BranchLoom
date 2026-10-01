"""Shared plumbing every subcommand handler uses.

Argument coercion, the write-intent rule, the uniform phase keyword bundle, the
config overrides, the lazy IDA boundary and the two range helpers. Nothing here
imports ``idaapi`` at module load — :func:`loom_open_adapter` is the only door to the
database and it is called from inside a handler, never at import time.
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
import json as loom_json
import os as loom_os
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from .. import settings as LOOM_CFG
__all__ = ['loom_parse_int', 'loom_dump_json', 'loom_open_adapter', 'loom_will_write', 'loom_phase_kwargs', 'loom_apply_overrides', 'loom_count_drift', 'loom_scoped_ranges']

def loom_parse_int(loom_value: loom_Optional[str]) -> loom_Optional[int]:
    """Parse a CLI integer that may be decimal or ``0x``-hex; ``None`` passes through."""
    if loom_value is None:
        return None
    if isinstance(loom_value, int):
        return loom_value
    loom_s = str(loom_value).strip()
    if not loom_s:
        return None
    return int(loom_s, 0)

def loom_dump_json(location_path: str, loom_obj: loom_Any) -> None:
    """Write ``obj`` as indented JSON, creating the parent directory if needed."""
    loom_d_value = loom_os.path.dirname(location_path)
    if loom_d_value:
        loom_os.makedirs(loom_d_value, exist_ok=True)
    with open(location_path, 'w', encoding='utf-8') as stream:
        loom_json.dump(loom_obj, stream, indent=2, default=str)

def loom_open_adapter():
    """Import and return the IDA adapter module (the only idaapi importer).

    Imported lazily so the CLI stays importable — and ``py_compile``-able — outside
    a live IDA. Any command that touches the database calls this.
    """
    from ..database import bridge as bridge
    return bridge

def loom_will_write(options: loom_argparse.Namespace) -> bool:
    """A mutating command writes only when ``--apply`` is set and ``--dry-run`` isn't.

    ``--dry-run`` always wins so a preview is never destructive.
    """
    return bool(getattr(options, 'apply', False)) and (not bool(getattr(options, 'dry_run', False)))

def loom_phase_kwargs(options: loom_argparse.Namespace) -> loom_Dict[str, loom_Any]:
    """Uniform keyword bundle handed to every phase ``execute_stage()``.

    The Tier-3 contract is ``execute_stage(adapter, cfg, in_path=None, out_path=None, **kw)`` so
    every phase absorbs the keys it does not use. We surface the write intent, the
    resolution source and the optional parent-fn scope; the phase reads ``cfg`` for
    mode / strict-orig / segments.
    """
    return {'apply': loom_will_write(options), 'dry_run': not loom_will_write(options), 'source': getattr(options, 'source', None), 'parent_fn': loom_parse_int(getattr(options, 'parent_fn', None))}

def loom_apply_overrides(settings: 'LOOM_CFG.AnalysisSettings', options: loom_argparse.Namespace) -> None:
    """Fold ``--mode`` / ``--no-strict`` CLI overrides into the loaded config.

    ``--mode linear|full`` re-checks the config gate: those modes are refused
    unless known I/O vectors are configured. Configuring vectors does not prove
    that a rewrite has equivalent behaviour.
    """
    loom_mode = getattr(options, 'mode', None)
    if loom_mode:
        if loom_mode not in LOOM_CFG.LOOM_VALID_MODES:
            raise LOOM_CFG.SettingsFault('mode must be one of %s, got %r' % (LOOM_CFG.LOOM_VALID_MODES, loom_mode))
        if loom_mode in ('linear', 'full'):
            if not (settings.loom_verifier or {}).get('known_vectors'):
                raise LOOM_CFG.SettingsFault('--mode=%r rewrites instruction bytes and requires verifier.known_vectors. Those vectors are an experimental check, not a proof of equivalent behaviour. Use --mode=switch for a metadata-only run.' % loom_mode)
        settings.loom_mode = loom_mode
    if getattr(options, 'no_strict', False):
        settings.loom_strict_orig_check = False

def loom_count_drift(bridge, loom_start: int, loom_end: int) -> int:
    """How many dwords in ``[start, end)`` differ from the pristine on-disk image.

    Read-only preview used by ``revert --dry-run`` (mirrors the diff loop in
    :func:`branchloom.integrity.image_restore.loom_restore_range` without writing anything).
    """
    loom_start &= ~3
    loom_end = loom_end + 3 & ~3
    if loom_end <= loom_start:
        return 0
    loom_orig = bridge.loom_read_input_bytes(loom_start, loom_end - loom_start)
    if not loom_orig or len(loom_orig) < loom_end - loom_start:
        return 0
    loom_cnt_value = 0
    address = loom_start
    cursor = 0
    while address < loom_end:
        loom_want = int.from_bytes(loom_orig[cursor:cursor + 4], 'little')
        if bridge.loom_get_dword(address) != loom_want:
            loom_cnt_value += 1
        address += 4
        cursor += 4
    return loom_cnt_value

def loom_scoped_ranges(bridge, settings, loom_parent_fn: loom_Optional[int]) -> loom_List[loom_Tuple[int, int, str]]:
    """Exec ranges to operate on, narrowed to the segment containing ``parent_fn``.

    ``apply``/``revert`` are per parent function (SAFETY.md §10). Because the
    pristine restore only rewrites the dwords that actually drifted, restoring the
    *segment* that contains the function is equivalent-in-effect to restoring just
    the function (untouched code is already byte-identical, so it costs no writes),
    while needing no function-end query the thin adapter does not expose.
    TODO(validate): for ``clean`` the segment scope is a genuine superset of one
    function; pass an explicit segment ``range`` in the config to narrow it.
    """
    loom_ranges = list(bridge.loom_exec_segments(settings))
    if loom_parent_fn is None:
        return loom_ranges
    loom_hit = [(loom_s, loom_e, loom_nm_value) for loom_s, loom_e, loom_nm_value in loom_ranges if loom_s <= loom_parent_fn < loom_e]
    return loom_hit or loom_ranges
