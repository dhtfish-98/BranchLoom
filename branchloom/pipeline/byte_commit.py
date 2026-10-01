"""
branchloom.pipeline.byte_commit — Phase 5: apply (or revert) the planned byte patches.

**This phase WRITES to the IDA database.** It is the only pipeline stage that
mutates code bytes, and it is deliberately gated behind ``dry_run=True`` by
default. The phase entry point also requires ``apply=True``. CLI byte writes
are available through ``run --apply`` with verification and rollback; the
standalone ``apply`` command previews plans only. Low-level Python callers must
provide their own verification and recovery flow.

Faithful port of the algorithm in
the private reference toolchain (``cff_apply_patches.py``)
(``apply`` / ``revert``), re-expressed against the target-agnostic
:class:`branchloom` interfaces:

  * The patch plan is loaded via :func:`branchloom.records.read_rewrites`
    (``records.ByteRewrite`` records, not a bespoke dict shape).
  * Every DB touch goes through the Tier-1 ``adapter`` (``loom_get_bytes`` /
    ``loom_patch_bytes`` / ``loom_reanalyze`` / ``loom_auto_wait`` / ``loom_read_input_bytes``),
    never ``ida_bytes`` directly, so this module is IDA-free at import time.
  * No absolute address, segment name or test vector is baked in.

What P5 adds over the reference
-------------------------------
1. **Batched by parent_fn.** Patches are grouped by their owning function and
   applied one batch at a time; each batch is re-analysed on its own so a
   partial/failed batch leaves the rest of the DB coherent.
2. **Pristine-first (SAFETY.md §10).** Before an *apply* batch writes anything,
   :func:`branchloom.integrity.image_restore.loom_restore_range` restores that batch's byte
   span to the on-disk pristine image. Every pass therefore starts from the
   single source of truth, so re-running is deterministic and idempotent and the
   strict-orig check below always compares against the plan's recorded original.
3. **Idempotency skip.** A patch whose current bytes already equal
   ``new_bytes_hex`` is skipped (already applied).
4. **Strict-orig verify -> loud SKIP on drift.** Unless disabled, a patch whose
   current bytes differ from the plan's ``orig_bytes_hex`` is *not* written; a
   loud warning is printed and the patch is skipped (the plan was generated
   against a different DB state and must be regenerated).

Revert (``revert`` / ``execute_stage(..., revert=True)``) restores every planned-patch
address to pristine bytes read straight from the on-disk input file — an
independent recovery path that ignores current DB state and any patch log.
"""
from __future__ import annotations as loom_annotations
import os as loom_os
from typing import Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from .. import records as LOOM_M
from ..integrity import image_restore as image_restore
__all__ = ['execute_stage', 'loom_apply', 'loom_revert']
LOOM_DEFAULT_PLAN_NAME = 'cff_patch_plan.json'

def loom_plan_path(loom_in_path: loom_Optional[str]) -> str:
    return loom_in_path if loom_in_path else LOOM_DEFAULT_PLAN_NAME

def loom_match_parent(loom_patch: LOOM_M.ByteRewrite, loom_parent_fn, bridge) -> bool:
    """True iff ``patch`` belongs to the requested ``parent_fn`` filter.

    ``parent_fn`` may be ``None`` (match all), an address (int or a ``0x``/decimal
    string, compared against ``loom_patch.loom_parent_fn``), or a function *name* (compared
    against the adapter's name for ``loom_patch.loom_parent_fn``). Supporting both keeps the
    filter usable whether the user thinks in addresses or symbols, without baking
    any target name in.
    """
    if loom_parent_fn is None:
        return True
    loom_want_ea: loom_Optional[int] = None
    if isinstance(loom_parent_fn, int):
        loom_want_ea = loom_parent_fn
    elif isinstance(loom_parent_fn, str):
        try:
            loom_want_ea = int(loom_parent_fn, 0)
        except ValueError:
            loom_want_ea = None
    if loom_want_ea is not None and loom_patch.loom_parent_fn is not None and (loom_patch.loom_parent_fn == loom_want_ea):
        return True
    if isinstance(loom_parent_fn, str) and loom_patch.loom_parent_fn is not None:
        try:
            loom_fa = bridge.loom_func_at(loom_patch.loom_parent_fn)
        except Exception:
            loom_fa = None
        if loom_fa is not None and loom_fa[1] == loom_parent_fn:
            return True
    return False

def loom_group_by_parent(loom_patches: loom_List[LOOM_M.ByteRewrite]) -> 'loom_List[loom_Tuple[loom_Optional[int], loom_List[LOOM_M.ByteRewrite]]]':
    """Group patches by ``parent_fn`` (an int EA, or ``None``), preserving order.

    Returns an ordered list of ``(parent_fn_ea, patches)`` batches sorted by the
    parent EA so the on-screen log is stable; ``None``-parent patches form their
    own trailing batch.
    """
    loom_buckets: loom_Dict[loom_Optional[int], loom_List[LOOM_M.ByteRewrite]] = {}
    for loom_p in loom_patches:
        loom_buckets.setdefault(loom_p.loom_parent_fn, []).append(loom_p)

    def loom_key(loom_k: loom_Optional[int]):
        return (1, 0) if loom_k is None else (0, loom_k)
    return [(loom_k, loom_buckets[loom_k]) for loom_k in sorted(loom_buckets.keys(), key=loom_key)]

def loom_batch_span(loom_batch: loom_List[LOOM_M.ByteRewrite]) -> loom_Tuple[int, int]:
    """[lo, hi) byte span covering every patch in ``batch`` (for pristine restore)."""
    loom_lo = min((loom_p.location for loom_p in loom_batch))
    loom_hi = max((loom_p.location + max(loom_p.span, 4) for loom_p in loom_batch))
    return (loom_lo, loom_hi)

def loom_reanalyze_batch(bridge, loom_parent_ea: loom_Optional[int], loom_batch: loom_List[LOOM_M.ByteRewrite]) -> None:
    """Re-analyse the function(s) touched by ``batch`` so the CFG reflects the new
    B / B.cond edges."""
    loom_starts = set()
    if loom_parent_ea is not None:
        loom_starts.add(loom_parent_ea)
    for loom_p in loom_batch:
        try:
            loom_fa = bridge.loom_func_at(loom_p.location)
        except Exception:
            loom_fa = None
        if loom_fa is not None:
            loom_starts.add(loom_fa[0])
    for loom_s in sorted(loom_starts):
        bridge.loom_reanalyze(loom_s)

def loom_apply(bridge, settings, loom_in_path: loom_Optional[str]=None, *, loom_parent_fn=None, loom_dry_run: bool=True, loom_strict_orig_check: loom_Optional[bool]=None, loom_pristine_first: bool=True) -> loom_Dict:
    """Apply the planned patches, batched by parent function.

    Parameters
    ----------
    adapter : Tier-1 IDA boundary module (``branchloom.database.bridge``).
    cfg : :class:`branchloom.settings.AnalysisSettings` — supplies ``strict_orig_check``.
    in_path : path to ``cff_patch_plan.json`` (a ``records.write_rewrites`` file).
    parent_fn : optional filter (address or function name); apply only its patches.
    dry_run : if True (default) log intentions and make **no** DB changes.
    strict_orig_check : override ``settings.loom_strict_orig_check``; when None, use config.
    pristine_first : restore each batch's span to on-disk pristine before writing
        (apply mode only). Default True (SAFETY.md §10).
    """
    loom_strict = settings.loom_strict_orig_check if loom_strict_orig_check is None else bool(loom_strict_orig_check)
    if not loom_dry_run:
        if settings.loom_mode not in ('linear', 'full'):
            raise ValueError('Byte patches require linear or full mode; switch is metadata-only')
        if not (settings.loom_verifier or {}).get('known_vectors'):
            raise ValueError('Byte patches require configured verifier known_vectors')
    loom_patches = LOOM_M.read_rewrites(loom_plan_path(loom_in_path))
    loom_patches = [loom_p for loom_p in loom_patches if loom_match_parent(loom_p, loom_parent_fn, bridge)]
    loom_batches = loom_group_by_parent(loom_patches)
    print('[p5] %d patches selected in %d parent-batch(es) (dry_run=%s, strict=%s, pristine_first=%s, parent_fn=%r)' % (len(loom_patches), len(loom_batches), loom_dry_run, loom_strict, loom_pristine_first, loom_parent_fn))
    loom_applied = 0
    loom_dup = 0
    loom_mismatch = 0
    loom_restored = 0
    loom_by_parent: loom_Dict[str, loom_Dict[str, int]] = {}
    loom_reanalyzed = set()
    for loom_parent_ea, loom_batch in loom_batches:
        loom_pkey = LOOM_M.loom_hx_value(loom_parent_ea) if loom_parent_ea is not None else '?'
        loom_stat = loom_by_parent.setdefault(loom_pkey, {'applied': 0, 'duplicate': 0, 'mismatch': 0, 'restored': 0})
        if not loom_dry_run and loom_pristine_first:
            loom_lo, loom_hi = loom_batch_span(loom_batch)
            try:
                loom_n_value = image_restore.loom_restore_range(bridge, loom_lo, loom_hi)
            except ValueError as loom_exc:
                print('  !! PRISTINE-FAIL for %s [%s,%s): %s -- SKIP BATCH' % (loom_pkey, LOOM_M.loom_hx_value(loom_lo), LOOM_M.loom_hx_value(loom_hi), loom_exc))
                continue
            loom_restored += loom_n_value
            loom_stat['restored'] += loom_n_value
        for loom_p in loom_batch:
            loom_cur = bridge.loom_get_bytes(loom_p.location, loom_p.span) or b''
            loom_cur_hex = loom_cur.hex()
            loom_new_hex = loom_p.loom_new_bytes_hex.lower()
            loom_orig_hex = (loom_p.loom_orig_bytes_hex or '').lower()
            if loom_cur_hex == loom_new_hex:
                loom_dup += 1
                loom_stat['duplicate'] += 1
                continue
            if loom_strict and loom_orig_hex and (loom_cur_hex != loom_orig_hex):
                print('  !! DRIFT at %s: plan orig=%s but DB has %s -- LOUD SKIP (%s, %s); regenerate the plan against the current DB' % (LOOM_M.loom_hx_value(loom_p.location), loom_orig_hex, loom_cur_hex, loom_p.loom_reason, loom_pkey))
                loom_mismatch += 1
                loom_stat['mismatch'] += 1
                continue
            if loom_dry_run:
                print('  [dry] %s: %s -> %s  (%s, %s)' % (LOOM_M.loom_hx_value(loom_p.location), loom_cur_hex, loom_new_hex, loom_p.loom_reason, loom_pkey))
                continue
            bridge.loom_patch_bytes(loom_p.location, bytes.fromhex(loom_new_hex))
            bridge.loom_make_code(loom_p.location)
            loom_applied += 1
            loom_stat['applied'] += 1
        if not loom_dry_run and loom_stat['applied']:
            loom_reanalyze_batch(bridge, loom_parent_ea, loom_batch)
            loom_reanalyzed.add(loom_parent_ea)
    if not loom_dry_run:
        bridge.loom_auto_wait()
    print('[p5] applied=%d duplicate=%d drift_skipped=%d restored_dwords=%d reanalyzed_fns=%d' % (loom_applied, loom_dup, loom_mismatch, loom_restored, len(loom_reanalyzed)))
    return {'dry_run': loom_dry_run, 'selected': len(loom_patches), 'batches': len(loom_batches), 'applied': loom_applied, 'duplicate': loom_dup, 'mismatch': loom_mismatch, 'restored_dwords': loom_restored, 'reanalyzed_fns': len(loom_reanalyzed), 'by_parent': loom_by_parent}

def loom_revert(bridge, settings, loom_in_path: loom_Optional[str]=None, *, loom_parent_fn=None) -> loom_Dict:
    """Restore every planned-patch address to pristine on-disk bytes.

    Reads the pristine bytes straight from the input file via
    ``bridge.loom_read_input_bytes`` (independent of the current DB state and of any
    patch log), writes them back, then re-analyses each touched function. This is
    the second, log-free recovery path required by SAFETY.md §10.
    """
    loom_patches = LOOM_M.read_rewrites(loom_plan_path(loom_in_path))
    loom_patches = [loom_p for loom_p in loom_patches if loom_match_parent(loom_p, loom_parent_fn, bridge)]
    loom_reverted = 0
    loom_short = 0
    loom_touched: loom_Dict[loom_Optional[int], loom_List[LOOM_M.ByteRewrite]] = {}
    for loom_p in loom_patches:
        loom_orig = bridge.loom_read_input_bytes(loom_p.location, loom_p.span)
        if not loom_orig or len(loom_orig) < loom_p.span:
            print('  !! pristine read short at %s (got %d of %d) -- skip' % (LOOM_M.loom_hx_value(loom_p.location), 0 if not loom_orig else len(loom_orig), loom_p.span))
            loom_short += 1
            continue
        bridge.loom_patch_bytes(loom_p.location, bytes(loom_orig))
        bridge.loom_make_code(loom_p.location)
        loom_reverted += 1
        loom_touched.setdefault(loom_p.loom_parent_fn, []).append(loom_p)
    for loom_parent_ea, loom_batch in loom_touched.items():
        loom_reanalyze_batch(bridge, loom_parent_ea, loom_batch)
    bridge.loom_auto_wait()
    print('[p5] reverted %d patch site(s) to pristine (%d short reads)' % (loom_reverted, loom_short))
    return {'reverted': loom_reverted, 'short_reads': loom_short, 'reanalyzed_fns': len(loom_touched)}

def execute_stage(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, **loom_kw) -> loom_Dict:
    """Tier-3 entry point. ``kw`` honoured:

      * ``revert=True``          -> delegate to :func:`revert`.
      * ``parent_fn``            -> per-parent filter (address or name).
      * ``apply=True`` and ``dry_run=False`` are both required to write patches.
      * ``strict_orig_check``    -> override ``settings.loom_strict_orig_check``.
      * ``pristine_first`` (default True)

    ``out_path`` is unused by P5 (the DB *is* the output); it is accepted for a
    uniform phase signature.
    """
    if loom_kw.get('revert'):
        return loom_revert(bridge, settings, loom_in_path, loom_parent_fn=loom_kw.get('parent_fn'))
    return loom_apply(bridge, settings, loom_in_path, loom_parent_fn=loom_kw.get('parent_fn'), loom_dry_run=not (loom_kw.get('apply') is True and loom_kw.get('dry_run') is False), loom_strict_orig_check=loom_kw.get('strict_orig_check'), loom_pristine_first=loom_kw.get('pristine_first', True))

# TODO(validate): default artifact path is a convention, not read from AnalysisSettings
