"""
branchloom.pipeline.rewrite_design — Phase 4: synthesise a same-size byte-patch plan.

For every resolution whose targets all survived Phase-3 grading (``OK`` or
``UNVERIFIED``; ``MISMATCH`` and ``INVALID`` are dropped) this phase emits a
concrete, read-only patch plan that collapses the two-level dispatch into a direct
branch. Every patch is 4 bytes replacing 4 bytes, so the plan is always same-size
and the original instruction stream never grows or shrinks.

  ``CONST`` (state ``K`` -> single target ``T``)
      NOP the dead state-machine plumbing (the MOVZ/MOVN that produced ``K``, the
      ``STR`` to the state slot, the state reload, and the two dispatch loads) and
      overwrite the ``BR`` with ``B T`` (``LOOM_E.emit_jump``). Unconditional, so nothing is
      conditionally skipped and no hazard gate is needed.

  ``COND2`` (``CSEL`` of ``c1`` -> ``T_then`` / ``c2`` -> ``T_else`` under ``cond``)
      NOP the ``CSEL`` / ``STR`` / index-load plumbing, put ``B.<cond> T_then`` in
      the freed target-``LDR`` slot (``LOOM_E.emit_conditional_jump``) and ``B T_else`` in the ``BR``
      slot (``LOOM_E.emit_jump``). Because collapsing makes the taken path skip whatever sits
      between the freed ``LDR`` slot and the ``BR``, the site is **gated by**
      :func:`branchloom.integrity.clobber_scan.loom_a_path_hazard`: if that gap holds any
      externally-observable effect the site is refused (``loom_a_path_hazard`` returns
      ``None`` for the usual adjacent, empty gap, so the common case is allowed).

Each :class:`~branchloom.records.ByteRewrite` records its original bytes
(``bridge.loom_get_bytes``) and its new bytes (``LOOM_E.opcode_bytes``) so Phase-5 can
strict-orig verify before writing. The plan is pure JSON — **no DB writes here**.

Faithful port of ``cff_plan_patches.py::run`` from
the private reference toolchain — re-expressed
against the locked seams: encoders from :mod:`branchloom.arm_words.emission`, the hazard
gate from :mod:`branchloom.integrity.clobber_scan`, slot EAs read from the Phase-1
``RouteHub`` record (``ldr_tgt_ea`` / ``ldrsw_idx_ea`` / ``state_load_ea``)
instead of the reference's ``br_ea - 4`` / ``- 8`` arithmetic, and no absolute
address / segment name / test vector baked in.
"""
from __future__ import annotations as loom_annotations
from typing import Any as loom_Any, Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from . import destination_lookup as LOOM_P3
from .. import records as LOOM_M
from ..arm_words import recognition as LOOM_D
from ..arm_words import emission as LOOM_E
from ..dispatch_shapes import indexed_routes as indexed_routes
from ..integrity.clobber_scan import loom_a_path_hazard as loom_a_path_hazard
LOOM__MASK32 = 4294967295

def loom_make_reader(bridge) -> loom_Callable[[int], loom_Optional[int]]:

    def loom_read_value(address: int) -> loom_Optional[int]:
        if address < 0:
            return None
        try:
            return bridge.loom_get_dword(address) & LOOM__MASK32
        except Exception:
            return None
    return loom_read_value

def loom_mk_patch(bridge, location: int, opcode: int, loom_reason: str, loom_r: LOOM_M.DestinationSet, loom_via_state: loom_Optional[int], loom_via_case: loom_Optional[str], equivalence: loom_Optional[str], loom_target_ea: loom_Optional[int]) -> LOOM_M.ByteRewrite:
    """Build one same-size :class:`records.ByteRewrite`, capturing orig + new bytes."""
    loom_orig = bridge.loom_get_bytes(location, 4) or b''
    loom_new = LOOM_E.opcode_bytes(opcode)
    return LOOM_M.ByteRewrite(location=location, span=4, loom_orig_bytes_hex=loom_orig.hex(), loom_new_bytes_hex=loom_new.hex(), loom_reason=loom_reason, loom_parent_fn=loom_r.loom_parent_fn_ea, loom_dispatcher_pc=loom_r.loom_dispatcher_br_ea, loom_via_state=loom_via_state, loom_via_case=loom_via_case, equivalence=equivalence, loom_target_ea=loom_target_ea)

def loom_droppable(loom_entries: loom_List[LOOM_M.DestinationChoice]) -> bool:
    """True iff any entry is INVALID/MISMATCH or lacks a target (drop the site)."""
    for loom_e in loom_entries:
        if loom_e.equivalence in ('INVALID', 'MISMATCH'):
            return True
        if loom_e.destination is None:
            return True
    return False

def loom_load_inputs(bridge, settings, loom_in_path: loom_Optional[str], loom_kw: loom_Dict[str, loom_Any]) -> loom_Tuple[loom_List[LOOM_M.DestinationSet], loom_Dict[int, LOOM_M.IncomingBlock], loom_Dict[int, LOOM_M.RouteHub]]:
    """Return ``(resolutions, pred_by_br, disp_by_br)``.

    Resolutions come from ``in_path`` (Phase-3 artifact) or are recomputed via
    :func:`destination_lookup.loom_resolve_all`. Predecessors (needed for the COND2 ``csel_ea``)
    and dispatchers (needed for the exact slot EAs) come from ``kw['preds_path']`` /
    ``kw['disp_path']`` when given, else are recomputed from the census. All three
    are keyed by the dispatcher ``BR`` EA, which is deterministic across the
    detector so the keys line up.
    """
    loom_preds_path = loom_kw.get('preds_path')
    loom_disp_path_value = loom_kw.get('disp_path')
    loom_source = loom_kw.get('source') or 'trace'
    loom_preds = LOOM_P3.loom_build_predecessors(bridge, settings, loom_preds_path)
    if loom_in_path:
        loom_resolutions = LOOM_M.read_destinations(loom_in_path)
    else:
        loom_resolutions, loom_stats = LOOM_P3.loom_resolve_all(bridge, settings, loom_preds, loom_source=loom_source)
    if loom_disp_path_value:
        loom_disps = LOOM_M.read_hubs(loom_disp_path_value)
    else:
        loom_disps = indexed_routes.loom_find_dispatchers(bridge, settings)
    loom_pred_by_br = {loom_p.loom_dispatcher_br_ea: loom_p for loom_p in loom_preds}
    loom_disp_by_br = {loom_d_value.loom_br_ea: loom_d_value for loom_d_value in loom_disps}
    return (loom_resolutions, loom_pred_by_br, loom_disp_by_br)

def loom_plan_const(bridge, loom_r: LOOM_M.DestinationSet, loom_disp: loom_Optional[LOOM_M.RouteHub], loom_str_pc: loom_Optional[int]) -> loom_Tuple[loom_List[LOOM_M.ByteRewrite], loom_Optional[str]]:
    """Plan the CONST collapse. Returns ``(patches, skip_reason)``."""
    loom_e = loom_r.loom_entries[0]
    destination = loom_e.destination
    loom_br_pc = loom_r.loom_dispatcher_br_ea
    loom_b_word = LOOM_E.emit_jump(loom_br_pc, destination)
    if loom_b_word is None:
        return ([], 'NO_ENC')
    loom_ldr_tgt_pc = loom_disp.loom_ldr_tgt_ea if loom_disp and loom_disp.loom_ldr_tgt_ea is not None else loom_br_pc - 4
    loom_ldrsw_idx_pc = loom_disp.loom_ldrsw_idx_ea if loom_disp and loom_disp.loom_ldrsw_idx_ea is not None else loom_br_pc - 8
    loom_state_load_pc = loom_disp.loom_state_load_ea if loom_disp else None
    loom_prod_pc = loom_r.loom_pred_start_ea if loom_r.loom_pred_start_ea is not None else loom_str_pc - 4 if loom_str_pc is not None else None
    loom_nop_slots: loom_List[loom_Tuple[int, str]] = []
    if loom_prod_pc is not None:
        loom_nop_slots.append((loom_prod_pc, 'CONST-nop-movz'))
    if loom_str_pc is not None:
        loom_nop_slots.append((loom_str_pc, 'CONST-nop-str'))
    loom_nop_slots.append((loom_ldrsw_idx_pc, 'CONST-nop-idx-ldrsw'))
    loom_nop_slots.append((loom_ldr_tgt_pc, 'CONST-nop-tgt-ldr'))
    if loom_state_load_pc is not None:
        loom_nop_slots.append((loom_state_load_pc, 'CONST-nop-state-load'))
    loom_patches = [loom_mk_patch(bridge, location, LOOM_E.LOOM_ARM64_NOP, loom_reason, loom_r, loom_e.loom_state, None, loom_e.equivalence, None) for location, loom_reason in loom_nop_slots]
    loom_patches.append(loom_mk_patch(bridge, loom_br_pc, loom_b_word, 'CONST-branch', loom_r, loom_e.loom_state, None, loom_e.equivalence, destination))
    return (loom_patches, None)

def loom_plan_cond2(bridge, loom_r: LOOM_M.DestinationSet, loom_disp: loom_Optional[LOOM_M.RouteHub], loom_pred: loom_Optional[LOOM_M.IncomingBlock], loom_str_pc: loom_Optional[int], loom_read_value: loom_Callable[[int], loom_Optional[int]]) -> loom_Tuple[loom_List[LOOM_M.ByteRewrite], loom_Optional[str]]:
    """Plan the COND2 collapse (hazard-gated). Returns ``(patches, skip_reason)``."""
    loom_e_then, loom_e_else = (loom_r.loom_entries[0], loom_r.loom_entries[1])
    loom_tgt_then, loom_tgt_else = (loom_e_then.destination, loom_e_else.destination)
    loom_br_pc = loom_r.loom_dispatcher_br_ea
    loom_cond = loom_e_then.loom_cond
    loom_cnum = loom_cond if isinstance(loom_cond, int) else LOOM_D.loom_cond_num(loom_cond) if loom_cond else None
    if loom_cnum is None:
        return ([], 'OTHER')
    loom_ldr_tgt_pc = loom_disp.loom_ldr_tgt_ea if loom_disp and loom_disp.loom_ldr_tgt_ea is not None else loom_br_pc - 4
    loom_ldrsw_idx_pc = loom_disp.loom_ldrsw_idx_ea if loom_disp and loom_disp.loom_ldrsw_idx_ea is not None else loom_br_pc - 8
    loom_state_load_pc = loom_disp.loom_state_load_ea if loom_disp else None
    loom_hz = loom_a_path_hazard(loom_read_value, loom_ldr_tgt_pc + 4, loom_br_pc)
    if loom_hz is not None:
        return ([], 'HAZARD')
    loom_bc_word = LOOM_E.emit_conditional_jump(loom_ldr_tgt_pc, loom_tgt_then, loom_cnum)
    loom_b_word = LOOM_E.emit_jump(loom_br_pc, loom_tgt_else)
    if loom_bc_word is None or loom_b_word is None:
        return ([], 'NO_ENC')
    loom_det = (loom_pred.loom_class_detail if loom_pred else {}) or {}
    loom_csel_ea = loom_det.get('csel_ea')
    loom_csel_pc = LOOM_M.loom_unhx(loom_csel_ea) if loom_csel_ea is not None else loom_str_pc - 4 if loom_str_pc is not None else None
    loom_nop_slots: loom_List[loom_Tuple[int, str]] = []
    if loom_csel_pc is not None:
        loom_nop_slots.append((loom_csel_pc, 'COND2-nop-csel'))
    if loom_str_pc is not None:
        loom_nop_slots.append((loom_str_pc, 'COND2-nop-str'))
    loom_nop_slots.append((loom_ldrsw_idx_pc, 'COND2-nop-idx-ldrsw'))
    if loom_state_load_pc is not None:
        loom_nop_slots.append((loom_state_load_pc, 'COND2-nop-state-load'))
    loom_patches = [loom_mk_patch(bridge, location, LOOM_E.LOOM_ARM64_NOP, loom_reason, loom_r, None, None, loom_e_then.equivalence, None) for location, loom_reason in loom_nop_slots]
    loom_patches.append(loom_mk_patch(bridge, loom_ldr_tgt_pc, loom_bc_word, 'COND2-bcond', loom_r, loom_e_then.loom_state, 'then', loom_e_then.equivalence, loom_tgt_then))
    loom_patches.append(loom_mk_patch(bridge, loom_br_pc, loom_b_word, 'COND2-b', loom_r, loom_e_else.loom_state, 'else', loom_e_else.equivalence, loom_tgt_else))
    return (loom_patches, None)

def execute_stage(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, **loom_kw) -> loom_Dict[str, loom_Any]:
    """Synthesise the same-size patch plan from the Phase-3 resolutions.

    Parameters
    ----------
    adapter :
        The Tier-1 IDA boundary (needs ``loom_get_dword`` / ``loom_get_bytes``; upstream
        recompute additionally needs ``exec_segments`` / ``loom_func_at``).
    cfg :
        A loaded :class:`~branchloom.settings.AnalysisSettings`.
    in_path :
        Path to the ``resolutions`` JSON produced by Phase 3. When ``None`` the
        resolutions are recomputed on the fly (P1 -> P2 -> P3, ``kw['source']``).
    out_path :
        Where to write the ``patch_plan`` JSON. When ``None`` the plan is computed
        and summarised but not persisted.
    kw :
        ``preds_path`` / ``disp_path`` — optional artifact paths for the Phase-2
        predecessors and Phase-1 dispatchers (recomputed when absent);
        ``source`` — verdict oracle for the recompute path (default ``'trace'``).

    Returns
    -------
    dict
        A small summary: patch count, patchable-dispatcher count, per-parent
        tallies and the skip reasons.
    """
    loom_resolutions, loom_pred_by_br, loom_disp_by_br = loom_load_inputs(bridge, settings, loom_in_path, loom_kw)
    loom_read_value = loom_make_reader(bridge)
    loom_patches: loom_List[LOOM_M.ByteRewrite] = []
    loom_skipped = {'MISMATCH': 0, 'INVALID': 0, 'NO_ENC': 0, 'HAZARD': 0, 'OTHER': 0}
    loom_by_parent: loom_Dict[str, loom_Dict[str, int]] = {}
    loom_accepted = 0
    for loom_r in loom_resolutions:
        loom_entries = loom_r.loom_entries
        if loom_droppable(loom_entries):
            for loom_e in loom_entries:
                if loom_e.equivalence == 'MISMATCH':
                    loom_skipped['MISMATCH'] += 1
                elif loom_e.equivalence == 'INVALID':
                    loom_skipped['INVALID'] += 1
            continue
        loom_br_pc = loom_r.loom_dispatcher_br_ea
        loom_disp = loom_disp_by_br.get(loom_br_pc)
        loom_pred = loom_pred_by_br.get(loom_br_pc)
        loom_str_pc = loom_r.loom_str_ea if loom_r.loom_str_ea is not None else loom_pred.loom_str_ea if loom_pred else None
        loom_parent_key = loom_r.loom_parent_fn_name or LOOM_M.loom_hx_value(loom_r.loom_parent_fn_ea) or '?'
        loom_bp = loom_by_parent.setdefault(loom_parent_key, {'total': 0, 'patchable': 0, 'const': 0, 'cond2': 0})
        loom_bp['total'] += 1
        if loom_r.loom_via_class == 'CONST':
            loom_local, loom_skip = loom_plan_const(bridge, loom_r, loom_disp, loom_str_pc)
            loom_kind_key = 'const'
        elif loom_r.loom_via_class == 'COND2':
            loom_local, loom_skip = loom_plan_cond2(bridge, loom_r, loom_disp, loom_pred, loom_str_pc, loom_read_value)
            loom_kind_key = 'cond2'
        else:
            loom_skipped['OTHER'] += 1
            continue
        if loom_skip is not None:
            loom_skipped[loom_skip] = loom_skipped.get(loom_skip, 0) + 1
            continue
        loom_patches.extend(loom_local)
        loom_bp[loom_kind_key] += 1
        loom_bp['patchable'] += 1
        loom_accepted += 1
    if loom_out_path:
        LOOM_M.write_rewrites(loom_patches, loom_out_path, loom_by_parent=loom_by_parent, loom_skipped=loom_skipped)
    return {'phase': 'plan', 'patches': len(loom_patches), 'patchable_dispatchers': loom_accepted, 'resolutions_seen': len(loom_resolutions), 'skipped': loom_skipped, 'by_parent': loom_by_parent, 'in_path': loom_in_path, 'out_path': loom_out_path}
__all__ = ['execute_stage']
