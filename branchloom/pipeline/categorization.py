"""
branchloom.pipeline.categorization — Phase 2: classify each dispatcher's predecessor.

For every dispatcher found by P1 (:mod:`branchloom.pipeline.enumeration`), the
predecessor is the tail of the handler that computes the *next* flattening state,
writes it into the state stack-slot, and falls through / branches to the
dispatcher. This phase reverse-scans that tail and buckets it:

  ============  ====================================================  ==========
  class         shape (per docs/METHODOLOGY.md §2)                    successors
  ============  ====================================================  ==========
  ``CONST``     ``MOVZ/MOVN Wt,#imm ; ... ; STR Wt,[slot]``           1 static
  ``COND2``     ``MOVZ ; MOVZ ; CSEL/CSET/CINC Wc,..,cond ; STR``     2 (flag)
  ``XFORM``     ``LDR Wt,[slot] ; EOR #K ; ADD/SUB #C ; STR``         self-scramble
  ``OPAQUE``    anything else                                         unknown
  ============  ====================================================  ==========

Only ``CONST`` and ``COND2`` carry statically-known next-state(s), so only they
are ever resolved and patched downstream. ``XFORM`` is the obfuscator's own state
scrambler (rewrites the slot without branching) and is deliberately *not* patched;
``OPAQUE`` is left untouched.

Faithful port of ``cff_classify_preds.py::_classify`` from
the private reference toolchain — re-expressed
against the locked, target-agnostic seams of this package:

  * every instruction is recognised by :mod:`branchloom.arm_words.recognition` predicates
    (``LOOM_D.loom_store_to_slot`` / ``LOOM_D.loom_cond_select_w`` / ``LOOM_D.loom_alu_imm_w`` / ``LOOM_D.loom_state_load``
    / ``LOOM_D.loom_move_imm_w`` / ``LOOM_D.loom_mov_reg_w_fields``) instead of hand-rolled masks;
  * the STR-to-slot search and every producer back-walk go through
    :func:`branchloom.arm_words.neighbourhood.loom_find_reg_producer` / ``loom_reverse_words`` (which honour
    the AAPCS64 BL/BLR caller-saved clobber rule — never guess past a call);
  * the ``CONST`` value is proven by :func:`branchloom.arm_words.value_chains.loom_resolve_const_reg`
    (MOV/MOVZ/MOVN/MOVK, register copies, ORR/EOR/ADD/SUB chains — never guesses),
    which subsumes and strengthens the reference's MOVZ/MOVN-only recogniser;
  * nothing target-specific is baked in — the state slot / base register come from
    the P1 census record, scan windows are named constants.
"""
from __future__ import annotations as loom_annotations
from typing import Any as loom_Any, Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from .. import records as LOOM_M
from ..arm_words import value_chains as LOOM_CR
from ..arm_words import recognition as LOOM_D
from ..arm_words import neighbourhood as LOOM_W
from ..dispatch_shapes import indexed_routes as indexed_routes
LOOM__STORE_LOOKBACK_INSNS = 16
LOOM__PROD_LOOKBACK_INSNS = 16
LOOM__COND_FOLLOW_INSNS = 8
LOOM__XFORM_STEPS = 6
LOOM__XFORM_INNER_INSNS = 6
LOOM__CONST_DEPTH = 6
LOOM__MASK32 = 4294967295
LOOM__XFORM_ALU_OPS = ('ADD', 'SUB', 'EOR', 'AND', 'ORR')
LOOM__XFORM_SLOT_KINDS = ('LDR_W', 'LDUR_W')

def loom_make_reader(bridge) -> loom_Callable[[int], loom_Optional[int]]:

    def loom_read_value(address: int) -> loom_Optional[int]:
        if address < 0:
            return None
        try:
            return bridge.loom_get_dword(address) & LOOM__MASK32
        except Exception:
            return None
    return loom_read_value

def loom_base_reg(loom_state_base: loom_Optional[str]) -> loom_Optional[int]:
    """Map a state-base name ('X29' | 'SP' | 'Xn') back to its register number."""
    if loom_state_base is None:
        return None
    if loom_state_base == 'X29':
        return 29
    if loom_state_base == 'SP':
        return 31
    try:
        return int(loom_state_base[1:])
    except (ValueError, IndexError):
        return None

def loom_find_store_to_slot(loom_read_value: loom_Callable[[int], loom_Optional[int]], loom_state_load_ea: int, loom_want_rn: int, loom_slot: int, loom_lookback: int) -> loom_Tuple[loom_Optional[int], loom_Optional[int]]:
    """Nearest ``STR/STUR Wt, [base, #slot]`` strictly before ``state_load_ea``.

    Returns ``(str_ea, str_rt)`` or ``(None, None)``. Mirrors the reference's
    reverse-scan, but uses the locked :func:`LOOM_D.loom_store_to_slot` which already
    normalises both the STR (scaled uimm12) and STUR (signed simm9) forms to a
    single signed byte offset — so a plain ``imm == slot`` compare is exact and
    the reference's scaled-imm12-vs-simm9 split is unnecessary.
    """
    for address, opcode in LOOM_W.loom_reverse_words(loom_read_value, loom_state_load_ea - 4, loom_lookback):
        if opcode is None:
            continue
        loom_mi = LOOM_D.loom_store_to_slot(opcode)
        if loom_mi is not None and loom_mi.loom_rn == loom_want_rn and (loom_mi.loom_imm == loom_slot):
            return (address, loom_mi.loom_rt)
    return (None, None)

def loom_cond2_detail(loom_read_value: loom_Callable[[int], loom_Optional[int]], loom_str_ea: int, loom_cs_ea: int, loom_cs: 'LOOM_D.ConditionalChoice', loom_mov_ea: loom_Optional[int]) -> loom_Tuple[loom_Dict[str, loom_Any], int]:
    """Build the COND2 ``class_detail`` and the predecessor start EA.

    ``CSEL Wd, Wn, Wm, cond`` selects ``Wn`` (the "then" value) when ``cond`` holds
    and ``Wm`` (the "else" value) otherwise; the CSINC/CSINV/CSNEG members (and the
    CSET/CSETM/CINC/CINV/CNEG aliases) fold in the same 2-way selection with an
    implicit +1 / bitwise-NOT / negate that Phase 3 applies. Here we prove the two
    source constants (``c1`` from ``Rn``, ``c2`` from ``Rm``) via ``const_resolve``
    — either may be ``None`` when the source is not a provable constant (e.g. a
    CSET whose sources are WZR resolve to 0; a data-dependent source resolves to
    ``None``), which Phase 3 gates on.
    """
    loom_c1 = LOOM_CR.loom_resolve_const_reg(loom_read_value, loom_cs_ea, loom_cs.loom_rn, loom_max_depth=LOOM__CONST_DEPTH)
    loom_c2 = LOOM_CR.loom_resolve_const_reg(loom_read_value, loom_cs_ea, loom_cs.loom_rm, loom_max_depth=LOOM__CONST_DEPTH)
    loom_detail: loom_Dict[str, loom_Any] = {'c1': loom_c1, 'c2': loom_c2, 'cond': loom_cs.loom_cond, 'cond_name': LOOM_D.loom_cond_name(loom_cs.loom_cond), 'op': loom_cs.loom_op, 'alias': loom_cs.loom_alias, 'csel_ea': LOOM_M.loom_hx_value(loom_cs_ea), 'str_ea': LOOM_M.loom_hx_value(loom_str_ea)}
    if loom_mov_ea is not None:
        loom_detail['mov_ea'] = LOOM_M.loom_hx_value(loom_mov_ea)
    loom_starts = [loom_cs_ea]
    for loom_src in (loom_cs.loom_rn, loom_cs.loom_rm):
        loom_p = LOOM_W.loom_find_reg_producer(loom_read_value, loom_cs_ea, loom_src, loom_max_insns=LOOM__COND_FOLLOW_INSNS)
        if loom_p is not None:
            loom_starts.append(loom_p)
    return (loom_detail, min(loom_starts))

def loom_walk_xform(loom_read_value: loom_Callable[[int], loom_Optional[int]], loom_start_ea: int, loom_start_word: int, loom_want_rn: int, loom_slot: int) -> loom_Optional[loom_Tuple[loom_List[list], int]]:
    """Follow the state-rewrite chain back from the STR's producer to the slot load.

    Ported from ``cff_classify_preds._walk_xform``: starting at the arithmetic
    instruction that produced the stored value, walk backwards through an
    ADD/SUB/EOR(/AND/ORR)-immediate chain until it bottoms out in a 32-bit load of
    the *same* state slot (``LDR/LDUR Wt, [base, #slot]``). Returns
    ``(chain, ldr_slot_ea)`` where ``chain`` is a JSON-able list of
    ``[op, loom_hx_value(ea), imm]`` entries ending in ``["LDR_SLOT", loom_hx_value(ea), None]``, or
    ``None`` if the chain is not a pure self-scramble.
    """
    loom_chain: loom_List[list] = []
    loom_cur_ea, loom_cur_word = (loom_start_ea, loom_start_word)
    for _ in range(LOOM__XFORM_STEPS):
        loom_mi = LOOM_D.loom_state_load(loom_cur_word)
        if loom_mi is not None and loom_mi.loom_rn == loom_want_rn and (loom_mi.loom_imm == loom_slot) and (loom_mi.loom_kind_value in LOOM__XFORM_SLOT_KINDS):
            loom_chain.append(['LDR_SLOT', LOOM_M.loom_hx_value(loom_cur_ea), None])
            return (loom_chain, loom_cur_ea)
        loom_ai = LOOM_D.loom_alu_imm_w(loom_cur_word)
        if loom_ai is None or loom_ai.loom_op not in LOOM__XFORM_ALU_OPS:
            return None
        loom_chain.append([loom_ai.loom_op, LOOM_M.loom_hx_value(loom_cur_ea), loom_ai.loom_imm])
        loom_nxt = LOOM_W.loom_find_reg_producer(loom_read_value, loom_cur_ea, loom_ai.loom_rn, loom_max_insns=LOOM__XFORM_INNER_INSNS)
        if loom_nxt is None:
            return None
        loom_nw = loom_read_value(loom_nxt)
        if loom_nw is None:
            return None
        loom_cur_ea, loom_cur_word = (loom_nxt, loom_nw)
    return None

def loom_classify(loom_read_value: loom_Callable[[int], loom_Optional[int]], loom_disp: LOOM_M.RouteHub) -> loom_Tuple[str, loom_Dict[str, loom_Any], loom_Optional[int], loom_Optional[int], loom_Optional[str]]:
    """Classify the predecessor of a single dispatcher.

    Returns ``(cls, class_detail, str_ea, pred_start_ea, reason)`` where ``cls`` is
    one of :data:`branchloom.records.LOOM_CLASSES` and ``reason`` is populated only for
    ``OPAQUE``.
    """
    loom_state_load_ea = loom_disp.loom_state_load_ea
    loom_slot = loom_disp.loom_state_slot
    loom_base_value = loom_disp.loom_state_base
    if loom_state_load_ea is None or loom_slot is None or loom_base_value is None:
        return ('OPAQUE', {}, None, None, 'no state-load anchor')
    loom_want_rn = loom_base_reg(loom_base_value)
    if loom_want_rn is None:
        return ('OPAQUE', {}, None, None, 'unhandled state_base %r' % loom_base_value)
    loom_str_ea, loom_str_rt = loom_find_store_to_slot(loom_read_value, loom_state_load_ea, loom_want_rn, loom_slot, LOOM__STORE_LOOKBACK_INSNS)
    if loom_str_ea is None:
        return ('OPAQUE', {}, None, None, 'no STR to state slot in lookback')
    loom_prod_ea = LOOM_W.loom_find_reg_producer(loom_read_value, loom_str_ea, loom_str_rt, loom_max_insns=LOOM__PROD_LOOKBACK_INSNS)
    if loom_prod_ea is None:
        return ('OPAQUE', {'str_ea': LOOM_M.loom_hx_value(loom_str_ea)}, loom_str_ea, loom_str_ea, 'no provable writer of stored register')
    loom_prod_word = loom_read_value(loom_prod_ea)
    if loom_prod_word is None:
        return ('OPAQUE', {'str_ea': LOOM_M.loom_hx_value(loom_str_ea)}, loom_str_ea, loom_str_ea, 'unreadable producer word')
    loom_cs = LOOM_D.loom_cond_select_w(loom_prod_word)
    if loom_cs is not None:
        loom_detail, loom_pred_start = loom_cond2_detail(loom_read_value, loom_str_ea, loom_prod_ea, loom_cs, None)
        return ('COND2', loom_detail, loom_str_ea, loom_pred_start, None)
    if LOOM_D.loom_is_mov_reg_w(loom_prod_word):
        loom_rd, loom_rm = LOOM_D.loom_mov_reg_w_fields(loom_prod_word)
        loom_cs_ea = LOOM_W.loom_find_reg_producer(loom_read_value, loom_prod_ea, loom_rm, loom_max_insns=LOOM__COND_FOLLOW_INSNS)
        if loom_cs_ea is not None:
            loom_cs_word = loom_read_value(loom_cs_ea)
            loom_cs2 = LOOM_D.loom_cond_select_w(loom_cs_word) if loom_cs_word is not None else None
            if loom_cs2 is not None and loom_cs2.loom_rd_value == loom_rm:
                loom_detail, loom_pred_start = loom_cond2_detail(loom_read_value, loom_str_ea, loom_cs_ea, loom_cs2, loom_prod_ea)
                return ('COND2', loom_detail, loom_str_ea, loom_pred_start, None)
    loom_val = LOOM_CR.loom_resolve_const_reg(loom_read_value, loom_str_ea, loom_str_rt, loom_max_depth=LOOM__CONST_DEPTH)
    if loom_val is not None:
        return ('CONST', {'imm': loom_val, 'producer_ea': LOOM_M.loom_hx_value(loom_prod_ea), 'str_ea': LOOM_M.loom_hx_value(loom_str_ea)}, loom_str_ea, loom_prod_ea, None)
    loom_xf = loom_walk_xform(loom_read_value, loom_prod_ea, loom_prod_word, loom_want_rn, loom_slot)
    if loom_xf is not None:
        loom_chain, loom_ldr_slot_ea = loom_xf
        return ('XFORM', {'chain': loom_chain, 'str_ea': LOOM_M.loom_hx_value(loom_str_ea)}, loom_str_ea, loom_ldr_slot_ea, None)
    return ('OPAQUE', {'str_ea': LOOM_M.loom_hx_value(loom_str_ea), 'producer_ea': LOOM_M.loom_hx_value(loom_prod_ea), 'producer_word': '%08x' % loom_prod_word}, loom_str_ea, loom_str_ea, 'unrecognised state producer')

def execute_stage(bridge, settings, loom_in_path: loom_Optional[str]=None, loom_out_path: loom_Optional[str]=None, **loom_kw) -> loom_Dict[str, loom_Any]:
    """Classify every dispatcher's predecessor into CONST / COND2 / XFORM / OPAQUE.

    Parameters
    ----------
    adapter :
        The Tier-1 IDA boundary (needs ``loom_get_dword``; ``exec_segments`` /
        ``loom_func_at`` / ``loom_xrefs_to_code`` only when ``in_path`` is None and the
        census must be recomputed in-memory).
    cfg :
        A loaded :class:`~branchloom.settings.AnalysisSettings`.
    in_path :
        Path to the ``cff_dispatchers.json`` produced by Phase 1. When ``None``
        the census is recomputed on the fly via
        :func:`branchloom.dispatch_shapes.indexed_routes.loom_find_dispatchers` so the phase is
        runnable stand-alone.
    out_path :
        Where to write ``cff_predecessors.json``. When ``None`` the classification
        is computed and summarised but not persisted.

    Returns
    -------
    dict
        A small summary: per-class counts and the artifact path.
    """
    if loom_in_path:
        loom_dispatchers = LOOM_M.read_hubs(loom_in_path)
    else:
        loom_dispatchers = indexed_routes.loom_find_dispatchers(bridge, settings)
    loom_read_value = loom_make_reader(bridge)
    items: loom_List[LOOM_M.IncomingBlock] = []
    for loom_disp in loom_dispatchers:
        record_type, loom_detail, loom_str_ea, loom_pred_start_ea, loom_reason = loom_classify(loom_read_value, loom_disp)
        items.append(LOOM_M.IncomingBlock(loom_dispatcher_br_ea=loom_disp.loom_br_ea, loom_parent_fn_ea=loom_disp.loom_parent_fn_ea, loom_parent_fn_name=loom_disp.loom_parent_fn_name, loom_idx_tbl_ea=loom_disp.loom_idx_tbl_ea, loom_tgt_tbl_ea=loom_disp.loom_tgt_tbl_ea, loom_state_slot=loom_disp.loom_state_slot, loom_state_base=loom_disp.loom_state_base, record_type=record_type, loom_class_detail=loom_detail, loom_str_ea=loom_str_ea, loom_pred_start_ea=loom_pred_start_ea, loom_reason=loom_reason))
    if loom_out_path:
        LOOM_M.write_incoming(items, loom_out_path)
    loom_counts = {loom_c: sum((1 for loom_r in items if loom_r.record_type == loom_c)) for loom_c in LOOM_M.LOOM_CLASSES}
    return {'phase': 'classify', 'count': len(items), 'classes': loom_counts, 'in_path': loom_in_path, 'out_path': loom_out_path}
__all__ = ['execute_stage']

# TODO(validate): confirm on-device that AND/ORR-immediate really appear in the
