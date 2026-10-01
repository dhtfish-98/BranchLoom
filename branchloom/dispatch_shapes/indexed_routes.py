"""
branchloom.dispatch_shapes.indexed_routes — Family-A two-level dispatcher detector (P1 core).

Faithful port of the dispatcher-triplet census in
the private reference toolchain (``cff_census.py``)
(``_is_dispatcher_triplet`` / ``loom_find_state_load`` / ``_find_adr_for_reg`` /
``_predecessors_of`` / ``run``), re-expressed against the target-agnostic
primitives of this package:

  * IDA access goes exclusively through the injected ``adapter`` (never a direct
    ``idaapi`` import here) — ``loom_get_dword`` for instruction words, ``exec_segments``
    for the scan ranges, ``loom_func_at`` for the parent function, ``loom_xrefs_to_code`` for
    predecessors, ``loom_is_exec`` for target sanity.
  * every instruction is recognised by :mod:`branchloom.arm_words.recognition` bit-pattern
    predicates (``D.*``) instead of the reference's hand-rolled masks / IDA disasm.
  * every knob (segments, state-slot bases, index-register allowlist, table-base
    overrides) comes from :class:`~branchloom.settings.AnalysisSettings` — no address, no
    segment name, no table offset is baked in.

The *shape* recognised is the two-level flattening dispatcher (4-byte stride,
anchored on the stable LDRSW/LDR/BR triplet)::

    (state-load)  LDRSW/LDR/LDUR  Xs, [X29|SP, #K]    ; scrambled state <- stack slot
    ...
    ldrsw_idx_ea  LDRSW  Xi, [Xidx, Xs, LSL #2]        ; idx  = idx_table[state]
    ldr_tgt_ea    LDR    Xt, [Xtgt, Xi, LSL #3]        ; tgt  = tgt_table[idx]
    br_ea         BR     Xt

Cross-checks (identical to the reference): ``LDRSW.loom_rt == LDR.loom_rm`` and
``LDR.loom_rt == BR.loom_rn``. The BR is the anchor; we scan every 4-byte slot and, on a
triplet hit, back-scan for the state-load and resolve both table bases via
ADR / ADRP(+ADD).
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from .. import records as LOOM_M
from ..arm_words import recognition as LOOM_D
from ..arm_words.neighbourhood import loom_reverse_words as loom_reverse_words
__all__ = ['loom_find_dispatchers']
LOOM__STATE_LOOKBACK_INSNS = 16
LOOM__ADR_WINDOW_INSNS = 256
LOOM__ADD_FWD_INSNS = 64
LOOM__MASK32 = 4294967295

def loom_add_imm_x(opcode: int) -> loom_Optional[loom_Tuple[int, int, int]]:
    """Return ``(rd, rn, imm)`` for ``ADD Xd, Xn, #imm{, LSL #12}`` else ``None``."""
    if opcode & 4286578688 != 2432696320:
        return None
    loom_rd_value = opcode & 31
    loom_rn = opcode >> 5 & 31
    loom_sh = opcode >> 22 & 3
    loom_imm12 = opcode >> 10 & 4095
    loom_imm = loom_imm12 << 12 if loom_sh == 1 else loom_imm12
    return (loom_rd_value, loom_rn, loom_imm)

def loom_reg_name(loom_reg: int) -> str:
    """Map a base-register field to its canonical name (31 == SP in a base slot)."""
    if loom_reg == 29:
        return 'X29'
    if loom_reg == 31:
        return 'SP'
    return 'X%d' % loom_reg

def loom_writes_base(opcode: int, loom_reg: int) -> bool:
    """True iff ``word`` writes ``reg`` (covers the 64-bit ADD-imm decode too)."""
    if LOOM_D.loom_writes_reg(opcode, loom_reg):
        return True
    loom_a = loom_add_imm_x(opcode)
    return loom_a is not None and loom_a[0] == loom_reg

def loom_dispatcher_triplet(loom_read_word: loom_Callable[[int], loom_Optional[int]], address: int):
    """Return a small descriptor dict if the LDRSW/LDR/BR triplet roots at ``ea``.

    Mirrors ``cff_census._is_dispatcher_triplet`` but uses the locked decoders.
    """
    loom_w0 = loom_read_word(address)
    loom_w1 = loom_read_word(address + 4)
    loom_w2 = loom_read_word(address + 8)
    if loom_w0 is None or loom_w1 is None or loom_w2 is None:
        return None
    if not LOOM_D.loom_is_ldrsw_reg_lsl2(loom_w0):
        return None
    if not LOOM_D.loom_is_ldr_reg_x_lsl3(loom_w1):
        return None
    if not LOOM_D.loom_is_br(loom_w2):
        return None
    loom_idx = LOOM_D.loom_reg_load_fields(loom_w0)
    loom_tgt = LOOM_D.loom_reg_load_fields(loom_w1)
    loom_br_reg = LOOM_D.loom_br_rn(loom_w2)
    if loom_idx.loom_rt != loom_tgt.loom_rm:
        return None
    if loom_tgt.loom_rt != loom_br_reg:
        return None
    return {'ldrsw_idx_ea': address, 'ldr_tgt_ea': address + 4, 'br_ea': address + 8, 'state_reg': loom_idx.loom_rm, 'idx_val_reg': loom_idx.loom_rt, 'idx_tbl_reg': loom_idx.loom_rn, 'tgt_tbl_reg': loom_tgt.loom_rn, 'tgt_reg': loom_tgt.loom_rt}

def loom_find_state_load(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_ldrsw_idx_ea: int, loom_state_reg: int, loom_allowed_bases: loom_List[str]):
    """Nearest preceding stack-load that produces ``state_reg``.

    Returns ``(ea, slot_imm, base_name, mnem)`` or ``None``. Ported from
    ``cff_census._find_state_load``: it scans backwards for any of the recognised
    stack-load shapes (LDURSW / LDRSW / LDR_X / LDUR_X / LDR_W / LDUR_W, all via
    the locked ``LOOM_D.loom_state_load``) whose destination is the state register. When
    ``allowed_bases`` is non-empty a load is only accepted if its base register
    name is in it (``cff.state_slot_bases``, default ``['X29','SP']``); otherwise
    the base is recorded but not constrained.
    """
    for address, opcode in loom_reverse_words(loom_read_word, loom_ldrsw_idx_ea - 4, LOOM__STATE_LOOKBACK_INSNS):
        if opcode is None:
            continue
        loom_mi = LOOM_D.loom_state_load(opcode)
        if loom_mi is None or loom_mi.loom_rt != loom_state_reg:
            continue
        loom_base_value = loom_reg_name(loom_mi.loom_rn)
        if loom_allowed_bases and loom_base_value not in loom_allowed_bases:
            continue
        return (address, loom_mi.loom_imm, loom_base_value, loom_mi.loom_kind_value)
    return None

def loom_resolve_table_base(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_from_ea: int, loom_base_reg_value: int) -> loom_Optional[int]:
    """Resolve the absolute EA a table-base register points at.

    Ported from ``cff_census._find_adr_for_reg``: walk backwards for the most
    recent ADR / ADRP writing ``base_reg``. A bare ADRP is completed by scanning
    forward for the matching ``ADD Xd, Xd, #imm`` (page + offset); an ADR resolves
    directly. Returns ``None`` if no producer is found in the window.
    """
    for address, opcode in loom_reverse_words(loom_read_word, loom_from_ea - 4, LOOM__ADR_WINDOW_INSNS):
        if opcode is None:
            continue
        if LOOM_D.loom_is_adr(opcode) and LOOM_D.loom_adr_rd(opcode) == loom_base_reg_value:
            return LOOM_D.loom_adr_target(address, opcode)
        if LOOM_D.loom_is_adrp(opcode) and LOOM_D.loom_adr_rd(opcode) == loom_base_reg_value:
            loom_page = LOOM_D.loom_adrp_page(address, opcode)
            loom_probe = address + 4
            for _ in range(LOOM__ADD_FWD_INSNS):
                loom_fw = loom_read_word(loom_probe)
                if loom_fw is None:
                    break
                loom_add = loom_add_imm_x(loom_fw)
                if loom_add is not None and loom_add[0] == loom_base_reg_value and (loom_add[1] == loom_base_reg_value):
                    return loom_page + loom_add[2] & 18446744073709551615
                if loom_writes_base(loom_fw, loom_base_reg_value):
                    break
                loom_probe += 4
            return loom_page
    return None

def loom_make_reader(bridge) -> loom_Callable[[int], loom_Optional[int]]:

    def loom_read_value(address: int) -> loom_Optional[int]:
        if address < 0:
            return None
        try:
            return bridge.loom_get_dword(address) & LOOM__MASK32
        except Exception:
            return None
    return loom_read_value

def loom_find_dispatchers(bridge, settings) -> loom_List[LOOM_M.RouteHub]:
    """Enumerate every Family-A two-level CFF dispatcher in the configured segments.

    ``adapter`` is the :mod:`branchloom.database.bridge` boundary (or any object
    exposing the same free functions); ``cfg`` is a loaded
    :class:`~branchloom.settings.AnalysisSettings`. Returns a list of
    :class:`branchloom.records.RouteHub`, sorted by ``(parent_fn_ea, br_ea)``.
    """
    loom_read_word = loom_make_reader(bridge)
    loom_allowed_bases = list(settings.loom_state_slot_bases)
    loom_index_allow = set(settings.loom_index_reg_allowlist)
    loom_base_overrides = settings.loom_dispatch_base_overrides
    loom_found: loom_List[LOOM_M.RouteHub] = []
    for loom_seg_start, loom_seg_end, loom_seg_name in bridge.loom_exec_segments(settings):
        address = loom_seg_start & ~3
        while address + 12 <= loom_seg_end:
            loom_desc = loom_dispatcher_triplet(loom_read_word, address)
            if loom_desc is None:
                address += 4
                continue
            if loom_index_allow and loom_desc['state_reg'] not in loom_index_allow:
                address += 4
                continue
            loom_br_ea = loom_desc['br_ea']
            loom_sl = loom_find_state_load(loom_read_word, address, loom_desc['state_reg'], loom_allowed_bases)
            if loom_sl is None:
                loom_state_ea, loom_state_slot, loom_state_base, loom_state_mnem = (None, None, None, None)
            else:
                loom_state_ea, loom_state_slot, loom_state_base, loom_state_mnem = loom_sl
            loom_idx_tbl_ea = loom_resolve_table_base(loom_read_word, address, loom_desc['idx_tbl_reg'])
            loom_tgt_tbl_ea = loom_resolve_table_base(loom_read_word, loom_desc['ldr_tgt_ea'], loom_desc['tgt_tbl_reg'])
            if loom_tgt_tbl_ea is None and loom_br_ea in loom_base_overrides:
                loom_tgt_tbl_ea = loom_base_overrides[loom_br_ea]
            loom_parent = bridge.loom_func_at(address)
            if loom_parent is None:
                loom_parent_ea, loom_parent_name = (None, None)
            else:
                loom_parent_ea, loom_parent_name = (loom_parent[0], loom_parent[1] or None)
            loom_head = loom_state_ea if loom_state_ea is not None else address
            try:
                loom_preds = list(bridge.loom_xrefs_to_code(loom_head))
            except Exception:
                loom_preds = []
            loom_found.append(LOOM_M.RouteHub(loom_br_ea=loom_br_ea, loom_ldr_tgt_ea=loom_desc['ldr_tgt_ea'], loom_ldrsw_idx_ea=loom_desc['ldrsw_idx_ea'], loom_state_load_ea=loom_state_ea, loom_state_slot=loom_state_slot, loom_state_base=loom_state_base, loom_state_load_mnem=loom_state_mnem, loom_state_reg=loom_desc['state_reg'], loom_idx_tbl_reg=loom_desc['idx_tbl_reg'], loom_tgt_tbl_reg=loom_desc['tgt_tbl_reg'], loom_idx_tbl_ea=loom_idx_tbl_ea, loom_tgt_tbl_ea=loom_tgt_tbl_ea, loom_parent_fn_ea=loom_parent_ea, loom_parent_fn_name=loom_parent_name, loom_predecessor_eas=sorted(set(loom_preds))))
            address += 12
    LOOM__BIG = 1 << 63
    loom_found.sort(key=lambda loom_d_value: (loom_d_value.loom_parent_fn_ea if loom_d_value.loom_parent_fn_ea is not None else LOOM__BIG, loom_d_value.loom_br_ea))
    return loom_found
