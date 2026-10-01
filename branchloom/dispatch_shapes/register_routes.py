"""
branchloom.dispatch_shapes.register_routes — single-level CSEL/CSET + LDR + BR dispatch (Model-1).

Faithful port of the *algorithm* in
the private reference toolchain (``deobf_br_dispatch.py``) — specifically
``_find_dispatch_ctx`` / ``_find_table_base_for_ldr`` / ``_patch_site`` — rebuilt
against the target-agnostic Tier-1 layer (``arm_words.recognition`` bit-pattern recognisers,
``arm_words.neighbourhood`` / ``arm_words.value_chains`` back-walks, ``integrity.clobber_scan`` and
``integrity.site_validation``). No IDA import, no absolute addresses, no segment-name
assumptions: the executable ranges, the table entry size, the optional dispatch
base overrides and the index-register allow-list all come from the AnalysisSettings.

The obfuscator shape (per site)::

    ... MOV  Wa, #idxA ...
    ... MOV  Wb, #idxB ...
    CSEL/CSINC/CSET Wx, Wa, Wb, <cond>     # pick one of two constant indices
    [0+ side-effect insns]
    LDR  Xt, [Xbase, Wx, UXTW #3]          # 8-byte target-table load
    [0+ side-effect insns]
    BR   Xt                                 # indirect dispatch

``loom_find_single_level`` locates each such ``BR``, resolves the two constant indices,
reads the two table targets, and computes the *recommended* same-size rewrite that
collapses the indirect branch into ordinary control flow:

  * flags still valid at ``BR`` and one target is the fall-through
        -> one ``B.loom_cond`` / ``B.<!cond>`` in the ``BR`` slot.
  * flags still valid, neither target is the fall-through
        -> ``B.loom_cond`` in the freed ``LDR`` slot + ``B`` in the ``BR`` slot,
           **only** when ``integrity.clobber_scan.loom_a_path_hazard`` proves the skipped gap
           holds no externally-observable effect.

This module is a *detector*: it never patches bytes. It returns a list of plain
dicts (each carrying an already-range-checked, round-trip-verified ``patch`` plan)
for a Tier-3 phase to serialise into ``records.ByteRewrite`` objects and apply.

Behind a mode flag: single-level dispatch is a different obfuscation model from the
two-level CFF core, so it only runs when ``settings.loom_cff['single_level']`` is truthy (or
the aggressive rewrite modes are selected). See ``assumptions_todos``.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from ..arm_words import recognition as LOOM_D
from ..arm_words import emission as LOOM_E
from ..arm_words.value_chains import loom_resolve_const_reg as loom_resolve_const_reg
from ..arm_words.neighbourhood import loom_find_reg_producer as loom_find_reg_producer, loom_reverse_words as loom_reverse_words
from ..integrity.clobber_scan import loom_a_path_hazard as loom_a_path_hazard
from ..integrity.site_validation import loom_self_check_targets as loom_self_check_targets, loom_verify_branch_roundtrip as loom_verify_branch_roundtrip
LOOM_MASK32 = 4294967295
LOOM_MASK64 = 18446744073709551615
LOOM__CALLER_SAVED = frozenset(range(0, 19)) | {30}
LOOM__LDR_WINDOW = 32
LOOM__CSEL_WINDOW = 16
LOOM__TABLE_BASE_WINDOW = 4096

def loom_make_reader(bridge) -> loom_Callable[[int], loom_Optional[int]]:
    """Wrap ``bridge.loom_get_dword`` as the ``loom_read_word(ea) -> int|None`` callable the
    IDA-free Tier-1 helpers expect. Unreadable / raising reads collapse to ``None``
    so a back-walk aborts rather than proceeding on garbage."""

    def loom_read_word(address: int) -> loom_Optional[int]:
        try:
            loom_w = bridge.loom_get_dword(address)
        except Exception:
            return None
        if loom_w is None:
            return None
        return loom_w & LOOM_MASK32
    return loom_read_word

def loom_is_add_imm64(opcode: int) -> bool:
    """``ADD Xd, Xn, #imm{, LSL #12}`` (S=0). sf=1,op=0,S=0, [28:24]=10001."""
    return opcode & 4278190080 == 2432696320

def loom_add_imm64_fields(opcode: int) -> loom_Tuple[int, int]:
    loom_rn = opcode >> 5 & 31
    loom_sh = LOOM_D.loom_bits(opcode, 23, 22)
    loom_imm = LOOM_D.loom_bits(opcode, 21, 10) << (12 if loom_sh == 1 else 0)
    return (loom_rn, loom_imm)

def loom_is_mov_reg_x(opcode: int) -> bool:
    """``MOV Xd, Xm`` == ``ORR Xd, XZR, Xm`` (no shift)."""
    return opcode & 4292935648 == 2852127712

def loom_mov_reg_x_fields(opcode: int) -> loom_Tuple[int, int]:
    return (opcode & 31, opcode >> 16 & 31)

def loom_sets_flags(opcode: int) -> bool:
    if opcode & 520093696 == 285212672 and opcode >> 29 & 1:
        return True
    if opcode & 520093696 == 184549376 and opcode >> 29 & 1:
        return True
    if opcode & 520093696 == 167772160 and opcode & 1610612736 == 1610612736:
        return True
    if opcode & 528482304 == 301989888 and opcode & 1610612736 == 1610612736:
        return True
    if opcode & 534773760 == 440401920:
        return True
    if opcode & 4280351744 == 505421824:
        return True
    return False

def loom_flag_mod_in_gap(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_lo_ea: int, loom_hi_ea: int) -> bool:
    """True iff any instruction in the half-open ``[lo_ea, hi_ea)`` gap writes NZCV."""
    address = loom_lo_ea
    while address < loom_hi_ea:
        loom_w = loom_read_word(address)
        if loom_w is None:
            return True
        if loom_sets_flags(loom_w):
            return True
        address += 4
    return False

def loom_resolve_table_base(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_ldr_ea: int, loom_base_reg_value: int, loom_lo_ea: int) -> loom_Optional[int]:
    """Back-walk from the LDR to the ADRP(+ADD)/ADR that formed its base register.

    Port of ``_find_table_base_for_ldr`` (minus IDA disasm parsing). Returns the
    resolved absolute table address, or ``None`` if the base register is clobbered
    by an unmodelled writer or a caller-saved BL/BLR before an ADRP/ADR is reached.
    """
    loom_add_off = 0
    loom_reg = loom_base_reg_value
    loom_count = 0
    address = loom_ldr_ea - 4
    while address >= loom_lo_ea and loom_count < LOOM__TABLE_BASE_WINDOW:
        opcode = loom_read_word(address)
        if opcode is None:
            return None
        if LOOM_D.loom_is_bl(opcode) or LOOM_D.loom_is_blr(opcode):
            if loom_reg in LOOM__CALLER_SAVED:
                return None
            address -= 4
            loom_count += 1
            continue
        loom_rd_match = opcode & 31 == loom_reg
        if loom_rd_match and loom_is_add_imm64(opcode):
            loom_rn, loom_imm = loom_add_imm64_fields(opcode)
            loom_add_off = loom_add_off + loom_imm & LOOM_MASK64
            loom_reg = loom_rn
            address -= 4
            loom_count += 1
            continue
        if loom_rd_match and loom_is_mov_reg_x(opcode):
            loom_rd, loom_rm = loom_mov_reg_x_fields(opcode)
            loom_reg = loom_rm
            address -= 4
            loom_count += 1
            continue
        if LOOM_D.loom_writes_reg(opcode, loom_reg):
            if LOOM_D.loom_is_adrp(opcode):
                return LOOM_D.loom_adrp_page(address, opcode) + loom_add_off & LOOM_MASK64
            if LOOM_D.loom_is_adr(opcode):
                return LOOM_D.loom_adr_target(address, opcode) + loom_add_off & LOOM_MASK64
            return None
        address -= 4
        loom_count += 1
    return None

def loom_resolve_index_pair(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_csel_ea: int, loom_cs) -> loom_Optional[loom_Tuple[int, int]]:
    """Resolve (idx_when_cond_holds, idx_when_cond_fails) for a cond-select.

    The raw encoded condition (``loom_cs.loom_cond``) is used uniformly: for any member of
    the CSEL family the ``loom_rn`` operand is selected when the condition holds and a
    transform of ``loom_rm`` when it fails. This handles the CSET/CSETM/CINC/… aliases
    for free (they are just CSINC/CSINV with ZR operands + the inverted cond), so
    no per-alias special-casing is needed — see assumptions_todos.
    """
    loom_then_val = loom_resolve_const_reg(loom_read_word, loom_csel_ea, loom_cs.loom_rn)
    loom_else_raw = loom_resolve_const_reg(loom_read_word, loom_csel_ea, loom_cs.loom_rm)
    if loom_then_val is None or loom_else_raw is None:
        return None
    if loom_cs.loom_op == 'CSEL':
        loom_else_val = loom_else_raw
    elif loom_cs.loom_op == 'CSINC':
        loom_else_val = loom_else_raw + 1 & LOOM_MASK32
    elif loom_cs.loom_op == 'CSINV':
        loom_else_val = ~loom_else_raw & LOOM_MASK32
    elif loom_cs.loom_op == 'CSNEG':
        loom_else_val = -loom_else_raw & LOOM_MASK32
    else:
        return None
    return (loom_then_val & LOOM_MASK32, loom_else_val)

def loom_idx_offset(loom_idx: int, loom_entry_size: int, loom_option: int) -> int:
    """Byte offset of ``idx`` into the target table, honouring a signed (SXTW)
    index extension. Unsigned (UXTW/LSL) indices are used as-is."""
    if loom_option == 6:
        loom_idx = LOOM_D.loom_sign_extend(loom_idx & LOOM_MASK32, 32)
    return loom_idx * loom_entry_size

def loom_mk_branch(location: int, destination: int, opcode: loom_Optional[int]) -> loom_Optional[loom_Dict]:
    """Build a verified, same-size branch patch entry, or ``None`` if the encoder
    was out of range or the emitted word does not round-trip to ``target``."""
    if opcode is None:
        return None
    if not loom_verify_branch_roundtrip(location, opcode, destination):
        return None
    return {'pc': location, 'target': destination, 'new_word': opcode, 'new_bytes_hex': LOOM_E.opcode_bytes(opcode).hex()}

def loom_classify_patch(loom_read_word, loom_br_ea, loom_ldr_ea, loom_cond, loom_tgt_then, loom_tgt_else, loom_flag_mod_csel_br) -> loom_Tuple[str, str, loom_List[loom_Dict], loom_Optional[dict]]:
    """Compute the recommended rewrite for one resolved site.

    Returns ``(kind, reason, patch_entries, hazard)`` where ``kind`` is
    ``'resolved'`` or ``'skipped'``. Faithful to ``_patch_site`` Case 1 (flags
    valid CSEL->BR). The reference's Case 2 (1-insn at BR when flags were modified
    only *before* the LDR) is intentionally NOT ported: it relies on the CSEL
    condition being live at the BR despite a flag write between CSEL and LDR, which
    we cannot prove here — so we conservatively skip. See assumptions_todos.
    """
    loom_fall_through = loom_br_ea + 4
    loom_cond_inv = LOOM_D.loom_invert_cond(loom_cond)
    loom_cn, loom_cin = (LOOM_D.loom_cond_name(loom_cond), LOOM_D.loom_cond_name(loom_cond_inv))
    if loom_flag_mod_csel_br:
        return ('skipped', 'flags modified between CSEL and BR', [], None)
    if loom_fall_through == loom_tgt_then:
        loom_b = loom_mk_branch(loom_br_ea, loom_tgt_else, LOOM_E.emit_conditional_jump(loom_br_ea, loom_tgt_else, loom_cond_inv))
        if loom_b is not None:
            return ('resolved', '1-insn B.%s at BR (fall-through=then)' % loom_cin, [loom_b], None)
        return ('skipped', 'B.%s out of range' % loom_cin, [], None)
    if loom_fall_through == loom_tgt_else:
        loom_b = loom_mk_branch(loom_br_ea, loom_tgt_then, LOOM_E.emit_conditional_jump(loom_br_ea, loom_tgt_then, loom_cond))
        if loom_b is not None:
            return ('resolved', '1-insn B.%s at BR (fall-through=else)' % loom_cn, [loom_b], None)
        return ('skipped', 'B.%s out of range' % loom_cn, [], None)
    clobber_scan = loom_a_path_hazard(loom_read_word, loom_ldr_ea + 4, loom_br_ea)
    if clobber_scan is not None:
        loom_hea, loom_hm, loom_hreason = clobber_scan
        return ('skipped', 'unsafe A-path: %s@0x%x (%s)' % (loom_hm, loom_hea, loom_hreason), [], {'ea': loom_hea, 'mnem': loom_hm, 'reason': loom_hreason})
    loom_b1 = loom_mk_branch(loom_ldr_ea, loom_tgt_then, LOOM_E.emit_conditional_jump(loom_ldr_ea, loom_tgt_then, loom_cond))
    loom_b2 = loom_mk_branch(loom_br_ea, loom_tgt_else, LOOM_E.emit_jump(loom_br_ea, loom_tgt_else))
    if loom_b1 is not None and loom_b2 is not None:
        return ('resolved', '2-insn B.%s@LDR + B@BR (A-path verified clean)' % loom_cn, [loom_b1, loom_b2], None)
    return ('skipped', '2-insn branch out of range', [], None)

def loom_analyze_br(bridge, settings, loom_read_word, loom_br_ea, loom_br_word, loom_entry_size, loom_overrides, loom_allow, loom_seg_lo) -> loom_Optional[loom_Dict]:
    """Analyse a single ``BR`` instruction. Returns a site dict, or ``None`` when
    the instruction is not a single-level CSEL/LDR/BR dispatch at all."""
    loom_br_reg = LOOM_D.loom_br_rn(loom_br_word)
    loom_ldr_ea = loom_find_reg_producer(loom_read_word, loom_br_ea, loom_br_reg, loom_max_insns=LOOM__LDR_WINDOW)
    if loom_ldr_ea is None:
        return None
    loom_ldr_word = loom_read_word(loom_ldr_ea)
    if loom_ldr_word is None or not LOOM_D.loom_is_ldr_reg_x_lsl3(loom_ldr_word):
        return None
    loom_rl = LOOM_D.loom_reg_load_fields(loom_ldr_word)
    loom_idx_reg = loom_rl.loom_rm
    loom_base_reg_value = loom_rl.loom_rn
    loom_option = LOOM_D.loom_bits(loom_ldr_word, 15, 13)
    if loom_allow and loom_idx_reg not in loom_allow:
        return None
    loom_csel_ea = loom_find_reg_producer(loom_read_word, loom_ldr_ea, loom_idx_reg, loom_max_insns=LOOM__CSEL_WINDOW)
    if loom_csel_ea is None:
        return None
    loom_csel_word = loom_read_word(loom_csel_ea)
    if loom_csel_word is None:
        return None
    loom_cs = LOOM_D.loom_cond_select_w(loom_csel_word)
    if loom_cs is None or loom_cs.loom_rd_value != loom_idx_reg:
        return None
    loom_parent = bridge.loom_func_at(loom_br_ea)
    loom_parent_ea = loom_parent[0] if loom_parent else None
    loom_parent_name = loom_parent[1] if loom_parent else None
    loom_site: loom_Dict = {'model': 'single_level', 'br_ea': loom_br_ea, 'ldr_ea': loom_ldr_ea, 'csel_ea': loom_csel_ea, 'br_reg': loom_br_reg, 'idx_reg': loom_idx_reg, 'cond': LOOM_D.loom_cond_name(loom_cs.loom_cond), 'csel_op': loom_cs.loom_op, 'csel_alias': loom_cs.loom_alias, 'entry_size': loom_entry_size, 'parent_fn_ea': loom_parent_ea, 'parent_fn_name': loom_parent_name, 'idx_then': None, 'idx_else': None, 'table_ea': None, 'tgt_then': None, 'tgt_else': None, 'flag_mod_csel_br': None, 'a_path_hazard': None, 'kind': 'skipped', 'reason': '', 'patch': [], 'self_check_ok': None, 'self_check_errors': []}
    loom_pair = loom_resolve_index_pair(loom_read_word, loom_csel_ea, loom_cs)
    if loom_pair is None:
        loom_site['reason'] = 'index constant(s) unresolved'
        return loom_site
    loom_idx_then, loom_idx_else = loom_pair
    loom_site['idx_then'], loom_site['idx_else'] = (loom_idx_then, loom_idx_else)
    loom_table = loom_overrides.get(loom_br_ea)
    if loom_table is None:
        loom_table = loom_resolve_table_base(loom_read_word, loom_ldr_ea, loom_base_reg_value, loom_parent_ea if loom_parent_ea is not None else loom_seg_lo)
    if loom_table is None:
        loom_site['reason'] = 'table base unresolved'
        return loom_site
    loom_site['table_ea'] = loom_table
    try:
        loom_tgt_then = bridge.loom_get_qword(loom_table + loom_idx_offset(loom_idx_then, loom_entry_size, loom_option)) & LOOM_MASK64
        loom_tgt_else = bridge.loom_get_qword(loom_table + loom_idx_offset(loom_idx_else, loom_entry_size, loom_option)) & LOOM_MASK64
    except Exception as loom_exc:
        loom_site['reason'] = 'table read failed: %r' % (loom_exc,)
        return loom_site
    loom_site['tgt_then'], loom_site['tgt_else'] = (loom_tgt_then, loom_tgt_else)
    loom_ok, loom_errors = loom_self_check_targets(bridge.loom_is_exec, [loom_tgt_then, loom_tgt_else])
    if not loom_ok:
        loom_site['reason'] = 'invalid target(s): ' + '; '.join(loom_errors)
        loom_site['self_check_ok'] = False
        loom_site['self_check_errors'] = loom_errors
        return loom_site
    loom_flag_mod_csel_br = loom_flag_mod_in_gap(loom_read_word, loom_csel_ea + 4, loom_br_ea)
    loom_site['flag_mod_csel_br'] = loom_flag_mod_csel_br
    loom_kind_value, loom_reason, loom_patch, clobber_scan = loom_classify_patch(loom_read_word, loom_br_ea, loom_ldr_ea, loom_cs.loom_cond, loom_tgt_then, loom_tgt_else, loom_flag_mod_csel_br)
    loom_site['kind'] = loom_kind_value
    loom_site['reason'] = loom_reason
    loom_site['patch'] = loom_patch
    loom_site['a_path_hazard'] = clobber_scan
    if loom_kind_value == 'resolved':
        loom_site['self_check_ok'] = True
    return loom_site

def loom_enabled(settings) -> bool:
    """Single-level detection is gated (it is a distinct obfuscation model from the
    two-level CFF core). Enabled by an explicit ``cff.single_level`` flag, or when
    an aggressive rewrite mode is selected. TODO(validate): confirm the desired
    gate — for now default is OFF so a plain `switch`-mode run never touches these.
    """
    if bool(settings.loom_cff.get('single_level', False)):
        return True
    return settings.loom_mode in ('linear', 'full')

def loom_find_single_level(bridge, settings) -> loom_List[loom_Dict]:
    """Locate every single-level CSEL/CSET + LDR + BR dispatch in the configured
    executable segments and return one dict per site.

    Returns ``[]`` (a no-op) unless single-level detection is enabled for this run
    (see :func:`loom_enabled`). Each returned dict carries the resolved indices, the
    two table targets, and — for a ``kind == 'resolved'`` site — a ``patch`` list of
    already-range-checked, round-trip-verified same-size branch rewrites. This
    function never writes bytes; a Tier-3 phase turns the plan into ``records.ByteRewrite``
    objects and applies them under the usual image_restore/strict-orig gates.
    """
    if not loom_enabled(settings):
        return []
    loom_read_word = loom_make_reader(bridge)
    loom_entry_size = settings.loom_entry_size
    loom_overrides = settings.loom_dispatch_base_overrides
    loom_allow = set(settings.loom_index_reg_allowlist)
    loom_sites: loom_List[loom_Dict] = []
    for loom_seg_start, loom_seg_end, loom_seg_name in bridge.loom_exec_segments(settings):
        address = loom_seg_start
        while address < loom_seg_end:
            loom_w = loom_read_word(address)
            if loom_w is not None and LOOM_D.loom_is_br(loom_w):
                try:
                    loom_site = loom_analyze_br(bridge, settings, loom_read_word, address, loom_w, loom_entry_size, loom_overrides, loom_allow, loom_seg_start)
                except Exception as loom_exc:
                    loom_site = {'model': 'single_level', 'br_ea': address, 'kind': 'skipped', 'reason': 'analysis error: %s: %s' % (type(loom_exc).__name__, loom_exc), 'patch': []}
                if loom_site is not None:
                    loom_sites.append(loom_site)
            address += 4
    return loom_sites

# TODO(validate): confirm these masks against a real dispatcher prologue on-device;
# TODO(validate): faithful to the reference's _FLAG_MOD_MNEMS set, but the raw
# TODO(validate): the reference also handled the case-(b) `[base, Xi]`

__all__ = [export_binding for export_binding in ['LOOM_D', 'LOOM_E', 'LOOM_MASK32', 'LOOM_MASK64', 'loom_Callable', 'loom_Dict', 'loom_List', 'loom_Optional', 'loom_Tuple', 'loom_a_path_hazard', 'loom_annotations', 'loom_find_reg_producer', 'loom_find_single_level', 'loom_resolve_const_reg', 'loom_reverse_words', 'loom_self_check_targets', 'loom_verify_branch_roundtrip'] if export_binding in globals()]
