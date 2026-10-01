"""
branchloom.dispatch_shapes.comparison_routes — OLLVM CMP-tree state machine (Model-2).

EXPERIMENTAL. This module ports the *structure* of the OLLVM control-flow-
flattening deflattener in
the private reference toolchain (``deobf_shellcode_cff.py``)
(``loom_find_loop_head`` / ``loom_scan_prologue_constants`` / ``loom_walk_dispatcher`` /
``loom_analyze_terminator`` / ``deflatten_function``) onto the target-agnostic Tier-1
layer. It is deliberately *analysis-only*: it recovers the dispatcher shape and
emits a recommended, round-trip-verified rewrite **plan**, but it NEVER patches
bytes and has NOT been validated against a real flattened function through this
port. Treat every recovered fact as a hypothesis until a phase verifies it behind
the behavioural oracle.

The obfuscator shape::

    prologue:  MOV/MOVK Wk,#magic ...            # state-magic constants
               STR Winit,[SP,#slot]              # seed the state variable
    loop_head: LDR Wstate,[SP,#slot]             # dispatcher state load
               CMP Wstate,#magic ; B.cc ...      # binary-search dispatch tree
    handler:   ... real work ...
               CSEL Wt,Wa,Wb,<cc> | MOV Wt,#k    # choose next state
               STR Wt,[Xstate]
               B loop_head

Deflattening replaces each ``STR next_state ; B loop_head`` terminator with a
direct branch to the handler that the dispatcher maps that state to.

Because the Tier-1 adapter exposes only a function's *start* (``loom_func_at``), the
scan window is bounded by a config knob rather than the true function end — see
the ``TODO(validate)`` notes and ``assumptions_todos``.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from ..arm_words import recognition as LOOM_D
from ..arm_words import emission as LOOM_E
from ..arm_words.value_chains import loom_resolve_const_reg as loom_resolve_const_reg
from ..arm_words.neighbourhood import loom_find_reg_producer as loom_find_reg_producer
from ..integrity.site_validation import loom_self_check_targets as loom_self_check_targets, loom_verify_branch_roundtrip as loom_verify_branch_roundtrip
LOOM_MASK32 = 4294967295
LOOM__DEFAULT_SCAN_INSNS = 4096
LOOM__TERM_WINDOW = 64

def loom_make_reader(bridge) -> loom_Callable[[int], loom_Optional[int]]:

    def loom_read_word(address: int) -> loom_Optional[int]:
        try:
            loom_w = bridge.loom_get_dword(address)
        except Exception:
            return None
        return None if loom_w is None else loom_w & LOOM_MASK32
    return loom_read_word

def loom_cmp_imm(opcode: int) -> loom_Optional[loom_Tuple[int, int]]:
    """Return (Rn, imm) for ``CMP Wn,#imm`` / ``CMP Xn,#imm`` else ``None``."""
    if opcode & 2139095071 == 1895825439:
        loom_rn = opcode >> 5 & 31
        loom_sh = LOOM_D.loom_bits(opcode, 23, 22)
        loom_imm = LOOM_D.loom_bits(opcode, 21, 10) << (12 if loom_sh == 1 else 0)
        return (loom_rn, loom_imm & LOOM_MASK32)
    return None

def loom_cmp_reg(opcode: int) -> loom_Optional[loom_Tuple[int, int]]:
    """Return (Rn, Rm) for ``CMP Wn,Wm`` (shifted-register, no shift) else ``None``."""
    if opcode & 2132803615 == 1795162143:
        loom_rn = opcode >> 5 & 31
        loom_rm = opcode >> 16 & 31
        return (loom_rn, loom_rm)
    return None

def loom_find_loop_head(loom_read_word, loom_start, loom_end) -> loom_Tuple[loom_Optional[int], loom_Optional[int]]:
    """The dispatcher loop head is the most-branched-to address inside the function
    that also decodes as a stack state-load. Returns (loop_head_ea, state_reg)."""
    loom_counts: loom_Dict[int, int] = {}
    address = loom_start
    while address < loom_end:
        loom_w = loom_read_word(address)
        if loom_w is not None:
            loom_t_value = None
            if LOOM_D.loom_is_b(loom_w):
                loom_t_value = LOOM_D.loom_b_target(address, loom_w)
            elif LOOM_D.loom_is_bcond(loom_w):
                loom_t_value = LOOM_D.loom_bcond_target(address, loom_w)
            if loom_t_value is not None and loom_start <= loom_t_value < loom_end:
                loom_counts[loom_t_value] = loom_counts.get(loom_t_value, 0) + 1
        address += 4
    for loom_t_value, loom_cnt in sorted(loom_counts.items(), key=lambda loom_kv: -loom_kv[1]):
        loom_w = loom_read_word(loom_t_value)
        if loom_w is None:
            continue
        loom_ml = LOOM_D.loom_state_load(loom_w)
        if loom_ml is not None and loom_ml.loom_kind_value in ('LDR_W', 'LDUR_W', 'LDRSW', 'LDURSW'):
            return (loom_t_value, loom_ml.loom_rt)
    return (None, None)

def loom_scan_prologue_constants(loom_read_word, loom_start, loom_boundary) -> loom_Dict[int, int]:
    """Build ``{reg: u32}`` for every W register given a materialised immediate in
    ``[start, boundary)`` via MOVZ(/MOVN) + MOVK slices. Port of
    ``loom_scan_prologue_constants``."""
    loom_regs: loom_Dict[int, int] = {}
    address = loom_start
    while address < loom_boundary:
        loom_w = loom_read_word(address)
        if loom_w is not None:
            loom_mv = LOOM_D.loom_move_imm_w(loom_w)
            if loom_mv is not None:
                if loom_mv.loom_kind_value in ('MOVZ', 'MOVN'):
                    loom_regs[loom_mv.loom_rd_value] = loom_mv.loom_imm & LOOM_MASK32
                else:
                    loom_shift = LOOM_D.loom_bits(loom_w, 22, 21) * 16
                    loom_slice_mask = 65535 << loom_shift & LOOM_MASK32
                    loom_cur = loom_regs.get(loom_mv.loom_rd_value, 0)
                    loom_regs[loom_mv.loom_rd_value] = (loom_cur & ~loom_slice_mask | loom_mv.loom_imm & loom_slice_mask) & LOOM_MASK32
        address += 4
    return loom_regs

def loom_magic_at(loom_read_word, loom_cmp_ea, loom_cmp_word, loom_state_reg, loom_prologue) -> loom_Optional[int]:
    """Resolve the constant a ``CMP Wstate, <op>`` compares against, or ``None``."""
    loom_ci = loom_cmp_imm(loom_cmp_word)
    if loom_ci is not None:
        loom_rn, loom_imm = loom_ci
        return loom_imm if loom_rn == loom_state_reg else None
    loom_cr = loom_cmp_reg(loom_cmp_word)
    if loom_cr is not None:
        loom_rn, loom_rm = loom_cr
        if loom_rn != loom_state_reg:
            return None
        loom_v = loom_resolve_const_reg(loom_read_word, loom_cmp_ea, loom_rm)
        if loom_v is not None:
            return loom_v
        return loom_prologue.get(loom_rm)
    return None

def loom_bcond_at_or_after(loom_read_word, address, loom_max_skip=6) -> loom_Optional[loom_Tuple[int, int, int]]:
    """From ``ea`` scan forward over flag-preserving ops for the first ``B.loom_cond``.
    Returns (bcond_ea, cond, target) or ``None`` if a flag write intervenes first."""
    loom_cur = address
    for _ in range(loom_max_skip):
        loom_w = loom_read_word(loom_cur)
        if loom_w is None:
            return None
        if LOOM_D.loom_is_bcond(loom_w):
            return (loom_cur, LOOM_D.loom_bcond_cond(loom_w), LOOM_D.loom_bcond_target(loom_cur, loom_w))
        if LOOM_D.loom_is_b(loom_w):
            return None
        loom_cur += 4
    return None

def loom_walk_dispatcher(loom_read_word, loom_loop_head, loom_state_reg, loom_start, loom_end, loom_prologue) -> loom_Dict[int, int]:
    """Recover ``{magic -> handler_ea}`` by a BST-directed walk from ``loop_head``.

    Simplified port of ``loom_walk_dispatcher``: at each ``CMP Wstate,K`` + ``B.cc`` we
    claim ``magic[K] -> handler`` for the EQ case (and the fall-through for NE), and
    queue non-EQ subtree targets. Handler bodies are not scanned (they reuse the
    state register as scratch and would pollute the map).
    TODO(validate): the tree traversal is heuristic and unverified through this port.
    """
    loom_mapping: loom_Dict[int, int] = {}
    loom_visited = set()
    loom_worklist: loom_List[int] = [loom_loop_head]
    while loom_worklist:
        address = loom_worklist.pop()
        while loom_start <= address < loom_end:
            if address in loom_visited:
                break
            loom_visited.add(address)
            loom_w = loom_read_word(address)
            if loom_w is None:
                break
            loom_ml = LOOM_D.loom_state_load(loom_w)
            if loom_ml is not None and loom_ml.loom_rt == loom_state_reg:
                if address == loom_loop_head:
                    address += 4
                    continue
                break
            loom_ci = loom_cmp_imm(loom_w)
            loom_cr = loom_cmp_reg(loom_w)
            if loom_ci is not None or loom_cr is not None:
                loom_magic = loom_magic_at(loom_read_word, address, loom_w, loom_state_reg, loom_prologue)
                loom_bc = loom_bcond_at_or_after(loom_read_word, address + 4)
                if loom_bc is not None:
                    loom_bcc_ea, loom_cond, loom_tgt = loom_bc
                    loom_cname = LOOM_D.loom_cond_name(loom_cond)
                    if loom_magic is not None:
                        if loom_cname == 'EQ':
                            loom_mapping[loom_magic] = loom_tgt
                        elif loom_cname == 'NE':
                            loom_mapping[loom_magic] = loom_bcc_ea + 4
                    if loom_cname != 'EQ' and loom_tgt != loom_loop_head and (loom_start <= loom_tgt < loom_end):
                        loom_worklist.append(loom_tgt)
                    address = loom_bcc_ea + 4
                    continue
                address += 4
                continue
            if LOOM_D.loom_is_b(loom_w):
                loom_t_value = LOOM_D.loom_b_target(address, loom_w)
                if loom_t_value == loom_loop_head:
                    break
                loom_nxt = loom_read_word(loom_t_value)
                if loom_nxt is not None and (loom_cmp_imm(loom_nxt) or loom_cmp_reg(loom_nxt)):
                    loom_worklist.append(loom_t_value)
                break
            if LOOM_D.loom_is_bcond(loom_w):
                address += 4
                continue
            break
    return loom_mapping

def loom_analyze_terminator(loom_read_word, loom_b_loop_ea, loom_handler_start, loom_prologue):
    """Classify the ``STR next_state ; B loop_head`` terminator at ``b_loop_ea``.

    Returns one of:
      ``('uncond', magic, str_ea)``
      ``('cond', magic_then, magic_else, cond, csel_ea, str_ea)``
      ``None`` (unrecognised).
    Port of ``loom_analyze_terminator`` using decode.store_to_slot / cond_select_w /
    move_imm_w and const_resolve for the magic values.
    """
    loom_str_ea = None
    loom_src_reg = None
    for loom_back in range(1, LOOM__TERM_WINDOW):
        loom_cur = loom_b_loop_ea - 4 * loom_back
        if loom_cur < loom_handler_start:
            break
        loom_w = loom_read_word(loom_cur)
        if loom_w is None:
            break
        loom_ms = LOOM_D.loom_store_to_slot(loom_w)
        if loom_ms is not None:
            loom_str_ea = loom_cur
            loom_src_reg = loom_ms.loom_rt
            break
    if loom_str_ea is None:
        return None
    loom_def_ea = loom_find_reg_producer(loom_read_word, loom_str_ea, loom_src_reg, loom_max_insns=LOOM__TERM_WINDOW)
    if loom_def_ea is None:
        loom_val = loom_prologue.get(loom_src_reg)
        return ('uncond', loom_val, loom_str_ea) if loom_val is not None else None
    loom_dw = loom_read_word(loom_def_ea)
    if loom_dw is None:
        return None
    loom_cs = LOOM_D.loom_cond_select_w(loom_dw)
    if loom_cs is not None:
        loom_va = loom_resolve_const_reg(loom_read_word, loom_def_ea, loom_cs.loom_rn)
        loom_vb_raw = loom_resolve_const_reg(loom_read_word, loom_def_ea, loom_cs.loom_rm)
        if loom_va is None or loom_vb_raw is None:
            return None
        if loom_cs.loom_op == 'CSEL':
            loom_vb = loom_vb_raw
        elif loom_cs.loom_op == 'CSINC':
            loom_vb = loom_vb_raw + 1 & LOOM_MASK32
        elif loom_cs.loom_op == 'CSINV':
            loom_vb = ~loom_vb_raw & LOOM_MASK32
        else:
            loom_vb = -loom_vb_raw & LOOM_MASK32
        return ('cond', loom_va & LOOM_MASK32, loom_vb, loom_cs.loom_cond, loom_def_ea, loom_str_ea)
    loom_val = loom_resolve_const_reg(loom_read_word, loom_str_ea, loom_src_reg)
    return ('uncond', loom_val, loom_str_ea) if loom_val is not None else None

def loom_scan_end(settings, loom_start: int) -> int:
    loom_n_value = int(settings.loom_cff.get('ollvm_scan_insns', LOOM__DEFAULT_SCAN_INSNS))
    return loom_start + loom_n_value * 4

def loom_deflatten_ollvm(bridge, settings, loom_fn_ea) -> loom_Dict:
    """EXPERIMENTAL analysis of one OLLVM-flattened function at ``fn_ea``.

    Recovers the dispatcher (loop head + state register + magic->handler map) and
    the per-handler next-state terminators, then emits a recommended rewrite
    **plan** (a list of same-size, round-trip-verified branch patches). It does NOT
    apply anything — the caller is responsible for verifying every plan entry
    behind the behavioural oracle before it is ever written.

    Returns a summary dict; ``status`` is always ``'experimental'``.
    """
    loom_read_word = loom_make_reader(bridge)
    loom_parent = bridge.loom_func_at(loom_fn_ea)
    loom_start = loom_parent[0] if loom_parent else loom_fn_ea
    label = loom_parent[1] if loom_parent else None
    loom_end = loom_scan_end(settings, loom_start)
    loom_result: loom_Dict = {'model': 'ollvm_statemachine', 'status': 'experimental', 'applied': False, 'fn_ea': loom_start, 'fn_name': label, 'scan_end': loom_end, 'loop_head': None, 'state_reg': None, 'prologue_magics': 0, 'handlers_mapped': 0, 'dispatch_map': {}, 'terminators': [], 'plan': [], 'unresolved': [], 'reason': ''}
    loom_loop_head, loom_state_reg = loom_find_loop_head(loom_read_word, loom_start, loom_end)
    if loom_loop_head is None:
        loom_result['reason'] = 'no dispatcher loop head found in scan window'
        return loom_result
    loom_result['loop_head'] = loom_loop_head
    loom_result['state_reg'] = loom_state_reg
    loom_prologue = loom_scan_prologue_constants(loom_read_word, loom_start, loom_loop_head)
    loom_result['prologue_magics'] = len(loom_prologue)
    loom_mapping = loom_walk_dispatcher(loom_read_word, loom_loop_head, loom_state_reg, loom_start, loom_end, loom_prologue)
    loom_result['handlers_mapped'] = len(loom_mapping)
    loom_result['dispatch_map'] = {'0x%x' % loom_k: '0x%x' % loom_v for loom_k, loom_v in loom_mapping.items()}
    if not loom_mapping:
        loom_result['reason'] = 'empty dispatcher map'
        return loom_result
    address = loom_loop_head
    while address < loom_end:
        loom_w = loom_read_word(address)
        if loom_w is None:
            address += 4
            continue
        if LOOM_D.loom_is_b(loom_w) and LOOM_D.loom_b_target(address, loom_w) == loom_loop_head:
            loom_res = loom_analyze_terminator(loom_read_word, address, loom_loop_head, loom_prologue)
            if loom_res is None:
                loom_result['unresolved'].append({'b_loop_ea': '0x%x' % address, 'reason': 'unclassified terminator'})
            elif loom_res[0] == 'uncond':
                loom_kind, loom_magic, loom_str_ea = loom_res
                loom_dst = loom_mapping.get(loom_magic) if loom_magic is not None else None
                if loom_dst is None:
                    loom_result['unresolved'].append({'b_loop_ea': '0x%x' % address, 'reason': 'uncond state 0x%s not in map' % ('%x' % loom_magic if loom_magic is not None else '?')})
                else:
                    loom_plan_uncond(loom_result, bridge, loom_str_ea, address, loom_dst, loom_magic)
            else:
                loom_kind, loom_va, loom_vb, loom_cond, loom_csel_ea, loom_str_ea = loom_res
                loom_dst_a, loom_dst_b = (loom_mapping.get(loom_va), loom_mapping.get(loom_vb))
                if loom_dst_a is None or loom_dst_b is None:
                    loom_result['unresolved'].append({'b_loop_ea': '0x%x' % address, 'reason': 'cond states 0x%x/0x%x not both in map' % (loom_va, loom_vb)})
                else:
                    loom_plan_cond(loom_result, bridge, loom_csel_ea, loom_str_ea, address, loom_dst_a, loom_dst_b, loom_cond, loom_va, loom_vb)
        address += 4
    loom_result['reason'] = 'ok (experimental — plan NOT applied)'
    return loom_result

def loom_plan_uncond(loom_result, bridge, loom_str_ea, loom_b_loop_ea, loom_dst, loom_magic) -> None:
    """Recommended rewrite for an unconditional next-state: ``B dst`` in the STR
    slot, ``NOP`` in the ``B loop_head`` slot. Not applied."""
    loom_ok, loom_errors = loom_self_check_targets(bridge.loom_is_exec, [loom_dst])
    if not loom_ok:
        loom_result['unresolved'].append({'b_loop_ea': '0x%x' % loom_b_loop_ea, 'reason': 'invalid target: ' + '; '.join(loom_errors)})
        return
    loom_w = LOOM_E.emit_jump(loom_str_ea, loom_dst)
    if loom_w is None or not loom_verify_branch_roundtrip(loom_str_ea, loom_w, loom_dst):
        loom_result['unresolved'].append({'b_loop_ea': '0x%x' % loom_b_loop_ea, 'reason': 'B out of range'})
        return
    loom_result['terminators'].append({'kind': 'uncond', 'b_loop_ea': '0x%x' % loom_b_loop_ea, 'via_state': '0x%x' % (loom_magic or 0), 'target': '0x%x' % loom_dst})
    loom_result['plan'].append({'pc': loom_str_ea, 'target': loom_dst, 'new_word': loom_w, 'new_bytes_hex': LOOM_E.opcode_bytes(loom_w).hex(), 'reason': 'OLLVM-uncond'})
    loom_result['plan'].append({'pc': loom_b_loop_ea, 'target': None, 'new_word': LOOM_E.LOOM_ARM64_NOP, 'new_bytes_hex': LOOM_E.opcode_bytes(LOOM_E.LOOM_ARM64_NOP).hex(), 'reason': 'OLLVM-nop-loopback'})

def loom_plan_cond(loom_result, bridge, loom_csel_ea, loom_str_ea, loom_b_loop_ea, loom_dst_a, loom_dst_b, loom_cond, loom_va, loom_vb) -> None:
    """Recommended rewrite for a CSEL-driven two-way next-state: ``B.loom_cond dst_a`` in
    the CSEL slot, ``B dst_b`` in the STR slot, ``NOP`` in the loop-back slot. Not
    applied. TODO(validate): assumes the CSEL flags are still live at its own slot
    (true when the CSEL is the terminator's own compare); shared-tail predecessors
    (the reference's post-pass) are NOT handled here."""
    loom_ok, loom_errors = loom_self_check_targets(bridge.loom_is_exec, [loom_dst_a, loom_dst_b])
    if not loom_ok:
        loom_result['unresolved'].append({'b_loop_ea': '0x%x' % loom_b_loop_ea, 'reason': 'invalid target(s): ' + '; '.join(loom_errors)})
        return
    loom_w_bcc = LOOM_E.emit_conditional_jump(loom_csel_ea, loom_dst_a, loom_cond)
    loom_w_b = LOOM_E.emit_jump(loom_str_ea, loom_dst_b)
    if loom_w_bcc is None or loom_w_b is None or (not loom_verify_branch_roundtrip(loom_csel_ea, loom_w_bcc, loom_dst_a)) or (not loom_verify_branch_roundtrip(loom_str_ea, loom_w_b, loom_dst_b)):
        loom_result['unresolved'].append({'b_loop_ea': '0x%x' % loom_b_loop_ea, 'reason': 'cond branch out of range'})
        return
    loom_result['terminators'].append({'kind': 'cond', 'b_loop_ea': '0x%x' % loom_b_loop_ea, 'cond': LOOM_D.loom_cond_name(loom_cond), 'state_then': '0x%x' % loom_va, 'state_else': '0x%x' % loom_vb, 'target_then': '0x%x' % loom_dst_a, 'target_else': '0x%x' % loom_dst_b})
    loom_result['plan'].append({'pc': loom_csel_ea, 'target': loom_dst_a, 'new_word': loom_w_bcc, 'new_bytes_hex': LOOM_E.opcode_bytes(loom_w_bcc).hex(), 'reason': 'OLLVM-cond-bcc'})
    loom_result['plan'].append({'pc': loom_str_ea, 'target': loom_dst_b, 'new_word': loom_w_b, 'new_bytes_hex': LOOM_E.opcode_bytes(loom_w_b).hex(), 'reason': 'OLLVM-cond-b'})
    loom_result['plan'].append({'pc': loom_b_loop_ea, 'target': None, 'new_word': LOOM_E.LOOM_ARM64_NOP, 'new_bytes_hex': LOOM_E.opcode_bytes(LOOM_E.LOOM_ARM64_NOP).hex(), 'reason': 'OLLVM-nop-loopback'})

# TODO(validate): these masks are derived from the ARM ARM but unexercised here.

__all__ = [export_binding for export_binding in ['LOOM_D', 'LOOM_E', 'LOOM_MASK32', 'loom_Callable', 'loom_Dict', 'loom_List', 'loom_Optional', 'loom_Tuple', 'loom_annotations', 'loom_deflatten_ollvm', 'loom_find_reg_producer', 'loom_resolve_const_reg', 'loom_self_check_targets', 'loom_verify_branch_roundtrip'] if export_binding in globals()]
