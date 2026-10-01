"""
branchloom.dispatch_shapes.filler_repair — anti-disassembly cleanup (trap-BLR + DCB filler).

Faithful port of the two stage-1 cleanups proven in
the private reference toolchain (``nop_dead_bytes.py``)
(``fold_trap_blr`` / ``_scan_trap_blr`` and the DCB-filler ``run`` / ``_plan``)
and the dead-slot NOP logic in
``.../misc/deobf/deobf_br_dispatch.py``. Re-expressed against the injected
``adapter`` (the only IDA boundary) plus the pure-Python
:mod:`branchloom.arm_words.recognition` / :mod:`branchloom.arm_words.emission` layers, so nothing
target-specific is baked in.

Two transforms, both 4-bytes-for-4-bytes and reversible from the returned log:

1. **trap-BLR fold** — the obfuscator hides a dispatcher terminator behind a
   PC-relative literal load followed by an indirect call::

        LDR  Xn, loc_LIT        ; LDR (literal), 64-bit  (opc=01, top byte 0x58)
        BLR  Xn

   ``loc_LIT`` is itself adjacent *code* bytes, so the BLR jumps to a "wild"
   value; the sequence is dead-or-crash camouflage that stops IDA's sweep and
   fabricates a bogus data xref into the code. We rewrite it to the real edge::

        B    loc_LIT
        NOP

2. **DCB filler NOP** — short runs of undecodable bytes wedged between real
   instructions to break the linear sweep. A run is NOP-ed only when it is
   short and sandwiched between decodable instructions (see ``loom_plausible_insn``),
   which keeps genuine literal pools / data tables untouched.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional
from ..arm_words import recognition as LOOM_D
from ..arm_words import emission as LOOM_E
__all__ = ['loom_clean_range']
LOOM__MAX_DCB_RUN_BYTES = 8

def loom_is_ldr_lit_x(opcode: int) -> bool:
    """``LDR Xt, label`` — PC-relative literal load, 64-bit (opc=01, byte 0x58).

    Straight ARM ARM (C6.2.119) decode; recognition.py models only register-offset and
    base+imm loads, not the literal form, so it is recognised locally here.
    """
    return opcode & 4278190080 == 1476395008

def loom_ldr_lit_target(location: int, opcode: int) -> int:
    """Literal-pool EA for an ``LDR (literal)`` word: ``pc + SignExtend(imm19:00)``."""
    loom_imm19 = opcode >> 5 & 524287
    return location + (LOOM_D.loom_sign_extend(loom_imm19, 19) << 2)

def loom_plausible_insn(opcode: int) -> bool:
    """True if ``word`` sits in an *allocated* A64 top-level encoding group.

    The AArch64 main encoding table (ARM ARM C4.1) keys on ``op1`` = bits[28:25];
    exactly three values are Reserved / Unallocated: ``0b0000``, ``0b0001`` and
    ``0b0011``. Everything else is a real instruction group (DP-immediate,
    branch/system, loads/stores, DP-register, SIMD/FP, SVE). Anti-disassembly
    filler such as the reference's ``0xA2F2FFF1`` lands in ``op1 == 0b0001`` and
    is therefore flagged as junk, while any genuine instruction is preserved.

    Deliberately conservative: an unallocated *sub*-encoding inside an allocated
    group still reports plausible, so we never NOP something that might be code.
    """
    loom_op1 = opcode >> 25 & 15
    return loom_op1 not in (0, 1, 3)

def loom_make_reader(bridge) -> loom_Callable[[int], loom_Optional[int]]:

    def loom_read_value(address: int) -> loom_Optional[int]:
        if address < 0:
            return None
        try:
            return bridge.loom_get_dword(address) & 4294967295
        except Exception:
            return None
    return loom_read_value

def loom_fold_trap_blr(bridge, loom_read_value: loom_Callable[[int], loom_Optional[int]], loom_start: int, loom_end: int) -> loom_List[loom_Dict]:
    loom_folds: loom_List[loom_Dict] = []
    address = loom_start & ~3
    while address + 8 <= loom_end:
        loom_w1 = loom_read_value(address)
        loom_w2 = loom_read_value(address + 4)
        if loom_w1 is None or loom_w2 is None:
            address += 4
            continue
        if loom_is_ldr_lit_x(loom_w1) and LOOM_D.loom_is_blr(loom_w2) and (loom_w1 & 31 == LOOM_D.loom_br_rn(loom_w2)):
            loom_lit_ea = loom_ldr_lit_target(address, loom_w1)
            if loom_lit_ea & 3 == 0 and bridge.loom_is_exec(loom_lit_ea):
                loom_tgt_word = loom_read_value(loom_lit_ea)
                loom_benc = LOOM_E.emit_jump(address, loom_lit_ea)
                if loom_benc is not None and loom_tgt_word is not None and loom_plausible_insn(loom_tgt_word):
                    loom_orig = bridge.loom_get_bytes(address, 8)
                    loom_new = LOOM_E.opcode_bytes(loom_benc) + LOOM_E.opcode_bytes(LOOM_E.LOOM_ARM64_NOP)
                    bridge.loom_patch_bytes(address, loom_new)
                    bridge.loom_make_code(address)
                    bridge.loom_make_code(address + 4)
                    loom_folds.append({'addr': loom_hx(address), 'lit': loom_hx(loom_lit_ea), 'orig': loom_orig.hex() if loom_orig else '', 'new': loom_new.hex()})
                    address += 8
                    continue
        address += 4
    return loom_folds

def loom_nop_dcb_filler(bridge, loom_read_value: loom_Callable[[int], loom_Optional[int]], loom_start: int, loom_end: int) -> loom_List[loom_Dict]:
    loom_nops: loom_List[loom_Dict] = []
    loom_max_slots = LOOM__MAX_DCB_RUN_BYTES // 4
    address = loom_start & ~3
    loom_prev_ok = False
    while address + 4 <= loom_end:
        opcode = loom_read_value(address)
        if opcode is None:
            loom_prev_ok = False
            address += 4
            continue
        if loom_plausible_insn(opcode):
            loom_prev_ok = True
            address += 4
            continue
        if not loom_prev_ok:
            loom_prev_ok = False
            address += 4
            continue
        execute_stage: loom_List[int] = []
        loom_run_ea = address
        while loom_run_ea + 4 <= loom_end and len(execute_stage) < loom_max_slots:
            loom_w = loom_read_value(loom_run_ea)
            if loom_w is None or loom_plausible_insn(loom_w):
                break
            execute_stage.append(loom_run_ea)
            loom_run_ea += 4
        loom_follow = loom_read_value(loom_run_ea)
        loom_followed_by_code = loom_follow is not None and loom_plausible_insn(loom_follow)
        if execute_stage and loom_followed_by_code:
            for loom_slot in execute_stage:
                loom_orig = bridge.loom_get_bytes(loom_slot, 4)
                bridge.loom_patch_bytes(loom_slot, LOOM_E.opcode_bytes(LOOM_E.LOOM_ARM64_NOP))
                bridge.loom_make_code(loom_slot)
                loom_nops.append({'addr': loom_hx(loom_slot), 'orig': loom_orig.hex() if loom_orig else ''})
            loom_prev_ok = True
            address = loom_run_ea
            continue
        loom_prev_ok = loom_followed_by_code
        address = loom_run_ea if loom_run_ea > address else address + 4
    return loom_nops

def loom_hx(loom_v: int) -> str:
    return '0x%x' % loom_v

def loom_clean_range(bridge, loom_start: int, loom_end: int) -> loom_Dict:
    """Fold trap-BLR pairs and NOP DCB filler across ``[start, end)``.

    ``adapter`` is the IDA boundary; ``start``/``end`` bound a (typically
    executable) range chosen by the caller. Returns a summary/reversal log::

        {"folded": N, "nopped": M,
         "trap_blr_folds": [{"addr","lit","orig","new"}, ...],
         "dcb_nops":       [{"addr","orig"}, ...]}
    """
    loom_read_value = loom_make_reader(bridge)
    loom_folds = loom_fold_trap_blr(bridge, loom_read_value, loom_start, loom_end)
    loom_nops = loom_nop_dcb_filler(bridge, loom_read_value, loom_start, loom_end)
    return {'folded': len(loom_folds), 'nopped': len(loom_nops), 'trap_blr_folds': loom_folds, 'dcb_nops': loom_nops}
