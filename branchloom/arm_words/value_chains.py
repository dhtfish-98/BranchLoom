"""
branchloom.arm_words.value_chains — bounded constant-register resolution (no IDA).

Given a ``loom_read_word(ea) -> int|None`` callable and a use site, resolve the
*constant* 32-bit value a register holds there, following the derivation chains an
obfuscator emits to hide a plain immediate:

    MOVZ / MOV #imm ............... immediate load
    MOVN #imm ..................... bitwise-NOT immediate
    MOVZ + MOVK (slice merge) ..... 16-bit slice written over a prior value
    MOV Wd, Wm .................... register copy (follow the source)
    ORR Wd, Wn, #imm / Wn, Wm ..... bit-or with an immediate or another reg
    EOR Wd, Wn, #imm / Wn, Wm ..... bit-xor with an immediate or another reg
    EOR(ADD(Wy,#k), Wy) ........... carry-safe xor-of-add idiom -> k (or exact)
    ADD/SUB Wd, Wn, #imm .......... additive chains (multi-pass via recursion)

The resolver is *exact and conservative*: every arithmetic step is computed in
32-bit modular arithmetic and any writer it does not model returns ``None`` — it
NEVER guesses a value. Recursion is bounded by ``max_depth`` and the back-walk is
bounded by a fixed instruction window, so the search always terminates.

Register numbers are the raw AArch64 encoding (0..31, 31 == XZR/WZR), matching
``branchloom.arm_words.recognition``. No IDA, no target-specific values.

Ported from ``_resolve_const_reg`` in
the private reference toolchain (``deobf_br_dispatch.py``) (which parsed
IDA disasm strings + used IDA register ids); here every producer is recognised via
``branchloom.arm_words.recognition`` bit-pattern predicates instead.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, Optional as loom_Optional, Tuple as loom_Tuple
from . import recognition as LOOM_D
from .neighbourhood import loom_reverse_words as loom_reverse_words
__all__ = ['loom_resolve_const_reg']
LOOM_MASK32 = 4294967295
LOOM__SCAN_INSNS = 128
LOOM__LOGREG_MASK = 4292934656
LOOM__ORR_REG_MATCH = 704643072
LOOM__EOR_REG_MATCH = 1241513984

def loom_logreg_fields(opcode: int) -> loom_Tuple[int, int]:
    """Return (rn, rm) for a plain shifted-register logical op (caller checks op)."""
    loom_rn = opcode >> 5 & 31
    loom_rm = opcode >> 16 & 31
    return (loom_rn, loom_rm)

def loom_is_orr_reg(opcode: int) -> bool:
    return opcode & LOOM__LOGREG_MASK == LOOM__ORR_REG_MATCH

def loom_is_eor_reg(opcode: int) -> bool:
    return opcode & LOOM__LOGREG_MASK == LOOM__EOR_REG_MATCH

def loom_find_producer(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_at_ea: int, loom_reg: int) -> loom_Optional[int]:
    for address, opcode in loom_reverse_words(loom_read_word, loom_at_ea - 4, LOOM__SCAN_INSNS):
        if opcode is None:
            return None
        if LOOM_D.loom_is_bl(opcode) or LOOM_D.loom_is_blr(opcode):
            if LOOM_D.loom_writes_reg(opcode, loom_reg):
                return None
            continue
        if LOOM_D.loom_writes_reg(opcode, loom_reg):
            return address
        if opcode & 31 == loom_reg and (loom_is_orr_reg(opcode) or loom_is_eor_reg(opcode)):
            return address
    return None

def loom_resolve_const_reg(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_at_ea: int, loom_reg: int, loom_max_depth: int=4) -> loom_Optional[int]:
    """Resolve the constant 32-bit value of ``reg`` as live at ``at_ea``.

    Returns the value masked to 32 bits, or ``None`` if it cannot be proven
    constant within the depth/scan bounds. Never guesses.
    """
    return loom_resolve(loom_read_word, loom_at_ea, loom_reg, loom_max_depth)

def loom_resolve(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_at_ea: int, loom_reg: int, loom_depth: int) -> loom_Optional[int]:
    if loom_depth < 0:
        return None
    if loom_reg == LOOM_D.LOOM_ZR:
        return 0
    loom_prod = loom_find_producer(loom_read_word, loom_at_ea, loom_reg)
    if loom_prod is None:
        return None
    opcode = loom_read_word(loom_prod)
    if opcode is None:
        return None
    loom_mv = LOOM_D.loom_move_imm_w(opcode)
    if loom_mv is not None:
        if loom_mv.loom_kind_value in ('MOVZ', 'MOVN'):
            return loom_mv.loom_imm & LOOM_MASK32
        loom_base_value = loom_resolve(loom_read_word, loom_prod, loom_reg, loom_depth - 1)
        if loom_base_value is None:
            return None
        loom_hw = LOOM_D.loom_bits(opcode, 22, 21)
        loom_shift = loom_hw * 16
        loom_slice_mask = 65535 << loom_shift & LOOM_MASK32
        return (loom_base_value & ~loom_slice_mask | loom_mv.loom_imm & loom_slice_mask) & LOOM_MASK32
    if LOOM_D.loom_is_mov_reg_w(opcode):
        loom_rd, loom_rm = LOOM_D.loom_mov_reg_w_fields(opcode)
        return loom_resolve(loom_read_word, loom_prod, loom_rm, loom_depth - 1)
    loom_ai = LOOM_D.loom_alu_imm_w(opcode)
    if loom_ai is not None:
        if loom_ai.loom_op not in ('ADD', 'SUB', 'ORR', 'EOR'):
            return None
        loom_base_value = loom_resolve(loom_read_word, loom_prod, loom_ai.loom_rn, loom_depth - 1)
        if loom_base_value is None:
            return None
        if loom_ai.loom_op == 'ADD':
            return loom_base_value + loom_ai.loom_imm & LOOM_MASK32
        if loom_ai.loom_op == 'SUB':
            return loom_base_value - loom_ai.loom_imm & LOOM_MASK32
        if loom_ai.loom_op == 'ORR':
            return (loom_base_value | loom_ai.loom_imm) & LOOM_MASK32
        return (loom_base_value ^ loom_ai.loom_imm) & LOOM_MASK32
    if loom_is_orr_reg(opcode):
        loom_rn, loom_rm = loom_logreg_fields(opcode)
        loom_a = loom_resolve(loom_read_word, loom_prod, loom_rn, loom_depth - 1)
        loom_b = loom_resolve(loom_read_word, loom_prod, loom_rm, loom_depth - 1)
        if loom_a is None or loom_b is None:
            return None
        return (loom_a | loom_b) & LOOM_MASK32
    if loom_is_eor_reg(opcode):
        loom_rn, loom_rm = loom_logreg_fields(opcode)
        loom_a = loom_resolve(loom_read_word, loom_prod, loom_rn, loom_depth - 1)
        loom_b = loom_resolve(loom_read_word, loom_prod, loom_rm, loom_depth - 1)
        if loom_a is not None and loom_b is not None:
            return (loom_a ^ loom_b) & LOOM_MASK32
        return loom_carry_safe_add_eor(loom_read_word, loom_prod, loom_rn, loom_rm, loom_depth - 1)
    return None

def loom_carry_safe_add_eor(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_eor_ea: int, loom_rn: int, loom_rm: int, loom_depth: int) -> loom_Optional[int]:
    """Resolve ``EOR(x, y)`` where one operand is ``ADD(other, #k)``.

    Tries both operand orderings. For the ordering where ``x`` is produced by
    ``ADD x, y, #k`` (immediate), we need ``y`` resolved to a constant; then:
        (y & k) == 0  -> result is exactly k        (no carry across k's bits)
        else          -> result is ((y + k) ^ y)    (exact, y known)
    Returns ``None`` if neither ordering matches or ``y`` is unresolved (never
    guesses).
    """
    if loom_depth < 0:
        return None
    for loom_x, loom_y in ((loom_rn, loom_rm), (loom_rm, loom_rn)):
        loom_x_prod = loom_find_producer(loom_read_word, loom_eor_ea, loom_x)
        if loom_x_prod is None:
            continue
        loom_xw = loom_read_word(loom_x_prod)
        if loom_xw is None:
            continue
        loom_ai = LOOM_D.loom_alu_imm_w(loom_xw)
        if loom_ai is None or loom_ai.loom_op != 'ADD' or loom_ai.loom_rn != loom_y:
            continue
        loom_y_val = loom_resolve(loom_read_word, loom_x_prod, loom_y, loom_depth)
        if loom_y_val is None:
            continue
        loom_k = loom_ai.loom_imm & LOOM_MASK32
        if loom_y_val & loom_k == 0:
            return loom_k
        return (loom_y_val + loom_k & LOOM_MASK32 ^ loom_y_val) & LOOM_MASK32
    return None

# TODO(validate): tune this window against a real flattened function — too small
