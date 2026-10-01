"""
branchloom.arm_words.recognition — pure-Python AArch64 instruction recognizers.

No IDA, no external deps. Every function takes a little-endian 32-bit instruction
word (``int``) and returns a bool predicate or an extracted-field object. Encodings
are expressed as ``(mask, match)`` pairs so the recognizer set is data-driven and
auditable against the ARM Architecture Reference Manual (C4.1, "A64 instruction set
encoding").

This is the target-agnostic foundation of the devirtualizer: the phase modules
never hard-code an opcode, they call these predicates. Unit-tested in
``tests/test_arm_words.py`` so the layer is verifiable without IDA.

Register numbering convention (matches the raw encoding): 0..30 = X0..X30 / W0..W30,
31 = XZR/WZR in most slots and SP/WSP in base-register slots. Callers that care
about the SP-vs-ZR distinction check the field position, exactly as the hardware does.
"""
from __future__ import annotations as loom_annotations
from dataclasses import dataclass as loom_dataclass
from typing import Optional as loom_Optional
from .logical_fields import logical_mask32 as logical_mask32
LOOM_ZR = 31
LOOM_SP = 31
LOOM_COND_NAMES = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC', 'HI', 'LS', 'GE', 'LT', 'GT', 'LE', 'AL', 'NV']

def loom_invert_cond(loom_cond: int) -> int:
    """Return the condition whose truth value is the negation of ``cond``."""
    return loom_cond ^ 1

def loom_cond_name(loom_cond: int) -> str:
    return LOOM_COND_NAMES[loom_cond & 15]

def loom_cond_num(label: str) -> loom_Optional[int]:
    label = label.upper()
    loom_alias = {'HS': 'CS', 'LO': 'CC'}
    label = loom_alias.get(label, label)
    return LOOM_COND_NAMES.index(label) if label in LOOM_COND_NAMES else None

def loom_bits(opcode: int, loom_hi: int, loom_lo: int) -> int:
    """Extract inclusive bit range [hi:lo]."""
    return opcode >> loom_lo & (1 << loom_hi - loom_lo + 1) - 1

def loom_sign_extend(loom_value: int, loom_nbits: int) -> int:
    loom_sign = 1 << loom_nbits - 1
    return (loom_value ^ loom_sign) - loom_sign

def loom_rd_value(opcode: int) -> int:
    return opcode & 31

def loom_rn(opcode: int) -> int:
    return opcode >> 5 & 31

def loom_rt(opcode: int) -> int:
    return opcode & 31

def loom_rm(opcode: int) -> int:
    return opcode >> 16 & 31

def loom_m(opcode: int, loom_mask: int, loom_match: int) -> bool:
    return opcode & loom_mask == loom_match

def loom_is_b(opcode: int) -> bool:
    return loom_m(opcode, 4227858432, 335544320)

def loom_is_bl(opcode: int) -> bool:
    return loom_m(opcode, 4227858432, 2483027968)

def loom_b_target(location: int, opcode: int) -> int:
    return location + loom_sign_extend(loom_bits(opcode, 25, 0) << 2, 28)

def loom_is_bcond(opcode: int) -> bool:
    return loom_m(opcode, 4278190096, 1409286144)

def loom_bcond_cond(opcode: int) -> int:
    return opcode & 15

def loom_bcond_target(location: int, opcode: int) -> int:
    return location + loom_sign_extend(loom_bits(opcode, 23, 5) << 2, 21)

def loom_is_cbz_cbnz(opcode: int) -> bool:
    return loom_m(opcode, 2113929216, 872415232)

def loom_is_tbz_tbnz(opcode: int) -> bool:
    return loom_m(opcode, 2113929216, 905969664)

def loom_is_br(opcode: int) -> bool:
    return loom_m(opcode, 4294966303, 3592355840)

def loom_is_blr(opcode: int) -> bool:
    return loom_m(opcode, 4294966303, 3594452992)

def loom_is_ret(opcode: int) -> bool:
    return loom_m(opcode, 4294966303, 3596550144)

def loom_br_rn(opcode: int) -> int:
    """Register operand of BR/BLR/RET (the dispatch target register for BR)."""
    return opcode >> 5 & 31

@loom_dataclass(frozen=True)
class IndexedRead:
    loom_rt: int
    loom_rn: int
    loom_rm: int
    span: int

def loom_is_ldr_reg_x_lsl3(opcode: int) -> bool:
    """``LDR Xt, [Xn, Xm, LSL #3]`` — the tgt-table (uint64) load.

    Extend-option-agnostic (UXTX/LSL/SXTX all accepted) but the S=1 scale bit is
    required, so only the *scaled* (LSL #3) register-offset form matches.
    """
    return loom_m(opcode, 4292877312, 4167047168)

def loom_is_ldrsw_reg_lsl2(opcode: int) -> bool:
    """``LDRSW Xt, [Xn, Wm, LSL #2]`` — the idx-table (int32) load.

    Extend-option-agnostic (UXTW/SXTW/LSL all accepted), S=1 scale required.
    """
    return loom_m(opcode, 4292877312, 3097499648)

def loom_reg_load_fields(opcode: int) -> IndexedRead:
    return IndexedRead(loom_rt=opcode & 31, loom_rn=opcode >> 5 & 31, loom_rm=opcode >> 16 & 31, span=8 if loom_is_ldr_reg_x_lsl3(opcode) else 4)

@loom_dataclass(frozen=True)
class OffsetAccess:
    loom_rt: int
    loom_rn: int
    loom_imm: int
    loom_kind_value: str

def loom_is_ldursw(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 3095396352)

def loom_is_ldrsw_uimm(opcode: int) -> bool:
    return loom_m(opcode, 4290772992, 3112173568)

def loom_is_ldr_x_uimm(opcode: int) -> bool:
    return loom_m(opcode, 4290772992, 4181721088)

def loom_is_ldur_x(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 4164943872)

def loom_is_ldr_w_uimm(opcode: int) -> bool:
    return loom_m(opcode, 4290772992, 3107979264)

def loom_is_ldur_w(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 3091202048)

def loom_is_str_w_uimm(opcode: int) -> bool:
    return loom_m(opcode, 4290772992, 3103784960)

def loom_is_stur_w(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 3087007744)

def loom_uimm_scaled(opcode: int, loom_scale: int) -> int:
    return loom_bits(opcode, 21, 10) * loom_scale

def loom_simm9(opcode: int) -> int:
    return loom_sign_extend(loom_bits(opcode, 20, 12), 9)

def loom_state_load(opcode: int) -> loom_Optional[OffsetAccess]:
    """
    Recognise any of the stack loads that can produce the dispatcher's int32
    state (or the XFORM scrambler's working W value). Returns None otherwise.
    """
    loom_base_value = opcode >> 5 & 31
    loom_dst = opcode & 31
    if loom_is_ldursw(opcode):
        return OffsetAccess(loom_dst, loom_base_value, loom_simm9(opcode), 'LDURSW')
    if loom_is_ldrsw_uimm(opcode):
        return OffsetAccess(loom_dst, loom_base_value, loom_uimm_scaled(opcode, 4), 'LDRSW')
    if loom_is_ldr_x_uimm(opcode):
        return OffsetAccess(loom_dst, loom_base_value, loom_uimm_scaled(opcode, 8), 'LDR_X')
    if loom_is_ldur_x(opcode):
        return OffsetAccess(loom_dst, loom_base_value, loom_simm9(opcode), 'LDUR_X')
    if loom_is_ldr_w_uimm(opcode):
        return OffsetAccess(loom_dst, loom_base_value, loom_uimm_scaled(opcode, 4), 'LDR_W')
    if loom_is_ldur_w(opcode):
        return OffsetAccess(loom_dst, loom_base_value, loom_simm9(opcode), 'LDUR_W')
    return None

def loom_store_to_slot(opcode: int) -> loom_Optional[OffsetAccess]:
    """Recognise ``STR/STUR Wt, [base, #imm]`` (the state write-back)."""
    loom_base_value = opcode >> 5 & 31
    loom_src = opcode & 31
    if loom_is_str_w_uimm(opcode):
        return OffsetAccess(loom_src, loom_base_value, loom_uimm_scaled(opcode, 4), 'STR_W')
    if loom_is_stur_w(opcode):
        return OffsetAccess(loom_src, loom_base_value, loom_simm9(opcode), 'STUR_W')
    return None

@loom_dataclass(frozen=True)
class ImmediateMove:
    loom_rd_value: int
    loom_imm: int
    loom_kind_value: str

def loom_is_movz_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 1384120320)

def loom_is_movn_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 310378496)

def loom_is_movk_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 1920991232)

def loom_move_imm_w(opcode: int) -> loom_Optional[ImmediateMove]:
    loom_hw = loom_bits(opcode, 22, 21)
    loom_imm16 = loom_bits(opcode, 20, 5)
    loom_shift = loom_hw * 16
    loom_dst = opcode & 31
    if loom_is_movz_w(opcode):
        return ImmediateMove(loom_dst, loom_imm16 << loom_shift & 4294967295, 'MOVZ')
    if loom_is_movn_w(opcode):
        return ImmediateMove(loom_dst, ~(loom_imm16 << loom_shift) & 4294967295, 'MOVN')
    if loom_is_movk_w(opcode):
        return ImmediateMove(loom_dst, loom_imm16 << loom_shift, 'MOVK')
    return None

def loom_is_mov_reg_w(opcode: int) -> bool:
    """``MOV Wd, Wm`` == ``ORR Wd, WZR, Wm`` (no shift)."""
    return loom_m(opcode, 4292935648, 704644064)

def loom_mov_reg_w_fields(opcode: int) -> tuple:
    """Return (rd, rm) for a ``MOV Wd, Wm`` alias."""
    return (opcode & 31, opcode >> 16 & 31)

@loom_dataclass(frozen=True)
class ConditionalChoice:
    loom_rd_value: int
    loom_rn: int
    loom_rm: int
    loom_cond: int
    loom_op: str
    loom_alias: loom_Optional[str] = None

def loom_is_csel_w(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 444596224)

def loom_is_csinc_w(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 444597248)

def loom_is_csinv_w(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 1518338048)

def loom_is_csneg_w(opcode: int) -> bool:
    return loom_m(opcode, 4292873216, 1518339072)

def loom_cond_select_w(opcode: int) -> loom_Optional[ConditionalChoice]:
    """
    Decode the 32-bit conditional-select family, recognising the common aliases
    (CSET/CSETM/CINC/CINV/CNEG) that obfuscators emit as 1-of-N state producers.
    """
    loom_d_value, loom_n_value, loom_m_value = (opcode & 31, opcode >> 5 & 31, opcode >> 16 & 31)
    loom_cond = loom_bits(opcode, 15, 12)
    if loom_is_csel_w(opcode):
        return ConditionalChoice(loom_d_value, loom_n_value, loom_m_value, loom_cond, 'CSEL')
    if loom_is_csinc_w(opcode):
        loom_alias = 'CSET' if loom_n_value == LOOM_ZR and loom_m_value == LOOM_ZR and (loom_cond & 14 != 14) else 'CINC' if loom_n_value == loom_m_value else None
        return ConditionalChoice(loom_d_value, loom_n_value, loom_m_value, loom_cond, 'CSINC', loom_alias)
    if loom_is_csinv_w(opcode):
        loom_alias = 'CSETM' if loom_n_value == LOOM_ZR and loom_m_value == LOOM_ZR and (loom_cond & 14 != 14) else 'CINV' if loom_n_value == loom_m_value else None
        return ConditionalChoice(loom_d_value, loom_n_value, loom_m_value, loom_cond, 'CSINV', loom_alias)
    if loom_is_csneg_w(opcode):
        loom_alias = 'CNEG' if loom_n_value == loom_m_value else None
        return ConditionalChoice(loom_d_value, loom_n_value, loom_m_value, loom_cond, 'CSNEG', loom_alias)
    return None

@loom_dataclass(frozen=True)
class ArithmeticImmediate:
    loom_rd_value: int
    loom_rn: int
    loom_imm: int
    loom_op: str

def loom_is_add_imm_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 285212672)

def loom_is_sub_imm_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 1358954496)

def loom_is_eor_imm_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 1375731712)

def loom_is_and_imm_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 301989888)

def loom_is_orr_imm_w(opcode: int) -> bool:
    return loom_m(opcode, 4286578688, 838860800)

def loom_alu_imm_w(opcode: int) -> loom_Optional[ArithmeticImmediate]:
    loom_d_value, loom_n_value = (opcode & 31, opcode >> 5 & 31)
    if loom_is_add_imm_w(opcode):
        loom_sh = loom_bits(opcode, 23, 22)
        loom_imm = loom_bits(opcode, 21, 10) << (12 if loom_sh == 1 else 0)
        return ArithmeticImmediate(loom_d_value, loom_n_value, loom_imm, 'ADD')
    if loom_is_sub_imm_w(opcode):
        loom_sh = loom_bits(opcode, 23, 22)
        loom_imm = loom_bits(opcode, 21, 10) << (12 if loom_sh == 1 else 0)
        return ArithmeticImmediate(loom_d_value, loom_n_value, loom_imm, 'SUB')
    if loom_is_eor_imm_w(opcode):
        loom_v = logical_mask32(opcode)
        return None if loom_v is None else ArithmeticImmediate(loom_d_value, loom_n_value, loom_v, 'EOR')
    if loom_is_and_imm_w(opcode):
        loom_v = logical_mask32(opcode)
        return None if loom_v is None else ArithmeticImmediate(loom_d_value, loom_n_value, loom_v, 'AND')
    if loom_is_orr_imm_w(opcode):
        loom_v = logical_mask32(opcode)
        return None if loom_v is None else ArithmeticImmediate(loom_d_value, loom_n_value, loom_v, 'ORR')
    return None

def loom_is_adr(opcode: int) -> bool:
    return loom_m(opcode, 2667577344, 268435456)

def loom_is_adrp(opcode: int) -> bool:
    return loom_m(opcode, 2667577344, 2415919104)

def loom_adr_imm(opcode: int) -> int:
    loom_immlo = loom_bits(opcode, 30, 29)
    loom_immhi = loom_bits(opcode, 23, 5)
    return loom_immhi << 2 | loom_immlo

def loom_adr_target(location: int, opcode: int) -> int:
    return location + loom_sign_extend(loom_adr_imm(opcode), 21)

def loom_adrp_page(location: int, opcode: int) -> int:
    loom_imm = loom_sign_extend(loom_adr_imm(opcode), 21) << 12
    return (location & ~4095) + loom_imm

def loom_adr_rd(opcode: int) -> int:
    return opcode & 31

def loom_writes_reg(opcode: int, loom_reg: int) -> bool:
    """
    Conservative test: does ``word`` write W/X ``reg`` as a destination?

    Handles the common single-dest ALU/mov/load forms plus LDP dual-dest and the
    AAPCS64 caller-saved clobber of BL/BLR (X0-X18, X30). STR* is transparent (its
    Op1 is a source, not a dest). Used only to gate reverse walks; when in doubt it
    errs toward "yes" (safer for the walker's abort-on-unknown-writer rule).
    """
    if loom_is_bl(opcode) or loom_is_blr(opcode):
        return loom_reg in range(0, 19) or loom_reg == 30
    if opcode & 2113929216 == 671088640:
        loom_is_load = loom_bits(opcode, 22, 22) == 1
        if loom_is_load:
            loom_rt1 = opcode & 31
            loom_rt2 = opcode >> 10 & 31
            return loom_reg in (loom_rt1, loom_rt2)
        return False
    if loom_store_to_slot(opcode) is not None:
        return False
    if loom_is_ldr_reg_x_lsl3(opcode) or loom_is_ldrsw_reg_lsl2(opcode):
        return opcode & 31 == loom_reg
    loom_ml = loom_state_load(opcode)
    if loom_ml is not None:
        return loom_ml.loom_rt == loom_reg
    if loom_move_imm_w(opcode) is not None:
        return opcode & 31 == loom_reg
    if loom_is_mov_reg_w(opcode):
        return opcode & 31 == loom_reg
    if loom_cond_select_w(opcode) is not None:
        return opcode & 31 == loom_reg
    if loom_alu_imm_w(opcode) is not None:
        return opcode & 31 == loom_reg
    if loom_is_adr(opcode) or loom_is_adrp(opcode):
        return opcode & 31 == loom_reg
    return False

__all__ = [export_binding for export_binding in ['ArithmeticImmediate', 'ConditionalChoice', 'ImmediateMove', 'IndexedRead', 'LOOM_COND_NAMES', 'LOOM_SP', 'LOOM_ZR', 'OffsetAccess', 'logical_mask32', 'loom_Optional', 'loom_adr_rd', 'loom_adr_target', 'loom_adrp_page', 'loom_alu_imm_w', 'loom_annotations', 'loom_b_target', 'loom_bcond_cond', 'loom_bcond_target', 'loom_bits', 'loom_br_rn', 'loom_cond_name', 'loom_cond_num', 'loom_cond_select_w', 'loom_dataclass', 'loom_invert_cond', 'loom_is_add_imm_w', 'loom_is_adr', 'loom_is_adrp', 'loom_is_and_imm_w', 'loom_is_b', 'loom_is_bcond', 'loom_is_bl', 'loom_is_blr', 'loom_is_br', 'loom_is_cbz_cbnz', 'loom_is_csel_w', 'loom_is_csinc_w', 'loom_is_csinv_w', 'loom_is_csneg_w', 'loom_is_eor_imm_w', 'loom_is_ldr_reg_x_lsl3', 'loom_is_ldr_w_uimm', 'loom_is_ldr_x_uimm', 'loom_is_ldrsw_reg_lsl2', 'loom_is_ldrsw_uimm', 'loom_is_ldur_w', 'loom_is_ldur_x', 'loom_is_ldursw', 'loom_is_mov_reg_w', 'loom_is_movk_w', 'loom_is_movn_w', 'loom_is_movz_w', 'loom_is_orr_imm_w', 'loom_is_ret', 'loom_is_str_w_uimm', 'loom_is_stur_w', 'loom_is_sub_imm_w', 'loom_is_tbz_tbnz', 'loom_mov_reg_w_fields', 'loom_move_imm_w', 'loom_rd_value', 'loom_reg_load_fields', 'loom_rm', 'loom_rn', 'loom_rt', 'loom_sign_extend', 'loom_state_load', 'loom_store_to_slot', 'loom_writes_reg'] if export_binding in globals()]
