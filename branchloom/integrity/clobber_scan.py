"""
branchloom.integrity.clobber_scan — externally-observable side-effect scanner (IDA-free).

Faithful port of ``_a_path_hazard`` from the reference
``misc/deobf/deobf_br_dispatch.py``, reimplemented against the pure-Python
AArch64 recognisers in :mod:`branchloom.arm_words.recognition` instead of IDA's textual
disassembly. See ``docs/SAFETY.md`` §4.

Background
----------
A ``COND2`` rewrite (two constant indices + ``CSEL`` + ``STR`` ... ``BR``) can be
collapsed to a single ``B.loom_cond``. Doing so makes *one* control-flow path skip
every instruction that sits between the freed dispatch-table ``LDR`` slot and the
``BR``. Before emitting that rewrite the caller scans the gap with
:func:`loom_a_path_hazard`. If any skipped instruction is externally observable — a
call/branch, a barrier (``DMB/DSB/ISB``), a system/cache/TLB op
(``MSR/MRS/SYS/SYSL/IC/DC/AT/TLBI``), an exclusive or acquire/release
(``LDXR/STXR/LDAR/STLR/…``), an exception (``SVC/BRK/HLT/…``), or a **non-stack
store** (base register is not ``SP``/``WSP``/``X29``) — the site is refused with
the recorded reason. Only a stack-local store may be safely skipped.

The reference keyed off IDA mnemonic strings; here every category is decided from
the raw 32-bit little-endian instruction word, so the module has no IDA import
and is unit-testable with a plain ``loom_read_word`` callable.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, Optional as loom_Optional, Tuple as loom_Tuple
from ..arm_words import recognition as LOOM_D
LOOM_SP_REG = 31
LOOM_FP_REG = 29
LOOM__STACK_BASE_REGS = frozenset({LOOM_SP_REG, LOOM_FP_REG})
LOOM__CRN_HINT = 2
LOOM__CRN_BARRIER = 3

def loom_crn(opcode: int) -> int:
    """System-instruction CRn field (bits [15:12])."""
    return opcode >> 12 & 15

def loom_is_exception(opcode: int) -> bool:
    """Exception-generating group: SVC/HVC/SMC/BRK/HLT/DCPS1-3 (bits[31:24]=0xD4)."""
    return opcode & 4278190080 == 3556769792

def loom_is_system(opcode: int) -> bool:
    """System-instruction group: MSR/MRS/SYS/SYSL/barriers/hints (bits[31:22]=0xD5<<..)."""
    return opcode & 4290772992 == 3573547008

def loom_is_branch_reg(opcode: int) -> bool:
    """Unconditional-branch-to-register group: BR/BLR/RET/ERET/DRPS (bits[31:25]=1101011)."""
    return opcode & 4261412864 == 3590324224

def loom_is_exclusive_or_ordered(opcode: int) -> bool:
    """Load/store exclusive + load-acquire/store-release group (bits[29:24]=001000).

    Covers LDXR/STXR/LDAXR/STLXR, LDAR/STLR, LDLAR/STLLR and their pair forms
    (LDXP/STXP/LDAXP/STLXP). Every member is either exclusive or carries
    acquire/release ordering, so any of them in the gap is externally observable.
    """
    return opcode & 1056964608 == 134217728

def loom_store_base(opcode: int) -> loom_Optional[int]:
    """Return the base register (Rn, bits[9:5]) of a recognised GPR store, else None.

    Recognises the integer store forms the obfuscator's state plumbing can emit:
      * unsigned-immediate store  (STR/STRB/STRH, 32/64-bit)
      * unscaled / pre / post-indexed store (STUR, STR ...!, STR ...,#imm)
      * register-offset store     (STR Xt,[Xn,Xm{,ext}])
      * store pair                (STP / STNP)

    Loads are excluded via the opc/L field; SIMD/FP (V=1) stores are intentionally
    not matched here (see TODO(validate) in the module notes).
    """
    loom_rn = opcode >> 5 & 31
    if opcode & 1069547520 == 956301312:
        return loom_rn
    if opcode & 1071644672 == 939524096:
        return loom_rn
    if opcode & 1071647744 == 941623296:
        return loom_rn
    if opcode & 943718400 == 671088640:
        return loom_rn
    return None

def loom_classify(opcode: int) -> loom_Optional[loom_Tuple[str, str]]:
    """Return ``(mnem, reason)`` if ``word`` is an externally-observable effect, else None.

    Order matters: control-flow, exception, system and exclusive/ordered forms are
    tested before the plain-store check so that e.g. ``STLR`` is reported as an
    acquire/release rather than as a store.
    """
    if LOOM_D.loom_is_bl(opcode):
        return ('BL', 'call')
    if LOOM_D.loom_is_blr(opcode):
        return ('BLR', 'call')
    if LOOM_D.loom_is_b(opcode):
        return ('B', 'control-flow branch')
    if LOOM_D.loom_is_bcond(opcode):
        return ('B.cond', 'control-flow branch')
    if LOOM_D.loom_is_cbz_cbnz(opcode):
        return ('CBZ/CBNZ', 'control-flow branch')
    if LOOM_D.loom_is_tbz_tbnz(opcode):
        return ('TBZ/TBNZ', 'control-flow branch')
    if LOOM_D.loom_is_br(opcode):
        return ('BR', 'control-flow branch')
    if LOOM_D.loom_is_ret(opcode):
        return ('RET', 'control-flow return')
    if loom_is_branch_reg(opcode):
        return ('BR-family', 'control-flow branch')
    if loom_is_exception(opcode):
        return ('SVC/BRK/HLT', 'exception-generating')
    if loom_is_system(opcode) and loom_crn(opcode) != LOOM__CRN_HINT:
        if loom_crn(opcode) == LOOM__CRN_BARRIER:
            return ('DMB/DSB/ISB', 'memory barrier')
        return ('MSR/MRS/SYS', 'system/cache/TLB op')
    if loom_is_exclusive_or_ordered(opcode):
        return ('LDXR/STXR/LDAR/STLR', 'exclusive or acquire/release')
    loom_base_value = loom_store_base(opcode)
    if loom_base_value is not None and loom_base_value not in LOOM__STACK_BASE_REGS:
        return ('STR', 'non-stack store (base x%d)' % loom_base_value)
    return None

def loom_a_path_hazard(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_lo_ea: int, loom_hi_ea: int) -> loom_Optional[loom_Tuple[int, str, str]]:
    """Scan ``[lo_ea, hi_ea)`` for the first externally-observable skipped effect.

    ``loom_read_word(ea)`` returns the little-endian 32-bit instruction word at ``ea``
    (or None if it cannot be read). The range is half-open and 4-byte stepped:
    to mirror the reference's exclusive ``(ldr_ea, br_ea)`` gap scan, a caller
    passes ``lo_ea = ldr_ea + 4`` (first instruction after the freed LDR slot)
    and ``hi_ea = br_ea`` (the BR itself, which is being replaced and is never
    part of the skipped gap).

    Returns ``(ea, mnem, reason)`` for the first hazard, or ``None`` when the gap
    holds nothing but stack-local stores and other non-observable instructions,
    i.e. the collapse is safe.
    """
    address = loom_lo_ea
    while address < loom_hi_ea:
        opcode = loom_read_word(address)
        if opcode is None:
            return (address, '?', 'decode-fail')
        loom_hit = loom_classify(opcode & 4294967295)
        if loom_hit is not None:
            return (address, loom_hit[0], loom_hit[1])
        address += 4
    return None

__all__ = [export_binding for export_binding in ['LOOM_D', 'LOOM_FP_REG', 'LOOM_SP_REG', 'loom_Callable', 'loom_Optional', 'loom_Tuple', 'loom_a_path_hazard', 'loom_annotations'] if export_binding in globals()]
