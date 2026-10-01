"""
AArch64 logical-immediate decoder (the ``DecodeBitMasks`` routine from the ARM
ARM, section J1 / C4.1 pseudocode).

Needed to read the immediate of ``AND/ORR/EOR (immediate)`` — in this tool the
CFF "self-scrambler" predecessor is typically ``EOR Wt, Wt, #mask``, and mask is
a logical immediate, not a plain imm12. Pure Python, unit-tested.
"""
from __future__ import annotations as loom_annotations
from typing import Optional as loom_Optional

def loom_ones(loom_n_value: int) -> int:
    return (1 << loom_n_value) - 1

def loom_ror(loom_value: int, loom_amount: int, loom_width: int) -> int:
    loom_amount %= loom_width
    loom_mask = loom_ones(loom_width)
    loom_value &= loom_mask
    return (loom_value >> loom_amount | loom_value << loom_width - loom_amount) & loom_mask

def expand_logical_field(loom_n_value: int, loom_imms: int, loom_immr: int, loom_width: int=32) -> loom_Optional[int]:
    """
    Decode (N, imms, immr) into the ``wmask`` logical immediate value.

    ``width`` is the datasize (32 for W-form, 64 for X-form). Returns the
    immediate as an unsigned int, or ``None`` if the encoding is reserved
    (matching the architectural UNDEFINED cases).
    """
    loom_combined = loom_n_value << 6 | ~loom_imms & 63
    loom_length = loom_combined.bit_length() - 1
    if loom_length < 1:
        return None
    if loom_width < 1 << loom_length:
        return None
    loom_levels = loom_ones(loom_length)
    loom_s = loom_imms & loom_levels
    loom_r = loom_immr & loom_levels
    if loom_s == loom_levels:
        return None
    loom_esize = 1 << loom_length
    loom_welem = loom_ones(loom_s + 1)
    loom_welem = loom_ror(loom_welem, loom_r, loom_esize)
    repeat_count = (loom_width + loom_esize - 1) // loom_esize
    repeated_unit = ((1 << (repeat_count * loom_esize)) - 1) // ((1 << loom_esize) - 1)
    return (loom_welem * repeated_unit) & loom_ones(loom_width)

def logical_mask32(opcode: int) -> loom_Optional[int]:
    """Decode the immediate of a 32-bit ``AND/ORR/EOR/ANDS (immediate)`` word."""
    loom_n_value = opcode >> 22 & 1
    if loom_n_value != 0:
        return None
    loom_immr = opcode >> 16 & 63
    loom_imms = opcode >> 10 & 63
    return expand_logical_field(loom_n_value, loom_imms, loom_immr, loom_width=32)

def logical_mask64(opcode: int) -> loom_Optional[int]:
    """Decode the immediate of a 64-bit ``AND/ORR/EOR/ANDS (immediate)`` word."""
    loom_n_value = opcode >> 22 & 1
    loom_immr = opcode >> 16 & 63
    loom_imms = opcode >> 10 & 63
    return expand_logical_field(loom_n_value, loom_imms, loom_immr, loom_width=64)

__all__ = [export_binding for export_binding in ['expand_logical_field', 'logical_mask32', 'logical_mask64', 'loom_Optional', 'loom_annotations'] if export_binding in globals()]
