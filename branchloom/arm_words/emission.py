"""Four-byte AArch64 branches share one signed-displacement packer."""
from __future__ import annotations as loom_annotations
from typing import Optional as loom_Optional
from .recognition import loom_cond_num

LOOM_ARM64_NOP = 0xD503201F


def loom_off(location: int, destination: int) -> loom_Optional[int]:
    distance = destination - location
    return None if distance & 0b11 else distance


def relative_field(location: int, destination: int, field_width: int) -> loom_Optional[int]:
    distance = loom_off(location, destination)
    if distance is None:
        return None
    word_offset = distance >> 2
    displacement_bound = 1 << (field_width - 1)
    if not -displacement_bound <= word_offset < displacement_bound:
        return None
    return word_offset & ((1 << field_width) - 1)


def emit_jump(location: int, destination: int) -> loom_Optional[int]:
    immediate = relative_field(location, destination, 26)
    return None if immediate is None else 0x14000000 | immediate


def emit_conditional_jump(location: int, destination: int, loom_cond) -> loom_Optional[int]:
    condition = loom_cond if isinstance(loom_cond, int) else loom_cond_num(loom_cond)
    if condition is None:
        return None
    immediate = relative_field(location, destination, 19)
    return None if immediate is None else 0x54000000 | (immediate << 5) | (condition & 15)


def emit_bit_jump(location: int, destination: int, loom_reg: int, loom_bit: int, loom_is_tbnz: bool) -> loom_Optional[int]:
    immediate = relative_field(location, destination, 14)
    if immediate is None:
        return None
    fields = (0x36000000, ((loom_bit >> 5) & 1) << 31,
              int(bool(loom_is_tbnz)) << 24, (loom_bit & 31) << 19,
              immediate << 5, loom_reg & 31)
    instruction = 0
    for field_value in fields:
        instruction |= field_value
    return instruction


def opcode_bytes(opcode: int) -> bytes:
    return (opcode & 0xFFFFFFFF).to_bytes(4, 'little')

__all__ = [export_binding for export_binding in ['LOOM_ARM64_NOP', 'emit_bit_jump', 'emit_conditional_jump', 'emit_jump', 'loom_Optional', 'loom_annotations', 'loom_cond_num', 'opcode_bytes'] if export_binding in globals()]
