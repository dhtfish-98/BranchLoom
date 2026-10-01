"""
branchloom.arm_words.neighbourhood — bounded reverse instruction walking (no IDA, no deps).

The devirtualizer resolves a dispatch/state register by scanning *backwards* from
a use site to the instruction that produced it. That scan is the same primitive
whether it runs inside IDA or against a raw byte buffer, so it is factored here
behind a single ``loom_read_word(ea) -> int`` callable:

    read_word(ea) returns the little-endian 32-bit instruction word at ``ea``
    (an int), or ``None`` if ``ea`` is unreadable / cannot be fetched.

Because the walker never imports IDA, it is exhaustively unit-testable by passing
a dict-backed ``loom_read_word``.

Register numbers are the *raw* AArch64 encoding values 0..31 (31 == XZR/WZR),
exactly as produced by ``branchloom.arm_words.recognition`` (never IDA's internal ids).

Ported from the back-walk in
the private reference toolchain (``deobf_br_dispatch.py``) (``_walk_back`` /
``_WalkBackIter`` / the BL-clobber abort in ``_find_dispatch_ctx``) and the
predecessor scan in
``.../misc/final/part3_trigger4/tools/cff_classify_preds.py``. All target-specific
values (addresses, segment names, table offsets) are intentionally *absent*: this
layer only knows about instruction words and register numbers.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, Iterator as loom_Iterator, Optional as loom_Optional, Tuple as loom_Tuple
from . import recognition as LOOM_D
__all__ = ['loom_reverse_words', 'loom_find_reg_producer']

def loom_reverse_words(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_start_ea: int, loom_count: int) -> loom_Iterator[loom_Tuple[int, loom_Optional[int]]]:
    """Yield ``(ea, word)`` pairs walking backwards from ``start_ea``, stepping -4.

    The first pair yielded is ``(start_ea, loom_read_word(start_ea))``; each subsequent
    pair steps 4 bytes lower. At most ``count`` pairs are produced and the walk
    stops early if the address would go negative. ``word`` is whatever
    ``loom_read_word`` returned (possibly ``None`` for an unreadable slot) — the caller
    decides how to treat a ``None`` word.

    This is a pure generator: no IDA, no global state, safe to unit-test with a
    dict-backed ``loom_read_word``.
    """
    address = loom_start_ea
    loom_produced = 0
    while loom_produced < loom_count and address >= 0:
        yield (address, loom_read_word(address))
        address -= 4
        loom_produced += 1

def loom_find_reg_producer(loom_read_word: loom_Callable[[int], loom_Optional[int]], loom_from_ea: int, loom_reg: int, loom_max_insns: int=16) -> loom_Optional[int]:
    """Return the EA of the nearest instruction *before* ``from_ea`` that writes
    register ``reg``, or ``None`` if none is found within ``max_insns`` or the
    result would be ambiguous.

    Semantics (faithful to the proven back-walk):

    * The instruction at ``from_ea`` itself is NOT considered — only its
      predecessors (this matches how the reference anchors on the *use* site,
      e.g. a ``BR``/``LDR``, and looks strictly earlier for the definition).
    * Stores are transparent: ``LOOM_D.loom_writes_reg`` already reports ``False`` for
      ``STR*`` (their operand-1 is a source, not a destination), so a store to a
      stack slot never masks the real producer.
    * ``BL``/``BLR`` clobber the AAPCS64 caller-saved set (X0..X18, X30). If
      ``reg`` is in that set, the value live at ``from_ea`` is the *callee's*
      result, not anything an earlier instruction produced — the producer is
      therefore ambiguous and we return ``None`` (never guess). If ``reg`` is
      callee-saved, the call preserves it and the walk continues through it.
    * An unreadable slot (``loom_read_word`` -> ``None``) aborts the walk with
      ``None``: we cannot prove anything past a byte we cannot decode.
    """
    for address, opcode in loom_reverse_words(loom_read_word, loom_from_ea - 4, loom_max_insns):
        if opcode is None:
            return None
        if LOOM_D.loom_is_bl(opcode) or LOOM_D.loom_is_blr(opcode):
            if LOOM_D.loom_writes_reg(opcode, loom_reg):
                return None
            continue
        if LOOM_D.loom_writes_reg(opcode, loom_reg):
            return address
    return None
