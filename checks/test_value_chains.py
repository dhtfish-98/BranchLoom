"""
Unit tests for the bounded constant-register resolver (branchloom.arm_words.value_chains).

This is the layer that decides whether a predecessor's next-state is *provably* a
constant. Everything downstream — the CONST/COND2 classification, the resolutions,
the patch plan — is gated on it, and a wrong answer here is how a devirtualizer
silently corrupts a binary. So the contract these tests pin down is two-sided:

  * every derivation chain the obfuscator emits resolves to the exact 32-bit value;
  * anything else resolves to ``None``. Never a guess, never a default.

No IDA and no target binary: ``loom_read_word`` is a dict. Encodings are hand-derived
from the ARM ARM (C4.1) and cross-checkable with any assembler.

Run:  pytest -q
"""
from branchloom.arm_words.value_chains import loom_resolve_const_reg as loom_resolve_const_reg

def loom_movz(loom_rd_value, loom_imm16, loom_hw=0):
    return 1384120320 | loom_hw << 21 | (loom_imm16 & 65535) << 5 | loom_rd_value

def loom_movk(loom_rd_value, loom_imm16, loom_hw=0):
    return 1920991232 | loom_hw << 21 | (loom_imm16 & 65535) << 5 | loom_rd_value

def loom_movn(loom_rd_value, loom_imm16, loom_hw=0):
    return 310378496 | loom_hw << 21 | (loom_imm16 & 65535) << 5 | loom_rd_value

def loom_mov_reg(loom_rd_value, loom_rm):
    """``MOV Wd, Wm`` == ``ORR Wd, WZR, Wm``."""
    return 704644064 | loom_rm << 16 | loom_rd_value

def loom_add_imm(loom_rd_value, loom_rn, loom_imm12, loom_sh=0):
    return 285212672 | loom_sh << 22 | (loom_imm12 & 4095) << 10 | loom_rn << 5 | loom_rd_value

def loom_sub_imm(loom_rd_value, loom_rn, loom_imm12, loom_sh=0):
    return 1358954496 | loom_sh << 22 | (loom_imm12 & 4095) << 10 | loom_rn << 5 | loom_rd_value

def loom_orr_reg(loom_rd_value, loom_rn, loom_rm):
    return 704643072 | loom_rm << 16 | loom_rn << 5 | loom_rd_value

def loom_eor_reg(loom_rd_value, loom_rn, loom_rm):
    return 1241513984 | loom_rm << 16 | loom_rn << 5 | loom_rd_value

def loom_csel(loom_rd_value, loom_rn, loom_rm, loom_cond=0):
    return 444596224 | loom_rm << 16 | loom_cond << 12 | loom_rn << 5 | loom_rd_value

def loom_bl(loom_imm26=1):
    return 2483027968 | loom_imm26 & 67108863
LOOM_BASE = 1048576

def loom_mem(*loom_words):
    """Lay ``words`` out at BASE, BASE+4, ... and return (read_word, use_site_ea).

    The use site is one instruction past the last word, which is where the resolver
    is asked what the register holds.
    """
    loom_layout = {LOOM_BASE + 4 * loom_i: loom_w for loom_i, loom_w in enumerate(loom_words)}

    def loom_read_word(address):
        return loom_layout.get(address)
    return (loom_read_word, LOOM_BASE + 4 * len(loom_words))

def test_loom_movz_immediate():
    loom_read_value, loom_use = loom_mem(loom_movz(8, 4660))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 4660

def test_loom_movz_shifted_immediate():
    loom_read_value, loom_use = loom_mem(loom_movz(8, 48879, loom_hw=1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 3203334144

def test_loom_movn_is_inverted():
    loom_read_value, loom_use = loom_mem(loom_movn(8, 0))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 4294967295
    loom_read_value, loom_use = loom_mem(loom_movn(8, 1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 4294967294

def test_loom_movz_movk_slice_merge():
    """MOVK overwrites only its own 16-bit slice, keeping the prior value."""
    loom_read_value, loom_use = loom_mem(loom_movz(8, 4660), loom_movk(8, 43981, loom_hw=1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 2882343476

def test_loom_movk_without_a_prior_value_is_unresolvable():
    """A lone MOVK has no base to merge into — that is not a provable constant."""
    loom_read_value, loom_use = loom_mem(loom_movk(8, 43981, loom_hw=1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) is None

def test_loom_register_copy_follows_the_source():
    loom_read_value, loom_use = loom_mem(loom_movz(9, 85), loom_mov_reg(8, 9))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 85

def test_loom_add_and_sub_immediate_chains():
    loom_read_value, loom_use = loom_mem(loom_movz(9, 16), loom_add_imm(8, 9, 32))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 48
    loom_read_value, loom_use = loom_mem(loom_movz(9, 48), loom_sub_imm(8, 9, 16))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 32

def test_loom_add_immediate_lsl12():
    loom_read_value, loom_use = loom_mem(loom_movz(9, 0), loom_add_imm(8, 9, 2, loom_sh=1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 8192

def test_loom_arithmetic_is_modular_32bit():
    """SUB below zero wraps in 32-bit modular arithmetic, it does not go negative."""
    loom_read_value, loom_use = loom_mem(loom_movz(9, 5), loom_sub_imm(8, 9, 16))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 4294967285

def test_loom_orr_and_eor_register_forms():
    loom_read_value, loom_use = loom_mem(loom_movz(9, 240), loom_movz(10, 15), loom_orr_reg(8, 9, 10))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 255
    loom_read_value, loom_use = loom_mem(loom_movz(9, 255), loom_movz(10, 15), loom_eor_reg(8, 9, 10))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) == 240

def test_loom_wzr_reads_as_zero():
    """W31 is the zero register; it needs no producer."""
    loom_read_value, loom_use = loom_mem(loom_movz(0, 1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 31) == 0

def test_loom_no_producer_is_unresolvable():
    loom_read_value, loom_use = loom_mem(loom_movz(9, 4660))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) is None

def test_loom_unmodelled_producer_is_unresolvable():
    """CSEL is a real writer but not a provable constant — never guess a branch."""
    loom_read_value, loom_use = loom_mem(loom_movz(9, 1), loom_movz(10, 2), loom_csel(8, 9, 10))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8) is None

def test_loom_call_clobbering_the_register_is_ambiguous():
    """A BL clobbers the caller-saved registers, so anything before it is unusable."""
    loom_read_value, loom_use = loom_mem(loom_movz(0, 4660), loom_bl())
    assert loom_resolve_const_reg(loom_read_value, loom_use, 0) is None

def test_loom_call_not_clobbering_the_register_is_walked_through():
    """W19 is callee-saved, so a BL in the way does not break the chain."""
    loom_read_value, loom_use = loom_mem(loom_movz(19, 4660), loom_bl())
    assert loom_resolve_const_reg(loom_read_value, loom_use, 19) == 4660

def test_loom_unmapped_memory_is_unresolvable():
    """read_word returning None (unmapped/unreadable) must not be treated as 0."""

    def loom_read_value(loom_ea):
        return None
    assert loom_resolve_const_reg(loom_read_value, LOOM_BASE + 64, 8) is None

def test_loom_depth_bound_is_enforced():
    """A chain longer than max_depth returns None rather than running unbounded."""
    loom_read_value, loom_use = loom_mem(loom_movz(9, 1), loom_add_imm(9, 9, 1), loom_add_imm(9, 9, 1), loom_add_imm(9, 9, 1), loom_add_imm(8, 9, 1))
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8, loom_max_depth=16) == 5
    assert loom_resolve_const_reg(loom_read_value, loom_use, 8, loom_max_depth=1) is None
