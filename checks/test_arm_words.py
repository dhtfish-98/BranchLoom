"""
Unit tests for the pure-Python AArch64 ISA layer (branchloom.arm_words).

These are the *crown-jewel* primitives — every phase depends on them and they run
with no IDA and no target binary, so they can (and must) be validated in CI before
the tool is trusted on a real binary. Encodings below are hand-derived from the ARM
ARM (C4.1) and cross-checkable with any assembler.

Run:  pytest -q
"""
from branchloom.arm_words import recognition as loom_d_value
from branchloom.arm_words import emission as loom_e
from branchloom.arm_words.logical_fields import logical_mask32 as logical_mask32, expand_logical_field as expand_logical_field

def test_loom_br_vs_blr_vs_ret():
    loom_br_x16 = 3592356352
    loom_blr_x8 = 3594453248
    loom_ret_value = 3596551104
    assert loom_d_value.loom_is_br(loom_br_x16) and (not loom_d_value.loom_is_blr(loom_br_x16)) and (not loom_d_value.loom_is_ret(loom_br_x16))
    assert loom_d_value.loom_br_rn(loom_br_x16) == 16
    assert loom_d_value.loom_is_blr(loom_blr_x8) and (not loom_d_value.loom_is_br(loom_blr_x8))
    assert loom_d_value.loom_br_rn(loom_blr_x8) == 8
    assert loom_d_value.loom_is_ret(loom_ret_value) and (not loom_d_value.loom_is_br(loom_ret_value))

def test_loom_nop():
    assert loom_e.LOOM_ARM64_NOP == 3573751839

def test_loom_enc_b_roundtrip_forward_and_back():
    loom_w = loom_e.emit_jump(4096, 4112)
    assert loom_w == 335544324
    assert loom_d_value.loom_is_b(loom_w) and loom_d_value.loom_b_target(4096, loom_w) == 4112
    loom_w2 = loom_e.emit_jump(4112, 4096)
    assert loom_d_value.loom_is_b(loom_w2) and loom_d_value.loom_b_target(4112, loom_w2) == 4096

def test_loom_enc_bcond_roundtrip():
    loom_w = loom_e.emit_conditional_jump(8192, 8200, 'NE')
    assert loom_d_value.loom_is_bcond(loom_w)
    assert loom_d_value.loom_bcond_cond(loom_w) == loom_d_value.loom_cond_num('NE') == 1
    assert loom_d_value.loom_bcond_target(8192, loom_w) == 8200

def test_loom_enc_range_and_alignment_guards():
    assert loom_e.emit_jump(0, 1 << 27) is None
    assert loom_e.emit_jump(0, 2) is None
    assert loom_e.emit_conditional_jump(0, 1 << 20, 'EQ') is None
    assert loom_e.emit_conditional_jump(0, 64, 'ZZ') is None

def test_loom_cond_helpers():
    assert loom_d_value.loom_cond_name(0) == 'EQ' and loom_d_value.loom_cond_name(1) == 'NE'
    assert loom_d_value.loom_invert_cond(loom_d_value.loom_cond_num('NE')) == loom_d_value.loom_cond_num('EQ')
    assert loom_d_value.loom_cond_num('HS') == loom_d_value.loom_cond_num('CS')

def test_loom_ldrsw_reg_idx_load():
    loom_w = 3098106184
    assert loom_d_value.loom_is_ldrsw_reg_lsl2(loom_w)
    loom_f = loom_d_value.loom_reg_load_fields(loom_w)
    assert (loom_f.loom_rt, loom_f.loom_rn, loom_f.loom_rm, loom_f.span) == (8, 10, 9, 4)

def test_loom_ldr_reg_tgt_load():
    loom_w = 4167661896
    assert loom_d_value.loom_is_ldr_reg_x_lsl3(loom_w)
    loom_f = loom_d_value.loom_reg_load_fields(loom_w)
    assert (loom_f.loom_rt, loom_f.loom_rn, loom_f.loom_rm, loom_f.span) == (8, 10, 9, 8)

def test_loom_state_load_ldursw_negative_offset():
    loom_w = 3097478056
    loom_ml = loom_d_value.loom_state_load(loom_w)
    assert loom_ml is not None
    assert (loom_ml.loom_rt, loom_ml.loom_rn, loom_ml.loom_imm, loom_ml.loom_kind_value) == (8, 29, -4, 'LDURSW')

def test_loom_store_to_slot():
    loom_w = 3103793064
    loom_st = loom_d_value.loom_store_to_slot(loom_w)
    assert loom_st is not None
    assert (loom_st.loom_rt, loom_st.loom_rn, loom_st.loom_imm, loom_st.loom_kind_value) == (8, 29, 28, 'STR_W')

def test_loom_movz_movn():
    loom_mz = loom_d_value.loom_move_imm_w(1384269448)
    assert loom_mz.loom_kind_value == 'MOVZ' and loom_mz.loom_rd_value == 8 and (loom_mz.loom_imm == 4660)
    loom_mn = loom_d_value.loom_move_imm_w(310378496)
    assert loom_mn.loom_kind_value == 'MOVN' and loom_mn.loom_rd_value == 0 and (loom_mn.loom_imm == 4294967295)

def test_loom_csel_and_cset_alias():
    loom_cs = loom_d_value.loom_cond_select_w(444727328)
    assert loom_cs.loom_op == 'CSEL' and (loom_cs.loom_rd_value, loom_cs.loom_rn, loom_cs.loom_rm, loom_cs.loom_cond) == (0, 1, 2, 0)
    loom_cset = loom_d_value.loom_cond_select_w(446629856)
    assert loom_cset.loom_op == 'CSINC' and loom_cset.loom_alias == 'CSET'
    assert loom_cset.loom_rn == loom_d_value.LOOM_ZR and loom_cset.loom_rm == loom_d_value.LOOM_ZR

def test_loom_alu_imm_add_and_eor_logical():
    loom_add = loom_d_value.loom_alu_imm_w(285284616)
    assert loom_add.loom_op == 'ADD' and loom_add.loom_imm == 70 and ((loom_add.loom_rd_value, loom_add.loom_rn) == (8, 8))
    loom_eor = loom_d_value.loom_alu_imm_w(1377569032)
    assert loom_eor.loom_op == 'EOR' and loom_eor.loom_imm == 112 and ((loom_eor.loom_rd_value, loom_eor.loom_rn) == (8, 8))

def test_loom_logical_immediate_decoder():
    assert expand_logical_field(0, 2, 28, 32) == 112
    assert logical_mask32(1377569032) == 112
    assert expand_logical_field(0, 63, 0, 32) is None

def test_loom_adrp_page():
    loom_w = 3489660928
    assert loom_d_value.loom_is_adrp(loom_w)
    assert loom_d_value.loom_adrp_page(4096, loom_w) == 12288
    assert loom_d_value.loom_adr_rd(loom_w) == 0

def test_loom_writes_reg_basic():
    loom_mov = 704775144
    assert loom_d_value.loom_is_mov_reg_w(loom_mov)
    assert loom_d_value.loom_writes_reg(loom_mov, 8) and (not loom_d_value.loom_writes_reg(loom_mov, 2))
    assert not loom_d_value.loom_writes_reg(3103793064, 8)
    loom_bl = 2483027968
    assert loom_d_value.loom_writes_reg(loom_bl, 0) and loom_d_value.loom_writes_reg(loom_bl, 30) and (not loom_d_value.loom_writes_reg(loom_bl, 19))
def test_loom_branch_emitters_reject_noninteger_addresses():
    for branch_emitter, probe_arguments in [
        (loom_e.emit_jump, (0, 1.5)),
        (loom_e.emit_conditional_jump, (0, 4.0, 'NE')),
        (loom_e.emit_bit_jump, (0, 4.0, 0, 1, False)),
    ]:
        try:
            branch_emitter(*probe_arguments)
        except TypeError:
            continue
        raise AssertionError('Noninteger addresses must retain the baseline TypeError')


def test_loom_word_serialization_rejects_noninteger_words():
    for invalid_opcode in [1.5, '3', None]:
        try:
            loom_e.opcode_bytes(invalid_opcode)
        except TypeError:
            continue
        raise AssertionError('Noninteger words must retain the baseline TypeError')
