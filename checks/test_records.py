"""
Unit tests for the inter-phase data model (branchloom.records).

The pipeline is a chain of plain JSON files, so every phase boundary is a
serialisation boundary: P1 writes dispatchers, P2 reads them and writes
predecessors, and so on. If a round-trip loses or mangles a field, a later phase
silently plans a patch from the wrong address. These tests pin the round-trip for
all four artifacts, plus the hex convention the JSON is written in.

No IDA and no target binary — the artifacts are written to a temp directory.

Run:  pytest -q
"""
import json as loom_json
import os as loom_os
import tempfile as loom_tempfile
from branchloom import records as LOOM_M

def loom_tmp(label):
    return loom_os.path.join(loom_tempfile.mkdtemp(prefix='branchloom-test-'), label)

def test_loom_hx_and_unhx_round_trip():
    assert LOOM_M.loom_hx_value(5368713216) == '0x140001000'
    assert LOOM_M.loom_hx_value(0) == '0x0'
    assert LOOM_M.loom_unhx('0x140001000') == 5368713216
    assert LOOM_M.loom_unhx(LOOM_M.loom_hx_value(3735928559)) == 3735928559

def test_loom_hx_and_unhx_pass_none_through():
    """Optional addresses stay None rather than becoming 0 — 0 is a real address."""
    assert LOOM_M.loom_hx_value(None) is None
    assert LOOM_M.loom_unhx(None) is None

def test_loom_unhx_accepts_an_already_decoded_int():
    """Lets a hand-written or re-loaded artifact mix int and '0x..' forms."""
    assert LOOM_M.loom_unhx(4660) == 4660

def loom_dispatcher(**loom_kw):
    loom_base_value = dict(loom_br_ea=4096, loom_ldr_tgt_ea=4092, loom_ldrsw_idx_ea=4088, loom_state_load_ea=4080, loom_state_slot=40, loom_state_base='X29', loom_state_load_mnem='LDURSW', loom_state_reg=8, loom_idx_tbl_reg=9, loom_tgt_tbl_reg=10, loom_idx_tbl_ea=131072, loom_tgt_tbl_ea=196608, loom_parent_fn_ea=3840, loom_parent_fn_name='sub_F00', loom_predecessor_eas=[3904, 3936])
    loom_base_value.update(loom_kw)
    return LOOM_M.RouteHub(**loom_base_value)

def test_loom_dispatcher_round_trip():
    location_path = loom_tmp('dispatchers.json')
    items = [loom_dispatcher(), loom_dispatcher(loom_br_ea=8192, loom_parent_fn_ea=7936)]
    LOOM_M.write_hubs(items, location_path)
    loom_back = LOOM_M.read_hubs(location_path)
    assert [loom_r.export_record() for loom_r in loom_back] == [loom_r.export_record() for loom_r in items]
    assert loom_back[0].loom_br_ea == 4096
    assert loom_back[0].loom_predecessor_eas == [3904, 3936]
    assert loom_back[0].loom_state_base == 'X29'

def test_loom_dispatcher_optional_fields_survive_as_none():
    location_path = loom_tmp('dispatchers.json')
    item = loom_dispatcher(loom_state_load_ea=None, loom_state_slot=None, loom_idx_tbl_ea=None, loom_parent_fn_ea=None, loom_parent_fn_name=None, loom_predecessor_eas=[])
    LOOM_M.write_hubs([item], location_path)
    loom_back = LOOM_M.read_hubs(location_path)[0]
    assert loom_back.loom_state_load_ea is None
    assert loom_back.loom_state_slot is None
    assert loom_back.loom_idx_tbl_ea is None
    assert loom_back.loom_parent_fn_ea is None
    assert loom_back.loom_predecessor_eas == []

def test_loom_dispatcher_head_falls_back_to_the_index_load():
    """With no state load, the dispatcher head is the LDRSW that indexes the table."""
    assert loom_dispatcher().loom_dispatcher_head_ea == 4080
    assert loom_dispatcher(loom_state_load_ea=None).loom_dispatcher_head_ea == 4088

def test_loom_dispatcher_json_is_hex_encoded_on_disk():
    location_path = loom_tmp('dispatchers.json')
    LOOM_M.write_hubs([loom_dispatcher()], location_path)
    with open(location_path, encoding='utf-8') as stream:
        source = loom_json.load(stream)
    assert source['meta']['count'] == 1
    assert source['dispatchers'][0]['br_ea'] == '0x1000'
    assert source['dispatchers'][0]['predecessor_eas'] == ['0xf40', '0xf60']

def loom_predecessor(**loom_kw):
    loom_base_value = dict(loom_dispatcher_br_ea=4096, loom_parent_fn_ea=3840, loom_parent_fn_name='sub_F00', loom_idx_tbl_ea=131072, loom_tgt_tbl_ea=196608, loom_state_slot=40, loom_state_base='X29', record_type='CONST', loom_class_detail={'state': 7}, loom_str_ea=3908, loom_pred_start_ea=3904, loom_reason=None)
    loom_base_value.update(loom_kw)
    return LOOM_M.IncomingBlock(**loom_base_value)

def test_loom_predecessor_round_trip():
    location_path = loom_tmp('predecessors.json')
    items = [loom_predecessor(), loom_predecessor(record_type='COND2', loom_class_detail={'then': 3, 'else': 9, 'cond': 'EQ'})]
    LOOM_M.write_incoming(items, location_path)
    loom_back = LOOM_M.read_incoming(location_path)
    assert [loom_r.export_record() for loom_r in loom_back] == [loom_r.export_record() for loom_r in items]
    assert loom_back[1].record_type == 'COND2'
    assert loom_back[1].loom_class_detail['cond'] == 'EQ'

def test_loom_predecessor_class_key_is_renamed_in_json():
    """``cls`` is spelled ``class`` on disk — the round-trip must survive it."""
    location_path = loom_tmp('predecessors.json')
    LOOM_M.write_incoming([loom_predecessor(record_type='OPAQUE')], location_path)
    with open(location_path, encoding='utf-8') as stream:
        source = loom_json.load(stream)
    assert source['predecessors'][0]['class'] == 'OPAQUE'
    assert 'cls' not in source['predecessors'][0]
    assert LOOM_M.read_incoming(location_path)[0].record_type == 'OPAQUE'

def test_loom_predecessor_meta_counts_every_class():
    location_path = loom_tmp('predecessors.json')
    items = [loom_predecessor(record_type='CONST'), loom_predecessor(record_type='CONST'), loom_predecessor(record_type='COND2')]
    LOOM_M.write_incoming(items, location_path)
    with open(location_path, encoding='utf-8') as stream:
        loom_counts = loom_json.load(stream)['meta']['classes']
    assert loom_counts == {'CONST': 2, 'COND2': 1, 'XFORM': 0, 'OPAQUE': 0}
    assert set(loom_counts) == set(LOOM_M.LOOM_CLASSES)

def test_loom_resolution_round_trip_with_entries():
    location_path = loom_tmp('resolutions.json')
    items = [LOOM_M.DestinationSet(loom_dispatcher_br_ea=4096, loom_parent_fn_ea=3840, loom_parent_fn_name='sub_F00', loom_via_class='COND2', loom_state_slot=40, loom_state_base='X29', loom_idx_tbl_ea=131072, loom_tgt_tbl_ea=196608, loom_str_ea=3908, loom_pred_start_ea=3904, loom_entries=[LOOM_M.DestinationChoice(loom_state=3, loom_idx=1, destination=4352, equivalence='OK', loom_cond='EQ', loom_cond_case='then'), LOOM_M.DestinationChoice(loom_state=9, loom_idx=4, destination=4608, equivalence='UNVERIFIED', loom_cond='EQ', loom_cond_case='else')])]
    LOOM_M.write_destinations(items, location_path)
    loom_back = LOOM_M.read_destinations(location_path)
    assert [loom_r.export_record() for loom_r in loom_back] == [loom_r.export_record() for loom_r in items]
    assert len(loom_back[0].loom_entries) == 2
    assert loom_back[0].loom_entries[0].destination == 4352
    assert loom_back[0].loom_entries[1].equivalence == 'UNVERIFIED'
    assert loom_back[0].loom_entries[1].loom_cond_case == 'else'

def test_loom_resolution_entry_keeps_an_unresolved_target_as_none():
    """An INVALID entry has no target; it must not round-trip into 0."""
    location_path = loom_tmp('resolutions.json')
    items = [LOOM_M.DestinationSet(loom_dispatcher_br_ea=4096, loom_parent_fn_ea=None, loom_parent_fn_name=None, loom_via_class='CONST', loom_state_slot=None, loom_state_base=None, loom_idx_tbl_ea=None, loom_tgt_tbl_ea=None, loom_str_ea=None, loom_pred_start_ea=None, loom_entries=[LOOM_M.DestinationChoice(loom_state=5, loom_idx=None, destination=None, equivalence='INVALID')])]
    LOOM_M.write_destinations(items, location_path)
    loom_entry_value = LOOM_M.read_destinations(location_path)[0].loom_entries[0]
    assert loom_entry_value.destination is None
    assert loom_entry_value.loom_idx is None
    assert loom_entry_value.equivalence in LOOM_M.LOOM_VERDICTS

def test_loom_patch_plan_round_trip():
    location_path = loom_tmp('patch_plan.json')
    items = [LOOM_M.ByteRewrite(location=4160, span=4, loom_orig_bytes_hex='00020000', loom_new_bytes_hex='04000014', loom_reason='CONST-branch', loom_parent_fn=3840, loom_dispatcher_pc=4096, loom_via_state=7, equivalence='OK', loom_target_ea=4352), LOOM_M.ByteRewrite(location=4224, span=4, loom_orig_bytes_hex='e0031f2a', loom_new_bytes_hex='40000054', loom_reason='COND2-bcond', loom_parent_fn=3840, loom_dispatcher_pc=4096, loom_via_state=9, loom_via_case='then', equivalence='OK', loom_target_ea=4608)]
    LOOM_M.write_rewrites(items, location_path)
    loom_back = LOOM_M.read_rewrites(location_path)
    assert [loom_r.export_record() for loom_r in loom_back] == [loom_r.export_record() for loom_r in items]
    assert loom_back[0].location == 4160
    assert loom_back[1].loom_via_case == 'then'

def test_loom_patch_plan_patches_are_same_size_rewrites():
    """Every planned patch replaces exactly as many bytes as it consumes."""
    items = [LOOM_M.ByteRewrite(location=4160, span=4, loom_orig_bytes_hex='00020000', loom_new_bytes_hex='04000014', loom_reason='CONST-branch', loom_parent_fn=3840, loom_dispatcher_pc=4096)]
    for loom_p in items:
        assert len(loom_p.loom_orig_bytes_hex) == len(loom_p.loom_new_bytes_hex) == loom_p.span * 2

def test_loom_patch_plan_meta_carries_the_skip_reasons():
    location_path = loom_tmp('patch_plan.json')
    LOOM_M.write_rewrites([], location_path, loom_by_parent={'0xf00': 0}, loom_skipped={'OPAQUE': 3})
    with open(location_path, encoding='utf-8') as stream:
        source = loom_json.load(stream)
    assert source['meta']['patches'] == 0
    assert source['meta']['skipped'] == {'OPAQUE': 3}
    assert source['by_parent'] == {'0xf00': 0}
    assert LOOM_M.read_rewrites(location_path) == []
def test_loom_omitted_class_detail_preserves_independent_empty_mappings():
    from branchloom.records import IncomingBlock
    fixture_payload = {'dispatcher_br_ea': '0x1000', 'class': 'OPAQUE'}
    first_record = IncomingBlock.import_record(fixture_payload)
    second_record = IncomingBlock.import_record(fixture_payload)
    assert first_record.export_record()['class_detail'] == {}
    first_record.loom_class_detail['fixture'] = 1
    assert second_record.export_record()['class_detail'] == {}


def test_loom_explicit_null_class_detail_is_preserved():
    from branchloom.records import IncomingBlock
    fixture_payload = {'dispatcher_br_ea': '0x1000', 'class': 'OPAQUE', 'class_detail': None}
    imported_record = IncomingBlock.import_record(fixture_payload)
    assert imported_record.export_record()['class_detail'] is None
