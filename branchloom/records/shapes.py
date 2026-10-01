from __future__ import annotations as loom_annotations
import json as loom_json
from dataclasses import asdict as loom_asdict, dataclass as loom_dataclass, field as loom_field
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional
from .codec import ExchangeRecord

@loom_dataclass
class RouteHub(ExchangeRecord):
    exchange_shape = [('br_ea', 'loom_br_ea', 'address', True, True), ('ldr_tgt_ea', 'loom_ldr_tgt_ea', 'address', True, True), ('ldrsw_idx_ea', 'loom_ldrsw_idx_ea', 'address', True, True), ('state_load_ea', 'loom_state_load_ea', 'address', False, True), ('state_slot', 'loom_state_slot', 'plain', False, True), ('state_base', 'loom_state_base', 'plain', False, True), ('state_load_mnem', 'loom_state_load_mnem', 'plain', False, True), ('state_reg', 'loom_state_reg', 'plain', False, True), ('idx_tbl_reg', 'loom_idx_tbl_reg', 'plain', False, True), ('tgt_tbl_reg', 'loom_tgt_tbl_reg', 'plain', False, True), ('idx_tbl_ea', 'loom_idx_tbl_ea', 'address', False, True), ('tgt_tbl_ea', 'loom_tgt_tbl_ea', 'address', False, True), ('parent_fn_ea', 'loom_parent_fn_ea', 'address', False, True), ('parent_fn_name', 'loom_parent_fn_name', 'plain', False, True), ('dispatcher_head_ea', 'loom_dispatcher_head_ea', 'address', False, False), ('predecessor_eas', 'loom_predecessor_eas', 'address_list', False, True)]
    loom_br_ea: int
    loom_ldr_tgt_ea: int
    loom_ldrsw_idx_ea: int
    loom_state_load_ea: loom_Optional[int]
    loom_state_slot: loom_Optional[int]
    loom_state_base: loom_Optional[str]
    loom_state_load_mnem: loom_Optional[str]
    loom_state_reg: loom_Optional[int]
    loom_idx_tbl_reg: loom_Optional[int]
    loom_tgt_tbl_reg: loom_Optional[int]
    loom_idx_tbl_ea: loom_Optional[int]
    loom_tgt_tbl_ea: loom_Optional[int]
    loom_parent_fn_ea: loom_Optional[int]
    loom_parent_fn_name: loom_Optional[str]
    loom_predecessor_eas: loom_List[int] = loom_field(default_factory=list)

    @property
    def loom_dispatcher_head_ea(record) -> int:
        return record.loom_state_load_ea if record.loom_state_load_ea is not None else record.loom_ldrsw_idx_ea

@loom_dataclass
class IncomingBlock(ExchangeRecord):
    exchange_shape = [('dispatcher_br_ea', 'loom_dispatcher_br_ea', 'address', True, True), ('parent_fn_ea', 'loom_parent_fn_ea', 'address', False, True), ('parent_fn_name', 'loom_parent_fn_name', 'plain', False, True), ('idx_tbl_ea', 'loom_idx_tbl_ea', 'address', False, True), ('tgt_tbl_ea', 'loom_tgt_tbl_ea', 'address', False, True), ('state_slot', 'loom_state_slot', 'plain', False, True), ('state_base', 'loom_state_base', 'plain', False, True), ('class', 'record_type', 'plain', True, True), ('class_detail', 'loom_class_detail', 'mapping', False, True), ('str_ea', 'loom_str_ea', 'address', False, True), ('pred_start_ea', 'loom_pred_start_ea', 'address', False, True), ('reason', 'loom_reason', 'plain', False, True)]
    loom_dispatcher_br_ea: int
    loom_parent_fn_ea: loom_Optional[int]
    loom_parent_fn_name: loom_Optional[str]
    loom_idx_tbl_ea: loom_Optional[int]
    loom_tgt_tbl_ea: loom_Optional[int]
    loom_state_slot: loom_Optional[int]
    loom_state_base: loom_Optional[str]
    record_type: str
    loom_class_detail: loom_Dict[str, loom_Any]
    loom_str_ea: loom_Optional[int]
    loom_pred_start_ea: loom_Optional[int]
    loom_reason: loom_Optional[str] = None

@loom_dataclass
class DestinationChoice(ExchangeRecord):
    exchange_shape = [('state', 'loom_state', 'plain', True, True), ('idx', 'loom_idx', 'plain', False, True), ('target', 'destination', 'address', False, True), ('verify', 'equivalence', 'plain', True, True), ('cond', 'loom_cond', 'plain', False, True), ('cond_case', 'loom_cond_case', 'plain', False, True)]
    loom_state: int
    loom_idx: loom_Optional[int]
    destination: loom_Optional[int]
    equivalence: str
    loom_cond: loom_Optional[str] = None
    loom_cond_case: loom_Optional[str] = None

@loom_dataclass
class DestinationSet(ExchangeRecord):
    exchange_shape = [('dispatcher_br_ea', 'loom_dispatcher_br_ea', 'address', True, True), ('parent_fn_ea', 'loom_parent_fn_ea', 'address', False, True), ('parent_fn_name', 'loom_parent_fn_name', 'plain', False, True), ('via_class', 'loom_via_class', 'plain', True, True), ('state_slot', 'loom_state_slot', 'plain', False, True), ('state_base', 'loom_state_base', 'plain', False, True), ('idx_tbl_ea', 'loom_idx_tbl_ea', 'address', False, True), ('tgt_tbl_ea', 'loom_tgt_tbl_ea', 'address', False, True), ('str_ea', 'loom_str_ea', 'address', False, True), ('pred_start_ea', 'loom_pred_start_ea', 'address', False, True), ('entries', 'loom_entries', 'choice_list', False, True)]
    loom_dispatcher_br_ea: int
    loom_parent_fn_ea: loom_Optional[int]
    loom_parent_fn_name: loom_Optional[str]
    loom_via_class: str
    loom_state_slot: loom_Optional[int]
    loom_state_base: loom_Optional[str]
    loom_idx_tbl_ea: loom_Optional[int]
    loom_tgt_tbl_ea: loom_Optional[int]
    loom_str_ea: loom_Optional[int]
    loom_pred_start_ea: loom_Optional[int]
    loom_entries: loom_List[DestinationChoice] = loom_field(default_factory=list)

@loom_dataclass
class ByteRewrite(ExchangeRecord):
    exchange_shape = [('pc', 'location', 'address', True, True), ('size', 'span', 'plain', True, True), ('orig_bytes_hex', 'loom_orig_bytes_hex', 'plain', True, True), ('new_bytes_hex', 'loom_new_bytes_hex', 'plain', True, True), ('reason', 'loom_reason', 'plain', True, True), ('parent_fn', 'loom_parent_fn', 'address', False, True), ('dispatcher_pc', 'loom_dispatcher_pc', 'address', False, True), ('via_state', 'loom_via_state', 'plain', False, True), ('via_case', 'loom_via_case', 'plain', False, True), ('verify', 'equivalence', 'plain', False, True), ('target_ea', 'loom_target_ea', 'address', False, True)]
    location: int
    span: int
    loom_orig_bytes_hex: str
    loom_new_bytes_hex: str
    loom_reason: str
    loom_parent_fn: loom_Optional[int]
    loom_dispatcher_pc: loom_Optional[int]
    loom_via_state: loom_Optional[int] = None
    loom_via_case: loom_Optional[str] = None
    equivalence: loom_Optional[str] = None
    loom_target_ea: loom_Optional[int] = None

LOOM_CLASSES = ('CONST', 'COND2', 'XFORM', 'OPAQUE')
LOOM_VERDICTS = ('OK', 'UNVERIFIED', 'MISMATCH', 'INVALID')
