from __future__ import annotations as loom_annotations
import json as loom_json
from dataclasses import asdict as loom_asdict, dataclass as loom_dataclass, field as loom_field
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional

def loom_hx_value(loom_v: loom_Optional[int]) -> loom_Optional[str]:
    return None if loom_v is None else f'0x{loom_v:x}'

def loom_unhx(loom_s: loom_Optional[str]) -> loom_Optional[int]:
    if loom_s is None:
        return None
    if isinstance(loom_s, int):
        return loom_s
    return int(loom_s, 16)
'Stable JSON field names are independent of in-memory identifiers.'

class ExchangeRecord:
    exchange_shape = ()

    def export_record(record):
        document = {}
        for wire_label, member, representation, required, input_field in record.exchange_shape:
            field_payload = getattr(record, member)
            if representation == 'address':
                field_payload = loom_hx_value(field_payload)
            elif representation == 'address_list':
                field_payload = [loom_hx_value(address) for address in field_payload]
            elif representation == 'choice_list':
                field_payload = [choice.export_record() for choice in field_payload]
            document[wire_label] = field_payload
        return document

    @classmethod
    def import_record(record_type, document):
        arguments = {}
        for wire_label, member, representation, required, input_field in record_type.exchange_shape:
            if not input_field:
                continue
            field_payload = document[wire_label] if required else document.get(wire_label)
            if representation == 'address':
                field_payload = loom_unhx(field_payload)
            elif representation == 'address_list':
                field_payload = [loom_unhx(address) for address in document.get(wire_label, [])]
            elif representation == 'choice_list':
                from .shapes import DestinationChoice
                field_payload = [DestinationChoice.import_record(choice) for choice in document.get(wire_label, [])]
            elif representation == 'mapping':
                field_payload = document.get(wire_label, {})
            arguments[member] = field_payload
        return record_type(**arguments)
