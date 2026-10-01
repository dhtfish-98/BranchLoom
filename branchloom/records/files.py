from __future__ import annotations as loom_annotations
import json as loom_json
from dataclasses import asdict as loom_asdict, dataclass as loom_dataclass, field as loom_field
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional
from .shapes import LOOM_CLASSES, LOOM_VERDICTS, RouteHub, IncomingBlock, DestinationChoice, DestinationSet, ByteRewrite
from .codec import loom_hx_value, loom_unhx

def loom_dump(loom_obj: loom_Any, location_path: str) -> None:
    with open(location_path, 'w', encoding='utf-8') as stream:
        loom_json.dump(loom_obj, stream, indent=2)

def loom_load(location_path: str) -> loom_Any:
    with open(location_path, 'r', encoding='utf-8') as stream:
        return loom_json.load(stream)

def write_hubs(items: loom_List[RouteHub], location_path: str, loom_meta: loom_Optional[dict]=None) -> None:
    loom_dump({'meta': loom_meta or {'count': len(items)}, 'dispatchers': [loom_r.export_record() for loom_r in items]}, location_path)

def read_hubs(location_path: str) -> loom_List[RouteHub]:
    return [RouteHub.import_record(loom_d_value) for loom_d_value in loom_load(location_path)['dispatchers']]

def write_incoming(items: loom_List[IncomingBlock], location_path: str) -> None:
    loom_counts = {loom_c: sum((1 for loom_r in items if loom_r.record_type == loom_c)) for loom_c in LOOM_CLASSES}
    loom_dump({'meta': {'count': len(items), 'classes': loom_counts}, 'predecessors': [loom_r.export_record() for loom_r in items]}, location_path)

def read_incoming(location_path: str) -> loom_List[IncomingBlock]:
    return [IncomingBlock.import_record(loom_d_value) for loom_d_value in loom_load(location_path)['predecessors']]

def write_destinations(items: loom_List[DestinationSet], location_path: str, loom_stats_value: loom_Optional[dict]=None) -> None:
    loom_dump({'meta': {'count': len(items), 'stats': loom_stats_value or {}}, 'resolutions': [loom_r.export_record() for loom_r in items]}, location_path)

def read_destinations(location_path: str) -> loom_List[DestinationSet]:
    return [DestinationSet.import_record(loom_d_value) for loom_d_value in loom_load(location_path)['resolutions']]

def write_rewrites(items: loom_List[ByteRewrite], location_path: str, loom_by_parent: loom_Optional[dict]=None, loom_skipped: loom_Optional[dict]=None) -> None:
    loom_dump({'meta': {'patches': len(items), 'skipped': loom_skipped or {}}, 'by_parent': loom_by_parent or {}, 'patches': [loom_r.export_record() for loom_r in items]}, location_path)

def read_rewrites(location_path: str) -> loom_List[ByteRewrite]:
    return [ByteRewrite.import_record(loom_d_value) for loom_d_value in loom_load(location_path)['patches']]
