"""
branchloom.settings — the single home of every target-specific value.

The code ships nothing binary-specific. Segment selectors, CFF pattern parameters,
the trace source, the verifier backend + memory layout + shim registry, per-function
jobs, the rewrite-mode gate and regression baselines all live in a YAML file the
user writes. ``profiles/neutral.yml`` documents every knob with neutral defaults.

YAML is loaded with PyYAML when available; otherwise a JSON config with the same
shape is accepted so the tool still runs inside a bare IDA Python with no installs.
"""
from __future__ import annotations as loom_annotations
import json as loom_json
import os as loom_os
from dataclasses import dataclass as loom_dataclass, field as loom_field
from typing import Any as loom_Any, Dict as loom_Dict, List as loom_List, Optional as loom_Optional
try:
    import yaml as loom_yaml
    LOOM__HAVE_YAML = True
except Exception:
    LOOM__HAVE_YAML = False
LOOM_VALID_MODES = ('switch', 'linear', 'full')

class SettingsFault(ValueError):
    pass

@loom_dataclass
class ExecutableRegion:
    label: loom_Optional[str] = None
    loom_range: loom_Optional[loom_List[int]] = None

    def loom_matches_name(record, loom_seg_name_value: str) -> bool:
        return record.label is not None and record.label == loom_seg_name_value

@loom_dataclass
class AnalysisSettings:
    source: loom_Dict[str, loom_Any]
    loom_image: loom_Optional[str]
    loom_reloc_image: loom_Optional[str]
    loom_exec_segments: loom_List[ExecutableRegion]
    loom_cff: loom_Dict[str, loom_Any]
    loom_jobs: loom_List[loom_Dict[str, loom_Any]]
    loom_trace: loom_Dict[str, loom_Any]
    loom_verifier: loom_Dict[str, loom_Any]
    loom_mode: str
    loom_strict_orig_check: bool
    batch_verdict: loom_Dict[str, loom_Any]

    @property
    def loom_idx_table_scale(record) -> int:
        return int(record.loom_cff.get('idx_table_scale', 2))

    @property
    def loom_tgt_table_scale(record) -> int:
        return int(record.loom_cff.get('tgt_table_scale', 3))

    @property
    def loom_entry_size(record) -> int:
        return int(record.loom_cff.get('entry_size', 8))

    @property
    def loom_state_slot_bases(record) -> loom_List[str]:
        return list(record.loom_cff.get('state_slot_bases', ['X29', 'SP']))

    @property
    def loom_index_reg_allowlist(record) -> loom_List[int]:
        return list(record.loom_cff.get('index_reg_allowlist', []))

    @property
    def loom_dispatch_base_overrides(record) -> loom_Dict[int, int]:
        source = record.loom_cff.get('dispatch_base_overrides', {}) or {}
        return {int(loom_k, 16) if isinstance(loom_k, str) else int(loom_k): int(loom_v, 16) if isinstance(loom_v, str) else int(loom_v) for loom_k, loom_v in source.items()}

def loom_read(location_path: str) -> loom_Dict[str, loom_Any]:
    with open(location_path, 'r', encoding='utf-8') as stream:
        loom_text = stream.read()
    if location_path.endswith(('.yml', '.yaml')):
        if not LOOM__HAVE_YAML:
            raise SettingsFault("PyYAML is not installed but a .yml config was given. Either `pip install pyyaml` (the 'config' extra) or provide a JSON config.")
        return loom_yaml.safe_load(loom_text) or {}
    return loom_json.loads(loom_text)

def read_settings(location_path: str) -> AnalysisSettings:
    if not loom_os.path.exists(location_path):
        raise SettingsFault(f'config not found: {location_path}')
    loom_d_value = loom_read(location_path)
    loom_segs_raw = loom_d_value.get('exec_segments', []) or []
    loom_segs = [ExecutableRegion(label=loom_s.get('name'), loom_range=loom_s.get('range')) for loom_s in loom_segs_raw]
    loom_mode = loom_d_value.get('mode', 'switch')
    if loom_mode not in LOOM_VALID_MODES:
        raise SettingsFault(f'mode must be one of {LOOM_VALID_MODES}, got {loom_mode!r}')
    settings = AnalysisSettings(source=loom_d_value, loom_image=loom_d_value.get('image'), loom_reloc_image=loom_d_value.get('reloc_image'), loom_exec_segments=loom_segs, loom_cff=loom_d_value.get('cff', {}) or {}, loom_jobs=loom_d_value.get('jobs', []) or [], loom_trace=loom_d_value.get('trace', {}) or {}, loom_verifier=loom_d_value.get('verifier', {}) or {}, loom_mode=loom_mode, loom_strict_orig_check=bool(loom_d_value.get('strict_orig_check', True)), batch_verdict=loom_d_value.get('regression', {}) or {})
    loom_validate(settings)
    return settings

def loom_validate(settings: AnalysisSettings) -> None:
    if not settings.loom_exec_segments:
        raise SettingsFault("config.exec_segments is empty — specify at least one segment by name or [start,end] range (never assume '.text').")
    for loom_s in settings.loom_exec_segments:
        if loom_s.label is None and loom_s.loom_range is None:
            raise SettingsFault("each exec_segments entry needs a 'name' or a 'range'.")
        if loom_s.loom_range is not None and (len(loom_s.loom_range) != 2 or loom_s.loom_range[0] >= loom_s.loom_range[1]):
            raise SettingsFault(f'bad exec_segments range: {loom_s.loom_range}')
    if settings.loom_mode in ('linear', 'full'):
        loom_ver = settings.loom_verifier or {}
        if not loom_ver.get('known_vectors'):
            raise SettingsFault(f"mode={settings.loom_mode!r} rewrites instruction bytes and requires verifier.known_vectors. Those vectors are an experimental check, not a proof of equivalent behaviour. Use mode='switch' for a metadata-only run.")

__all__ = [export_binding for export_binding in ['AnalysisSettings', 'ExecutableRegion', 'LOOM_VALID_MODES', 'SettingsFault', 'loom_Any', 'loom_Dict', 'loom_List', 'loom_Optional', 'loom_annotations', 'loom_dataclass', 'loom_field', 'loom_json', 'loom_os', 'loom_yaml', 'read_settings'] if export_binding in globals()]
