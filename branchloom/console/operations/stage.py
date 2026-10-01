"""The six phase-routed subcommands: census / classify / resolve / plan / apply / switch.

Each one is the same thing — resolve the artifact in/out paths, open the IDA
boundary, hand the phase module the uniform keyword bundle — so they share one
handler and differ only by the :data:`~branchloom.console.exchange_paths.LOOM_PHASE_IO` entry.
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
from typing import Any as loom_Any, Dict as loom_Dict
from ...settings import AnalysisSettings as AnalysisSettings, SettingsFault as SettingsFault
from ..exchange_paths import LOOM_PHASE_IO as LOOM_PHASE_IO, loom_default_path as loom_default_path, loom_load_phase as loom_load_phase
from ..context import loom_open_adapter as loom_open_adapter, loom_phase_kwargs as loom_phase_kwargs, loom_will_write as loom_will_write
__all__ = ['loom_cmd_phase']

def loom_cmd_phase(options: loom_argparse.Namespace, settings: AnalysisSettings) -> loom_Dict[str, loom_Any]:
    loom_cmd = options.command
    if loom_cmd == 'apply' and loom_will_write(options):
        raise SettingsFault('The apply command previews an existing plan only. Use run --apply --mode linear or full to include the verifier and rollback flow.')
    loom_in_key, loom_out_key = LOOM_PHASE_IO[loom_cmd]
    loom_in_path = options.in_path or loom_default_path(loom_in_key)
    loom_out_path = options.out_path or loom_default_path(loom_out_key)
    bridge = loom_open_adapter()
    stage = loom_load_phase(loom_cmd)
    loom_summary = stage.execute_stage(bridge, settings, loom_in_path=loom_in_path, loom_out_path=loom_out_path, **loom_phase_kwargs(options))
    if isinstance(loom_summary, dict):
        loom_summary.setdefault('command', loom_cmd)
        loom_summary.setdefault('in_path', loom_in_path)
        loom_summary.setdefault('out_path', loom_out_path)
        return loom_summary
    return {'command': loom_cmd, 'in_path': loom_in_path, 'out_path': loom_out_path, 'result': loom_summary}
