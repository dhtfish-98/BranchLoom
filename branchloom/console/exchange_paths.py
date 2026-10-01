"""Artifact filenames and the subcommand -> phase-module wiring.

The pipeline is a chain of plain JSON files. This module is the single place that
knows what those files are called by default and which Tier-3 phase module backs
each phase subcommand, so the command handlers never hard-code either.
"""
from __future__ import annotations as loom_annotations
import importlib as loom_importlib
from typing import Dict as loom_Dict, Optional as loom_Optional, Tuple as loom_Tuple
__all__ = ['LOOM_DEFAULTS', 'LOOM_PHASE_MODULE', 'LOOM_PHASE_IO', 'loom_default_path', 'loom_load_phase']
LOOM_DEFAULTS = {'dispatchers': 'cff_dispatchers.json', 'predecessors': 'cff_predecessors.json', 'resolutions': 'cff_resolutions.json', 'plan': 'cff_patch_plan.json', 'switch_log': 'cff_switch_info_log.json'}
LOOM_PHASE_MODULE = {'census': 'enumeration', 'classify': 'categorization', 'resolve': 'destination_lookup', 'plan': 'rewrite_design', 'apply': 'byte_commit', 'switch': 'graph_commit'}
LOOM_PHASE_IO: loom_Dict[str, loom_Tuple[loom_Optional[str], loom_Optional[str]]] = {'census': (None, 'dispatchers'), 'classify': ('dispatchers', 'predecessors'), 'resolve': ('predecessors', 'resolutions'), 'plan': ('resolutions', 'plan'), 'apply': ('plan', None), 'switch': ('dispatchers', 'switch_log')}

def loom_default_path(loom_key_value: loom_Optional[str]) -> loom_Optional[str]:
    """Default artifact filename for a DEFAULTS key; ``None`` passes through."""
    return LOOM_DEFAULTS[loom_key_value] if loom_key_value else None

def loom_load_phase(loom_cmd: str):
    """Import the Tier-3 phase module backing ``cmd`` (census/classify/.../switch).

    Imported lazily, by name, so the CLI stays importable outside a live IDA.
    """
    loom_modname = LOOM_PHASE_MODULE[loom_cmd]
    try:
        return loom_importlib.import_module('branchloom.pipeline.' + loom_modname)
    except ImportError as loom_exc:
        raise RuntimeError("phase module 'branchloom.pipeline.%s' is not available (%s). The Tier-3 phase layer must be installed to run '%s'." % (loom_modname, loom_exc, loom_cmd)) from loom_exc

# TODO(validate): the p{N}_{name} module names follow METHODOLOGY.md §5 and the
