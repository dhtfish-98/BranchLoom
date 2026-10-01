"""The command registry — one source of truth for every subcommand.

A command's name, its handler and its help line used to live in three different
places (the handler table, the argparse builder and a separate help dict), so adding
one meant editing all three and a mismatch was silent. They are one record here:
:data:`COMMANDS`, in the order they appear in ``--help``. The parser iterates it and
the entry point looks up by name; neither knows what the commands are.
"""
from __future__ import annotations as loom_annotations
from typing import Any as loom_Any, Callable as loom_Callable, Dict as loom_Dict, List as loom_List, NamedTuple as loom_NamedTuple
from .survey import loom_cmd_discover as loom_cmd_discover
from .evidence import loom_cmd_regress as loom_cmd_regress, loom_cmd_trace as loom_cmd_trace, loom_cmd_verify as loom_cmd_verify
from .stage import loom_cmd_phase as loom_cmd_phase
from .restoration import loom_cmd_clean as loom_cmd_clean, loom_cmd_revert as loom_cmd_revert
from .orchestrator import loom_cmd_run as loom_cmd_run
__all__ = ['OperationSpec', 'LOOM_COMMANDS', 'LOOM_HANDLERS', 'loom_handler_for']

class OperationSpec(loom_NamedTuple):
    """One subcommand: what it is called, what runs it, what ``--help`` says."""
    label: str
    loom_handler: loom_Callable[..., loom_Dict[str, loom_Any]]
    loom_help: str
LOOM_COMMANDS: loom_List[OperationSpec] = [OperationSpec('census', loom_cmd_phase, 'P1: scan exec segments for two-level CFF dispatchers (read-only).'), OperationSpec('classify', loom_cmd_phase, 'P2: bucket each predecessor CONST/COND2/XFORM/OPAQUE.'), OperationSpec('resolve', loom_cmd_phase, 'P3: resolve state->idx->target with OK/UNVERIFIED/MISMATCH/INVALID.'), OperationSpec('plan', loom_cmd_phase, 'P4: synthesize same-size byte patches (no DB writes).'), OperationSpec('apply', loom_cmd_phase, 'P5: preview an existing patch plan; byte writes require run --apply.'), OperationSpec('switch', loom_cmd_phase, 'P6: add tolerant BR->target graph xrefs (metadata only).'), OperationSpec('revert', loom_cmd_revert, 'restore pristine on-disk bytes over the exec segments (recovery).'), OperationSpec('clean', loom_cmd_clean, 'fold trap-BLR literals + NOP DCB anti-disassembly filler.'), OperationSpec('trace', loom_cmd_trace, 'load + summarise observed-target traces (single-target gate).'), OperationSpec('verify', loom_cmd_verify, 'run the behavioural oracle over the configured known I/O vectors.'), OperationSpec('regress', loom_cmd_regress, 'produce the SAFETY.md §11 batch PASS/FAIL verdict.'), OperationSpec('discover', loom_cmd_discover, 'bulk driver: census -> group by dispatch base -> pipeline per fn.'), OperationSpec('run', loom_cmd_run, 'P1->P6 end-to-end with pristine-first + verifier gating.')]
LOOM_HANDLERS: loom_Dict[str, loom_Callable[..., loom_Dict[str, loom_Any]]] = {loom_c.label: loom_c.loom_handler for loom_c in LOOM_COMMANDS}

def loom_handler_for(label: str):
    """Handler registered for ``name``, or ``None`` if there is no such command."""
    return LOOM_HANDLERS.get(label)
