"""branchloom.console — the argparse front-end that ties the whole pipeline together.

The command line is a thin router: it loads the :class:`~branchloom.settings.AnalysisSettings` via
``LOOM_CFG.read_settings(--config)``, opens the single IDA boundary
(:mod:`branchloom.database.bridge`), and dispatches to the phase ``execute_stage()`` functions
(P1 census -> P2 classify -> P3 resolve -> P4 plan -> P5 apply -> P6 switch) plus the
standalone helpers (revert, clean, trace, verify, regress). Two aggregate drivers sit
on top:

  * ``discover`` — bulk driver: scan the exec segments, group the two-level
    dispatchers by dispatch base, and run the per-function pipeline for each group.
  * ``run`` — the P1->P6 end-to-end pass with pristine-first restore and the
    experimental verifier check after byte application, with rollback on failure.

Every subcommand honours ``--in`` / ``--out`` / ``--dry-run`` / ``--apply`` /
``--mode`` / ``--parent-fn`` / ``--no-strict`` / ``--source``.

Layout:

  * :mod:`~branchloom.console.operations` — the command registry and the handlers.
  * :mod:`~branchloom.console.arguments` — argparse wiring, generated from that registry.
  * :mod:`~branchloom.console.exchange_paths` — artifact filenames + phase-module lookup.
  * :mod:`~branchloom.console.context` — the plumbing every handler shares.

Design rules honoured throughout:
  * NOTHING target-specific lives here — every address, segment, table and vector
    comes from the AnalysisSettings.
  * ``idaapi`` is never imported at module load. The IDA adapter (and every phase /
    safety / verify module that reaches the DB) is imported lazily inside the
    handler that needs it, so ``--help`` and ``py_compile`` work off-device.
  * The standalone apply command previews only. Mutating commands (clean / switch
    and the write legs of run / discover) only write when ``--apply`` is given and ``--dry-run`` is not
    (dry-run always wins). ``revert`` is the recovery escape hatch and restores
    unless ``--dry-run`` is set.

The six phase modules are imported through the mapping in
``branchloom.console.exchange_paths.LOOM_PHASE_MODULE``. Each exposes
``execute_stage(bridge, settings, loom_in_path=None, loom_out_path=None, **loom_kw) -> dict``.
"""
from __future__ import annotations as loom_annotations
import json as loom_json
import sys as loom_sys
import traceback as loom_traceback
from typing import Any as loom_Any, List as loom_List, Optional as loom_Optional
from .. import settings as LOOM_CFG
from .operations import LOOM_COMMANDS as LOOM_COMMANDS, loom_handler_for as loom_handler_for
from .arguments import make_arguments as make_arguments
from .context import loom_apply_overrides as loom_apply_overrides
__all__ = ['launch', 'make_arguments', 'LOOM_COMMANDS']

def loom_emit(loom_summary: loom_Any) -> int:
    """Print the summary as JSON and derive a process exit code."""
    print(loom_json.dumps(loom_summary, indent=2, default=str))
    if not isinstance(loom_summary, dict):
        return 0
    if loom_summary.get('error'):
        return 1
    loom_verdict = loom_summary.get('verdict')
    if loom_verdict in ('FAIL', 'MISMATCH', 'INVALID'):
        return 1
    if loom_summary.get('ok') is False:
        return 1
    return 0

def launch(tokens: loom_Optional[loom_List[str]]=None) -> int:
    arguments = make_arguments()
    options = arguments.parse_args(tokens)
    loom_handler = loom_handler_for(options.command)
    if loom_handler is None:
        arguments.error('unknown command %r' % (options.command,))
        return 2
    try:
        settings = LOOM_CFG.read_settings(options.config)
        loom_apply_overrides(settings, options)
        loom_summary = loom_handler(options, settings)
    except LOOM_CFG.SettingsFault as loom_exc:
        return loom_emit({'command': options.command, 'error': 'config error: %s' % (loom_exc,)})
    except Exception as loom_exc:
        return loom_emit({'command': options.command, 'error': repr(loom_exc), 'traceback': loom_traceback.format_exc()})
    return loom_emit(loom_summary)
if __name__ == '__main__':
    loom_sys.exit(launch())
