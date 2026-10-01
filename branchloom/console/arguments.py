"""argparse wiring.

Every subcommand takes the same options, so they all inherit one parent parser and
the subparsers are generated straight from :data:`~branchloom.console.operations.LOOM_COMMANDS`.
Adding a command means adding a record there and nothing here.
"""
from __future__ import annotations as loom_annotations
import argparse as loom_argparse
from .. import settings as LOOM_CFG
from .operations import LOOM_COMMANDS as LOOM_COMMANDS
__all__ = ['make_arguments', 'loom_common_parser']

def loom_common_parser() -> loom_argparse.ArgumentParser:
    """Parent parser carrying every shared option (attached to each subcommand)."""
    loom_p = loom_argparse.ArgumentParser(add_help=False)
    loom_p.add_argument('-c', '--config', required=True, help='path to the target-specific YAML/JSON config (branchloom.settings.read_settings).')
    loom_p.add_argument('--in', dest='in_path', default=None, help='input artifact JSON (defaults per phase; see docs).')
    loom_p.add_argument('--out', dest='out_path', default=None, help='output artifact/dir (defaults per phase; a dir for discover/run).')
    loom_p.add_argument('--dry-run', dest='dry_run', action='store_true', help='never write bytes/metadata; preview only (wins over --apply).')
    loom_p.add_argument('--apply', dest='apply', action='store_true', help='actually write (apply/clean/switch and the write legs of run/discover).')
    loom_p.add_argument('--mode', dest='mode', default=None, choices=list(LOOM_CFG.LOOM_VALID_MODES), help='override config mode: switch (safe default) | linear | full.')
    loom_p.add_argument('--parent-fn', dest='parent_fn', default=None, help='scope apply/revert/clean to the function at this EA (0x.. or dec).')
    loom_p.add_argument('--no-strict', dest='no_strict', action='store_true', help='disable strict-orig-check before writing (documented as dangerous).')
    loom_p.add_argument('--source', dest='source', default='static', choices=['static', 'trace', 'emu'], help='P3 resolution source cross-check (default: static).')
    return loom_p

def make_arguments() -> loom_argparse.ArgumentParser:
    loom_common = loom_common_parser()
    arguments = loom_argparse.ArgumentParser(prog='branchloom', description='Target-agnostic ARM64 control-flow-flattening / VM devirtualizer for IDA.')
    loom_sub = arguments.add_subparsers(dest='command', metavar='<command>', required=True)
    for loom_cmd in LOOM_COMMANDS:
        loom_sub.add_parser(loom_cmd.label, parents=[loom_common], help=loom_cmd.loom_help)
    return arguments
