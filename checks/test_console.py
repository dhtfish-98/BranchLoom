"""
Unit tests for the CLI front-end (branchloom.console).

The command line is a thin router, and these tests pin the two rules that keep it
thin. First, the command registry is the single source of truth: a command's name,
handler and help line live in one record, so the parser and the entry point can
never drift apart. Second — the load-bearing one — ``idaapi`` is never imported at
module load, so ``--help``, ``compileall`` and this test file all work outside a
live IDA.

Run:  pytest -q
"""
import sys as loom_sys
from branchloom.console import make_arguments as make_arguments
from branchloom.console.exchange_paths import LOOM_DEFAULTS as LOOM_DEFAULTS, LOOM_PHASE_IO as LOOM_PHASE_IO, LOOM_PHASE_MODULE as LOOM_PHASE_MODULE, loom_default_path as loom_default_path
from branchloom.console.operations import LOOM_COMMANDS as LOOM_COMMANDS, LOOM_HANDLERS as LOOM_HANDLERS, loom_handler_for as loom_handler_for
from branchloom.console.operations.stage import loom_cmd_phase as loom_cmd_phase
from branchloom.console.context import loom_parse_int as loom_parse_int, loom_phase_kwargs as loom_phase_kwargs, loom_will_write as loom_will_write

class ArgumentView:
    """Stand-in for the argparse namespace the runtime helpers read."""

    def __init__(record, **loom_kw):
        record.__dict__.update(loom_kw)

def test_loom_importing_the_cli_does_not_import_idaapi():
    """If this breaks, --help and every off-device tool break with it."""
    assert 'idaapi' not in loom_sys.modules

def test_loom_every_command_is_complete_and_unique():
    loom_names = [loom_c.label for loom_c in LOOM_COMMANDS]
    assert len(loom_names) == len(set(loom_names))
    for loom_c in LOOM_COMMANDS:
        assert loom_c.label and callable(loom_c.loom_handler)
        assert loom_c.loom_help and loom_c.loom_help.endswith('.')

def test_loom_handlers_table_is_derived_from_the_registry():
    assert LOOM_HANDLERS == {loom_c.label: loom_c.loom_handler for loom_c in LOOM_COMMANDS}
    assert loom_handler_for('run') is LOOM_HANDLERS['run']
    assert loom_handler_for('no-such-command') is None

def test_loom_the_six_phase_commands_share_one_handler():
    for label in LOOM_PHASE_MODULE:
        assert loom_handler_for(label) is loom_cmd_phase

def test_loom_phase_wiring_covers_exactly_the_phase_commands():
    assert set(LOOM_PHASE_IO) == set(LOOM_PHASE_MODULE)
    loom_registered = {loom_c.label for loom_c in LOOM_COMMANDS}
    assert set(LOOM_PHASE_MODULE) <= loom_registered

def test_loom_phase_io_chains_each_output_into_the_next_input():
    """P1 -> P2 -> P3 -> P4 is a file chain; a broken link silently reads stale data."""
    loom_chain = ['census', 'classify', 'resolve', 'plan']
    for loom_produced, loom_consumed in zip(loom_chain, loom_chain[1:]):
        assert LOOM_PHASE_IO[loom_produced][1] == LOOM_PHASE_IO[loom_consumed][0]
    assert LOOM_PHASE_IO['census'][0] is None
    assert LOOM_PHASE_IO['apply'][1] is None

def test_loom_artifact_defaults_resolve_and_are_distinct():
    for loom_key_value in LOOM_DEFAULTS:
        assert loom_default_path(loom_key_value) == LOOM_DEFAULTS[loom_key_value]
        assert loom_default_path(loom_key_value).endswith('.json')
    assert loom_default_path(None) is None
    assert len(set(LOOM_DEFAULTS.values())) == len(LOOM_DEFAULTS)

def test_loom_parser_accepts_every_registered_command():
    arguments = make_arguments()
    for loom_c in LOOM_COMMANDS:
        options = arguments.parse_args([loom_c.label, '--config', 'cfg.json'])
        assert options.command == loom_c.label
        assert options.config == 'cfg.json'

def test_loom_parser_rejects_an_unregistered_command():
    arguments = make_arguments()
    try:
        arguments.parse_args(['definitely-not-a-command', '--config', 'cfg.json'])
    except SystemExit as loom_exc:
        assert loom_exc.code != 0
    else:
        raise AssertionError('expected argparse to reject an unknown command')

def test_loom_config_is_required_on_every_command():
    arguments = make_arguments()
    for loom_c in LOOM_COMMANDS:
        try:
            arguments.parse_args([loom_c.label])
        except SystemExit as loom_exc:
            assert loom_exc.code != 0
        else:
            raise AssertionError('expected --config to be required for %r' % loom_c.label)

def test_loom_every_command_carries_the_shared_options():
    arguments = make_arguments()
    for loom_c in LOOM_COMMANDS:
        options = arguments.parse_args([loom_c.label, '--config', 'cfg.json', '--in', 'i.json', '--out', 'o.json', '--dry-run', '--apply', '--mode', 'switch', '--parent-fn', '0x1000', '--no-strict', '--source', 'trace'])
        assert options.in_path == 'i.json' and options.out_path == 'o.json'
        assert options.dry_run is True and options.apply is True
        assert options.mode == 'switch' and options.parent_fn == '0x1000'
        assert options.no_strict is True and options.source == 'trace'

def test_loom_source_defaults_to_static():
    arguments = make_arguments()
    assert arguments.parse_args(['resolve', '--config', 'c.json']).source == 'static'

def test_loom_mode_choices_are_the_config_modes():
    arguments = make_arguments()
    try:
        arguments.parse_args(['run', '--config', 'c.json', '--mode', 'nonsense'])
    except SystemExit as loom_exc:
        assert loom_exc.code != 0
    else:
        raise AssertionError('expected argparse to reject an invalid --mode')

def test_loom_a_command_writes_only_on_an_explicit_apply():
    assert loom_will_write(ArgumentView(apply=True, dry_run=False)) is True
    assert loom_will_write(ArgumentView(apply=False, dry_run=False)) is False

def test_loom_dry_run_beats_apply():
    """A preview is never destructive, even when --apply is also passed."""
    assert loom_will_write(ArgumentView(apply=True, dry_run=True)) is False

def test_loom_write_intent_defaults_to_false_when_the_flags_are_absent():
    assert loom_will_write(ArgumentView()) is False

def test_loom_phase_kwargs_carries_the_write_intent_and_scope():
    loom_kw = loom_phase_kwargs(ArgumentView(apply=True, dry_run=False, source='emu', parent_fn='0x1400'))
    assert loom_kw == {'apply': True, 'dry_run': False, 'source': 'emu', 'parent_fn': 5120}

def test_loom_parse_int_accepts_hex_decimal_and_none():
    assert loom_parse_int('0x1400') == 5120
    assert loom_parse_int('5120') == 5120
    assert loom_parse_int(5120) == 5120
    assert loom_parse_int(None) is None
    assert loom_parse_int('  ') is None

def test_loom_parse_int_rejects_garbage_rather_than_defaulting():
    try:
        loom_parse_int('not-an-address')
    except ValueError:
        pass
    else:
        raise AssertionError('expected a ValueError rather than a silent default')
