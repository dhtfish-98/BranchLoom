"""Exercise the real CLI and P5 against a disposable in-memory adapter."""
import contextlib as loom_contextlib
import io as loom_io
import json as loom_json
import tempfile as loom_tempfile
from pathlib import Path as loom_Path
from types import SimpleNamespace as loom_SimpleNamespace
from unittest.mock import patch as loom_patch
from branchloom import console as console, settings as loom_config_value
from branchloom.console.operations import orchestrator as loom_run_command
from branchloom.pipeline import byte_commit as byte_commit

class BranchLoomMemoryAdapter:

    def __init__(record):
        record.content = bytearray(4)
        record.loom_writes = []

    def loom_get_bytes(record, location, loom_n_value):
        return bytes(record.content[:loom_n_value])

    def loom_read_input_bytes(record, location, loom_n_value):
        return bytes(loom_n_value)

    def loom_get_dword(record, location):
        return int.from_bytes(record.content, 'little')

    def loom_patch_bytes(record, location, content):
        record.loom_writes.append((location, bytes(content)))
        record.content[:len(content)] = content

    def loom_make_code(record, *options):
        pass

    def loom_func_at(record, *options):
        return (4096, 'fixture')

    def loom_reanalyze(record, *options):
        pass

    def loom_auto_wait(record):
        pass

def loom_fixture(loom_directory):
    settings = loom_Path(loom_directory) / 'config.json'
    loom_plan = loom_Path(loom_directory) / 'plan.json'
    settings.write_text(loom_json.dumps({'exec_segments': [{'range': [4096, 4100]}], 'mode': 'switch'}))
    loom_plan.write_text(loom_json.dumps({'patches': [{'pc': '0x1000', 'size': 4, 'orig_bytes_hex': '00000000', 'new_bytes_hex': '11223344', 'reason': 'synthetic bytes', 'parent_fn': '0x1000'}]}))
    return (settings, loom_plan)

def test_loom_apply_cli_previews_without_writes_even_with_both_flags():
    with loom_tempfile.TemporaryDirectory() as loom_td:
        settings, loom_plan = loom_fixture(loom_td)
        for loom_flags in ([], ['--dry-run'], ['--apply', '--dry-run']):
            bridge = BranchLoomMemoryAdapter()
            with loom_patch('branchloom.console.operations.stage.loom_open_adapter', return_value=bridge), loom_contextlib.redirect_stdout(loom_io.StringIO()):
                loom_code = console.launch(['apply', '--config', str(settings), '--in', str(loom_plan)] + loom_flags)
            assert loom_code == 0
            assert bridge.loom_writes == []

def test_loom_standalone_apply_cannot_skip_pipeline_verification():
    with loom_tempfile.TemporaryDirectory() as loom_td:
        settings, loom_plan = loom_fixture(loom_td)
        bridge = BranchLoomMemoryAdapter()
        with loom_patch('branchloom.console.operations.stage.loom_open_adapter', return_value=bridge), loom_contextlib.redirect_stdout(loom_io.StringIO()), loom_contextlib.redirect_stderr(loom_io.StringIO()):
            loom_code = console.launch(['apply', '--config', str(settings), '--in', str(loom_plan), '--apply'])
        assert loom_code != 0
        assert bridge.loom_writes == []

def test_loom_p5_requires_explicit_intent_and_aggressive_mode():
    with loom_tempfile.TemporaryDirectory() as loom_td:
        loom_cfg_path, loom_plan = loom_fixture(loom_td)
        settings = loom_config_value.read_settings(str(loom_cfg_path))
        bridge = BranchLoomMemoryAdapter()
        with loom_contextlib.redirect_stdout(loom_io.StringIO()):
            loom_result = byte_commit.execute_stage(bridge, settings, str(loom_plan), dry_run=False)
        assert loom_result['dry_run'] and (not bridge.loom_writes)
        try:
            byte_commit.execute_stage(bridge, settings, str(loom_plan), apply=True, dry_run=False)
        except ValueError as loom_exc:
            assert 'metadata-only' in str(loom_exc)
        else:
            raise AssertionError('switch mode wrote bytes')
        assert not bridge.loom_writes
        settings.loom_mode = 'linear'
        try:
            byte_commit.execute_stage(bridge, settings, str(loom_plan), apply=True, dry_run=False)
        except ValueError as loom_exc:
            assert 'known_vectors' in str(loom_exc)
        else:
            raise AssertionError('missing vector configuration was accepted')
        assert not bridge.loom_writes
        settings.loom_verifier = {'known_vectors': [{'synthetic': True}]}
        with loom_contextlib.redirect_stdout(loom_io.StringIO()):
            byte_commit.execute_stage(bridge, settings, str(loom_plan), apply=True, dry_run=False)
        assert bridge.loom_writes == [(4096, bytes.fromhex('11223344'))]

def test_loom_run_reports_switch_exception_and_nonzero_exit():
    with loom_tempfile.TemporaryDirectory() as loom_td:
        settings, _ = loom_fixture(loom_td)

        def stage(label):
            if label == 'switch':

                def loom_fail(*options, **loom_kw):
                    raise RuntimeError('synthetic switch failure')
                return loom_SimpleNamespace(execute_stage=loom_fail)
            return loom_SimpleNamespace(execute_stage=lambda *options, **loom_kw: {})
        loom_output = loom_io.StringIO()
        with loom_patch.object(loom_run_command, 'loom_open_adapter', return_value=BranchLoomMemoryAdapter()), loom_patch.object(loom_run_command, 'loom_load_phase', side_effect=stage), loom_contextlib.redirect_stdout(loom_output):
            loom_code = console.launch(['run', '--config', str(settings), '--out', loom_td])
        loom_result = loom_json.loads(loom_output.getvalue())
        assert loom_code != 0
        assert loom_result['verdict'] == 'FAIL'
        assert 'switch' in loom_result['error']
