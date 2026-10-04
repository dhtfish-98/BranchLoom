"""Completion checks for the optional Unicorn verifier, using synthetic ARM64 code."""

import importlib.util as loom_importlib
import json as loom_json
import tempfile as loom_tempfile
from contextlib import contextmanager as loom_contextmanager
from pathlib import Path as LoomPath
from types import SimpleNamespace as LoomSettings

from branchloom.console.operations.evidence import loom_cmd_verify
from branchloom.equivalence.machine_oracle import MachineOracle


@loom_contextmanager
def loom_synthetic_case(loom_instruction: str):
    with loom_tempfile.TemporaryDirectory(prefix='branchloom-completion-') as loom_folder:
        loom_segments = LoomPath(loom_folder) / 'segments.json'
        loom_segments.write_text(
            loom_json.dumps([{'start': '0x1000', 'end': '0x1004', 'data': loom_instruction}]),
            encoding='utf-8',
        )
        yield LoomSettings(loom_verifier={
            'backend': 'unicorn',
            'segments': str(loom_segments),
            'entry': '0x1000',
            'max_insns': 16,
            'timeout_us': 100000,
            'memory_layout': {'ret_magic': '0x7fff0000'},
            'input': {'mode': 'scalar_x0'},
            'output': {'mode': 'retval', 'size': 1},
            'known_vectors': [{'in': '2a', 'out': '2a'}],
        })


# The dependency-free runner has no Unicorn by design. CI's regular test job
# installs the verifier extra and therefore collects both integration tests.
if loom_importlib.find_spec('unicorn') is not None:

    def test_loom_instruction_budget_exhaustion_is_not_completion():
        # AArch64 B-to-self leaves X0 unchanged; matching bytes cannot prove return.
        with loom_synthetic_case('00000014') as loom_settings:
            loom_oracle = MachineOracle(loom_settings)
            try:
                loom_oracle.evaluate_io(0x1000, b'\x2a')
            except RuntimeError as loom_exc:
                assert 'did not reach return sentinel' in str(loom_exc)
            else:
                raise AssertionError('nonreturning code was accepted as completed')
            loom_verdict = loom_cmd_verify(None, loom_settings)
            assert loom_verdict['ok'] is False
            assert loom_verdict['results'][0]['ok'] is False

    def test_loom_return_sentinel_allows_expected_output():
        # AArch64 RET reaches the configured LR sentinel and should still pass.
        with loom_synthetic_case('c0035fd6') as loom_settings:
            loom_oracle = MachineOracle(loom_settings)
            assert loom_oracle.evaluate_io(0x1000, b'\x2a') == b'\x2a'
            loom_verdict = loom_cmd_verify(None, loom_settings)
            assert loom_verdict['ok'] is True
            assert loom_verdict['results'][0]['ok'] is True
            # Cached emulator runs must not inherit the preceding completion.
            loom_oracle.loom_ensure_emu().mem_write(0x1000, bytes.fromhex('00000014'))
            try:
                loom_oracle.evaluate_io(0x1000, b'\x2a')
            except RuntimeError as loom_exc:
                assert 'did not reach return sentinel' in str(loom_exc)
            else:
                raise AssertionError('previous return made a later loop appear complete')
