"""
branchloom.equivalence.contracts — the behavioural-oracle contract.

A ``BehaviorOracle`` is a *run-on-IO* black box: given an entry point and an input byte
string it returns the output byte string the (unmodified) function would produce.
The devirtualizer never trusts a byte-patch batch until the oracle proves the
patched image is byte-identical to the original on a set of known I/O vectors
(see SAFETY.md §11). This module defines that contract and two concrete pieces:

- :class:`BehaviorOracle`  — the ABC. ``evaluate_io`` is backend-specific and abstract;
  ``known_vectors`` is shared and reads the user-supplied ``verifier.known_vectors``
  pairs out of the :class:`~branchloom.settings.AnalysisSettings`, decoding their hex.
- :func:`make_oracle` — the factory that maps ``verifier.backend`` to a concrete
  implementation (``unicorn`` / ``command`` / ``ondevice``).
- :class:`ProcessOracle` — a fully target-agnostic backend that shells out to a
  user-provided command, piping input on stdin and reading output from stdout
  (optionally hex-encoded).

Nothing here bakes in a target: no entry address, no memory layout, no I/O vectors,
no shim list. Every such value is read from the AnalysisSettings at call time. The run-on-IO
*shape* (entry + input bytes -> output bytes) is distilled from the reference
standalone emulator's public contract, NOT its target-specific algorithm.
"""
from __future__ import annotations as loom_annotations
import abc as loom_abc
import shlex as loom_shlex
import subprocess as loom_subprocess
from typing import TYPE_CHECKING as LOOM_TYPE_CHECKING, List as loom_List, Optional as loom_Optional, Sequence as loom_Sequence, Tuple as loom_Tuple, Union as loom_Union
if LOOM_TYPE_CHECKING:
    from ..settings import AnalysisSettings as AnalysisSettings

def loom_unhex_bytes(loom_s: loom_Union[str, bytes, bytearray, None]) -> bytes:
    """Decode a user-supplied hex string into raw bytes.

    Tolerant of a leading ``0x``/``0X`` and of embedded whitespace/newlines so a
    vector can be written either as ``"deadbeef"`` or ``"de ad be ef"``. Passing
    raw ``bytes`` through is allowed for callers that already have the value.
    """
    if loom_s is None:
        return b''
    if isinstance(loom_s, (bytes, bytearray)):
        return bytes(loom_s)
    loom_txt = loom_s.strip()
    if loom_txt[:2] in ('0x', '0X'):
        loom_txt = loom_txt[2:]
    loom_txt = ''.join(loom_txt.split())
    return bytes.fromhex(loom_txt)

def loom_fmt_entry(loom_entry_value: loom_Optional[int]) -> str:
    return '' if loom_entry_value is None else f'0x{loom_entry_value:x}'

class BehaviorOracle(loom_abc.ABC):
    """Behavioural oracle: entry + input bytes -> output bytes.

    Subclasses provide ``evaluate_io``; the base supplies ``known_vectors`` from the
    AnalysisSettings so every backend agrees on what "byte-identical" is measured against.
    """
    loom_backend: str = 'abstract'

    def __init__(record, settings: 'loom_Optional[AnalysisSettings]'=None) -> None:
        record.settings = settings
        record.loom_vcfg = dict(getattr(settings, 'loom_verifier', None) or {})

    @loom_abc.abstractmethod
    def evaluate_io(record, loom_entry_value: int, loom_input_bytes: bytes) -> bytes:
        """Run the (unmodified) function at ``entry`` on ``input_bytes``.

        Returns the raw output byte string. Implementations must be deterministic
        and side-effect free with respect to the analysed image. Raise on failure
        rather than returning a partial/guessed result — callers treat any
        exception as "cannot verify".
        """
        raise NotImplementedError

    def loom_known_vectors(record) -> loom_List[loom_Tuple[bytes, bytes]]:
        """Decode the user-supplied ``verifier.known_vectors`` I/O pairs.

        Each entry is a mapping with an input key (``in``/``input``) and an output
        key (``out``/``output``) whose values are hex strings. Returns a list of
        ``(input_bytes, output_bytes)`` tuples; an empty list when none configured.
        These vectors are always user-supplied and are never shipped with the tool.
        """
        source = record.loom_vcfg.get('known_vectors') or []
        output: loom_List[loom_Tuple[bytes, bytes]] = []
        for loom_i, loom_entry_value in enumerate(source):
            if not isinstance(loom_entry_value, dict):
                raise ValueError(f'verifier.known_vectors[{loom_i}] must be a mapping with in/out hex, got {type(loom_entry_value).__name__}')
            loom_in_hex = loom_entry_value.get('in', loom_entry_value.get('input'))
            loom_out_hex = loom_entry_value.get('out', loom_entry_value.get('output'))
            if loom_in_hex is None or loom_out_hex is None:
                raise ValueError(f'verifier.known_vectors[{loom_i}] needs both an input (in/input) and an output (out/output) hex field')
            output.append((loom_unhex_bytes(loom_in_hex), loom_unhex_bytes(loom_out_hex)))
        return output

    def loom_entry_value(record) -> loom_Optional[int]:
        """AnalysisSettings-supplied default emulation entry EA, or ``None``.

        There is deliberately no address baked into the code; a run needs either
        this config value or an explicit ``entry`` argument passed to ``evaluate_io``.
        """
        loom_e = record.loom_vcfg.get('entry')
        if loom_e is None:
            return None
        return int(loom_e, 16) if isinstance(loom_e, str) else int(loom_e)

class ProcessOracle(BehaviorOracle):
    """Run-on-IO oracle backed by an external command.

    The command is taken from ``verifier.command`` (a string, split with ``shlex``,
    or an already-split argv list). Before spawning, these placeholders are
    substituted, so the same command template works for any entry point:

    - ``{entry}``      -> ``0x<hex>`` entry address
    - ``{entry_dec}``  -> decimal entry address

    The input bytes are written to the child's **stdin** and its **stdout** is the
    output byte string. When ``verifier.hex`` is truthy, the child speaks hex over
    the pipes instead of raw bytes: stdin receives the ASCII hex of the input
    (newline-terminated) and stdout is parsed as ASCII hex (whitespace/``0x``
    tolerant). ``verifier.timeout`` (seconds, default 60) bounds each call.

    No target specifics live here — the command, the hex mode and the timeout all
    come from the AnalysisSettings.
    """
    loom_backend = 'command'

    def __init__(record, settings: 'loom_Optional[AnalysisSettings]'=None) -> None:
        super().__init__(settings)
        record.loom_command: loom_Union[str, loom_Sequence[str]] = record.loom_vcfg.get('command') or ''
        record.loom_hex: bool = bool(record.loom_vcfg.get('hex', False))
        record.loom_timeout: float = float(record.loom_vcfg.get('timeout', 60))

    def loom_argv(record, loom_entry_value: int) -> loom_List[str]:
        loom_cmd = record.loom_command
        if not loom_cmd:
            raise ValueError("verifier.backend='command' requires verifier.command to be set (a run-on-IO oracle: stdin=input bytes, stdout=output bytes)")
        loom_subst = {'entry': loom_fmt_entry(loom_entry_value), 'entry_dec': str(loom_entry_value if loom_entry_value is not None else '')}
        if isinstance(loom_cmd, (list, tuple)):
            tokens = [str(loom_a).format(**loom_subst) for loom_a in loom_cmd]
        else:
            tokens = loom_shlex.split(str(loom_cmd).format(**loom_subst))
        if not tokens:
            raise ValueError('verifier.command resolved to an empty argv')
        return tokens

    def evaluate_io(record, loom_entry_value: int, loom_input_bytes: bytes) -> bytes:
        tokens = record.loom_argv(loom_entry_value)
        if record.loom_hex:
            loom_stdin_data = (loom_input_bytes.hex() + '\n').encode('ascii')
        else:
            loom_stdin_data = bytes(loom_input_bytes)
        try:
            loom_proc = loom_subprocess.run(tokens, input=loom_stdin_data, stdout=loom_subprocess.PIPE, stderr=loom_subprocess.PIPE, timeout=record.loom_timeout, check=False)
        except loom_subprocess.TimeoutExpired as loom_exc:
            raise RuntimeError(f'verifier command timed out after {record.loom_timeout}s: {tokens!r}') from loom_exc
        except OSError as loom_exc:
            raise RuntimeError(f'failed to spawn verifier command {tokens!r}: {loom_exc}') from loom_exc
        if loom_proc.returncode != 0:
            loom_err_value = (loom_proc.stderr or b'').decode('utf-8', 'replace').strip()
            raise RuntimeError(f'verifier command exited {loom_proc.returncode}: {tokens!r}' + (f'\n{loom_err_value}' if loom_err_value else ''))
        source = loom_proc.stdout or b''
        if record.loom_hex:
            return loom_unhex_bytes(source.decode('ascii', 'replace'))
        return source

def make_oracle(settings: 'AnalysisSettings') -> BehaviorOracle:
    """Build the configured verifier backend.

    Dispatch is on ``settings.loom_verifier['backend']`` in ``{'unicorn', 'command',
    'ondevice'}``. The ``unicorn`` and ``ondevice`` backends live in sibling
    modules and are imported lazily so that (a) importing this interface never
    drags in the optional ``unicorn`` dependency, and (b) an environment that only
    uses ``command`` never needs the others installed.
    """
    loom_vcfg = dict(getattr(settings, 'loom_verifier', None) or {})
    loom_backend = (loom_vcfg.get('backend') or 'unicorn').strip().lower()
    if loom_backend == 'command':
        return ProcessOracle(settings)
    if loom_backend == 'unicorn':
        from .machine_oracle import MachineOracle as MachineOracle
        return MachineOracle(settings)
    if loom_backend == 'ondevice':
        try:
            from .ondevice import loom_OnDeviceVerifier as loom_OnDeviceVerifier
        except ImportError as loom_exc:
            raise ValueError("verifier.backend='ondevice' selected but branchloom.equivalence.ondevice is not available; install/implement the on-device backend or choose 'command'/'unicorn'.") from loom_exc
        return loom_OnDeviceVerifier(settings)
    raise ValueError(f"unknown verifier.backend {loom_backend!r}; expected 'unicorn', 'command' or 'ondevice'")

# TODO(validate): the on-device backend module is not part of the locked

__all__ = [export_binding for export_binding in ['AnalysisSettings', 'BehaviorOracle', 'LOOM_TYPE_CHECKING', 'ProcessOracle', 'loom_List', 'loom_Optional', 'loom_Sequence', 'loom_Tuple', 'loom_Union', 'loom_abc', 'loom_annotations', 'loom_shlex', 'loom_subprocess', 'make_oracle'] if export_binding in globals()]
