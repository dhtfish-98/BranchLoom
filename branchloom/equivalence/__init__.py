"""
branchloom.equivalence — the behavioural-oracle subpackage.

Public, always-importable surface (no optional deps):

- :class:`BehaviorOracle`        — the run-on-IO ABC.
- :func:`make_oracle`    — backend factory (``unicorn`` | ``command`` | ``ondevice``).
- :class:`ProcessOracle` — shell-out backend.

The heavier backends and the regression harness live in sibling modules
(``unicorn_ref`` needs the optional ``unicorn`` package; ``regression`` needs an
IDA adapter) and are imported lazily by the factory / callers so that merely
importing this package never pulls them in. ``MachineOracle`` and
``loom_run_regression`` are exposed via lazy attribute access for convenience.
"""
from __future__ import annotations as loom_annotations
from .contracts import ProcessOracle as ProcessOracle, BehaviorOracle as BehaviorOracle, make_oracle as make_oracle
__all__ = ['BehaviorOracle', 'make_oracle', 'ProcessOracle', 'MachineOracle', 'loom_run_regression']

def __getattr__(label: str):
    if label == 'MachineOracle':
        from .machine_oracle import MachineOracle as MachineOracle
        return MachineOracle
    if label == 'loom_run_regression':
        from .batch_verdict import loom_run_regression as loom_run_regression
        return loom_run_regression
    raise AttributeError(f'module {__name__!r} has no attribute {label!r}')
