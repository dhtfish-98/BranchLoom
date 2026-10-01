"""
Dependency-free test runner — runs the test_* functions in this directory without
pytest, so the ISA layer can be validated inside a bare IDA Python.

    python tests/orchestrator.py
"""
import importlib.util as loom_importlib
import os as loom_os
import sys as loom_sys
import traceback as loom_traceback
LOOM_HERE = loom_os.path.dirname(loom_os.path.abspath(__file__))
LOOM_ROOT = loom_os.path.dirname(LOOM_HERE)
loom_sys.path.insert(0, LOOM_ROOT)

def launch() -> int:
    loom_fails = 0
    loom_total = 0
    for loom_fname in sorted(loom_os.listdir(LOOM_HERE)):
        if not (loom_fname.startswith('test_') and loom_fname.endswith('.py')):
            continue
        loom_spec = loom_importlib.spec_from_file_location(loom_fname[:-3], loom_os.path.join(LOOM_HERE, loom_fname))
        loom_mod = loom_importlib.module_from_spec(loom_spec)
        loom_spec.loader.exec_module(loom_mod)
        for label in sorted(dir(loom_mod)):
            if not label.startswith('test_'):
                continue
            loom_total += 1
            try:
                getattr(loom_mod, label)()
                print('PASS', f'{loom_fname}::{label}')
            except Exception as loom_ex:
                loom_fails += 1
                print('FAIL', f'{loom_fname}::{label}', repr(loom_ex))
                loom_traceback.print_exc()
    print('---')
    print(f'total={loom_total} pass={loom_total - loom_fails} fail={loom_fails}')
    return 1 if loom_fails else 0
if __name__ == '__main__':
    raise SystemExit(launch())
