"""
branchloom.database.worker_process — the execute_sync(MFF_WRITE) bridge.

IDA's database is single-threaded: every read that must be coherent, and every
write, has to happen on IDA's main thread. Analysis is frequently kicked off
from a *worker* thread — the ida-pro-mcp server dispatches ``py_exec_file`` off
the UI thread, and long passes are run detached so IDA stays responsive. This
module marshals the heavy, DB-mutating work back onto the main thread via
``loom_ida_kernwin.execute_sync(..., MFF_WRITE)`` and drops the JSON result on disk
for a poller to pick up.

The pattern mirrors the proven ``regress_deobf.run(background=True)`` bridge:

    def delivery_pass():
        # runs on IDA's MAIN thread; may read+write the DB freely
        ...
        return {"verdict": "PASS", "patched": 12}

    from branchloom.database import worker_process
    worker_process.loom_run_in_background(delivery_pass, "/path/to/_result.json")
    # -> {"status": "started", "result_path": ".../_result.json"}
    # poll result_path until it exists; it holds delivery_pass()'s return dict plus
    # started_at / finished_at (and error/traceback on failure).

``ida_kernwin`` is imported lazily inside the call so that simply importing this
module never requires a live IDA.
"""
from __future__ import annotations as loom_annotations
import json as loom_json
import os as loom_os
import threading as loom_threading
import time as loom_time
from typing import Any as loom_Any, Callable as loom_Callable, Dict as loom_Dict

def loom_write_result(location_path: str, output: loom_Dict[str, loom_Any]) -> None:
    """Serialize ``out`` to ``path`` (``default=str`` tolerates odd values)."""
    loom_os.makedirs(loom_os.path.dirname(location_path) or '.', exist_ok=True)
    with open(location_path, 'w', encoding='utf-8') as stream:
        loom_json.dump(output, stream, indent=2, default=str)

def loom_merge(loom_container: loom_Dict[str, loom_Any], loom_res: loom_Any) -> None:
    """Fold a callback's return value into the result container."""
    if isinstance(loom_res, dict):
        loom_container.update(loom_res)
    elif loom_res is not None:
        loom_container['result'] = loom_res

def loom_run_in_background(loom_fn: loom_Callable[[], loom_Any], loom_result_path: str, loom_block: bool=False) -> loom_Dict[str, loom_Any]:
    """Run ``fn`` on IDA's main thread and persist its result to ``result_path``.

    ``fn`` takes no arguments and should return a JSON-serializable dict (its
    keys are merged into the written result; a non-dict lands under ``result``).
    Any exception is captured into ``error`` / ``traceback`` rather than killing
    the worker thread.

    Parameters
    ----------
    loom_fn : callable
        The DB-touching pass. Executed inside ``execute_sync(MFF_WRITE)`` so it
        always runs on IDA's main thread with exclusive write access.
    loom_result_path : str
        Where the JSON result is written when ``fn`` completes.
    loom_block : bool, default False
        When False (the default) the sync work is dispatched on a daemon thread
        and this returns immediately with ``{"status": "started",
        "result_path": ...}``; poll ``result_path`` for completion. When True,
        the work is driven inline and the fully populated result dict is
        returned (and also written to ``result_path``).

    Returns
    -------
    dict
        The "started" handle (non-blocking) or the completed result (blocking).
    """
    import ida_kernwin as loom_ida_kernwin
    try:
        if loom_os.path.exists(loom_result_path):
            loom_os.remove(loom_result_path)
    except OSError:
        pass

    def loom_run_sync() -> loom_Dict[str, loom_Any]:
        output: loom_Dict[str, loom_Any] = {'started_at': loom_time.time()}
        loom_container: loom_Dict[str, loom_Any] = {}

        def loom_sync():
            try:
                loom_merge(loom_container, loom_fn())
            except Exception as loom_exc:
                import traceback as loom_traceback
                loom_container['error'] = repr(loom_exc)
                loom_container['traceback'] = loom_traceback.format_exc()
            return 1
        loom_ida_kernwin.execute_sync(loom_sync, loom_ida_kernwin.MFF_WRITE)
        output.update(loom_container)
        output['finished_at'] = loom_time.time()
        loom_write_result(loom_result_path, output)
        return output
    if loom_block:
        return loom_run_sync()
    loom_threading.Thread(target=loom_run_sync, daemon=True).start()
    return {'status': 'started', 'result_path': loom_result_path}

__all__ = [export_binding for export_binding in ['loom_Any', 'loom_Callable', 'loom_Dict', 'loom_annotations', 'loom_json', 'loom_os', 'loom_run_in_background', 'loom_threading', 'loom_time'] if export_binding in globals()]
