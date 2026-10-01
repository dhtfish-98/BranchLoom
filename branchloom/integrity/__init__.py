"""
branchloom.integrity — provable-safety gates for the devirtualizer.

Re-exports the three safety primitives that the phase modules gate every byte
rewrite behind (see ``docs/SAFETY.md``):

  * :func:`loom_a_path_hazard` (clobber_scan.py, IDA-free) — §4, never bypass an observable
    side effect on a collapsed COND2 A-path.
  * :func:`loom_self_check_targets` / :func:`loom_verify_branch_roundtrip`
    (site_validation.py, IDA-free) — §9, target-validity + branch round-trip.
  * :func:`loom_restore_range` (image_restore.py, adapter-backed) — §10, pristine-first
    dword-diff restore.

Importing this package does not import idaapi: ``hazard`` and ``selfcheck`` only
depend on :mod:`branchloom.arm_words.recognition`, and ``pristine`` reaches IDA solely
through the adapter object handed to :func:`loom_restore_range` at call time.
"""
from .clobber_scan import loom_a_path_hazard as loom_a_path_hazard
from .site_validation import loom_self_check_targets as loom_self_check_targets, loom_verify_branch_roundtrip as loom_verify_branch_roundtrip
from .image_restore import loom_restore_range as loom_restore_range
__all__ = ['loom_a_path_hazard', 'loom_self_check_targets', 'loom_verify_branch_roundtrip', 'loom_restore_range']
