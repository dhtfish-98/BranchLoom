"""
branchloom.integrity.image_restore — pristine-first byte restore (adapter-backed).

Ports ``restore_from_disk`` / ``full_revert`` from the reference
``misc/final/part2_trigger3/tools/revert_ida_patches.py``: diff the current
in-database dwords against the on-disk *input* bytes and patch every drifted
dword back, so each pass starts from the single source of truth (SAFETY.md §10,
"Pristine-first" and "revert reads pristine bytes straight from the on-disk
image, independent of any patch log").

Every IDA-touching primitive is reached through the Tier-1 ``adapter`` module
(``loom_read_input_bytes`` / ``loom_get_dword`` / ``loom_patch_bytes``), never idaapi directly,
so this module stays IDA-free at import time and testable with a fake adapter.
"""
from __future__ import annotations as loom_annotations

def loom_restore_range(bridge, loom_start: int, loom_end: int) -> int:
    """Restore ``[start, end)`` to pristine on-disk bytes by dword-diff; return count.

    Reads the pristine bytes for the range via ``bridge.loom_read_input_bytes`` (the
    on-disk input file, the single source of truth), then for every 4-byte word
    whose current database value differs, patches the pristine word back. Only the
    dwords that actually drifted are written, so a clean range costs zero patches
    and repeated calls are idempotent.

    ``start``/``end`` are rounded outward to whole 4-byte instruction boundaries.
    Returns the number of dwords restored.
    """
    loom_start &= ~3
    loom_end = loom_end + 3 & ~3
    loom_length = loom_end - loom_start
    if loom_length <= 0:
        return 0
    loom_orig = bridge.loom_read_input_bytes(loom_start, loom_length)
    if loom_orig is None or len(loom_orig) < loom_length:
        loom_got = 0 if loom_orig is None else len(loom_orig)
        raise ValueError('pristine read short: got %d of %d bytes at %#x' % (loom_got, loom_length, loom_start))
    loom_restored = 0
    address = loom_start
    cursor = 0
    while address < loom_end:
        loom_want = int.from_bytes(loom_orig[cursor:cursor + 4], 'little')
        if bridge.loom_get_dword(address) != loom_want:
            bridge.loom_patch_bytes(address, loom_orig[cursor:cursor + 4])
            loom_restored += 1
        address += 4
        cursor += 4
    return loom_restored

__all__ = [export_binding for export_binding in ['loom_annotations', 'loom_restore_range'] if export_binding in globals()]
