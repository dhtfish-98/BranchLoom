"""
branchloom.target_sources.image_tables — pure-static two-level dispatch resolution.

Ported from the algorithm in
the private reference toolchain (``cff_resolve.py``)
(``_resolve_state`` + ``_target_valid``). A Family-A two-level dispatcher resolves
a concrete state value to a branch target in two table lookups::

    idx    = int32_le ( mem[idx_tbl_ea + (state << idx_scale)] )   # signed index
    target = uint64_le( mem[tgt_tbl_ea + (idx   *  entry_size)] )  # code pointer

The reference hard-coded ``state * 4`` (int32 index table) and ``idx * 8`` (uint64
target table). Here the scales are parameters so nothing target-specific is baked
in: ``idx_scale`` (``cff.idx_table_scale``, the ``LSL #k`` of the int32 index
table) and ``entry_size`` (``cff.entry_size``, the target-table entry width).

Relocation-aware reads
----------------------
On a raw, un-relocated ``.so`` the GOT/dispatch-table *entries are not relocated*
— reading them straight from the IDA database yields garbage pointers. When
``use_reloc`` is set and a relocation-applied image has been registered (via
:func:`loom_open_reloc` / :func:`loom_set_reloc_image`, honouring ``settings.loom_reloc_image``), the
two table reads are served from that image instead of from the database. When no
reloc image is registered, ``use_reloc`` reads the database directly — correct for
the deployment where IDA itself is opened on the reloc-applied dump. With
``use_reloc`` false the reads go straight to the database, matching the reference
byte-for-byte.

This module never imports IDA: the ``adapter`` is handed in at call time (same
convention as :mod:`branchloom.integrity.image_restore`).
"""
from __future__ import annotations as loom_annotations
from typing import Optional as loom_Optional, Tuple as loom_Tuple, TYPE_CHECKING as LOOM_TYPE_CHECKING
from ..arm_words import recognition as LOOM_D
if LOOM_TYPE_CHECKING:
    from ..settings import AnalysisSettings as AnalysisSettings
__all__ = ['loom_resolve_state', 'loom_target_valid', 'MappedImage', 'loom_open_reloc', 'loom_set_reloc_image', 'loom_clear_reloc_image']
LOOM__ALL_ONES = 18446744073709551615

class MappedImage:
    """A flat relocation-applied image used purely as a table-read source.

    The image is treated as a flat buffer whose byte offset for an effective
    address ``ea`` is ``ea - base_ea``. That covers the common ``dump_fix.bin``
    layout (a full memory capture of the module with relocations already applied
    in place). ``base_ea`` is the module load base under which those EAs were
    captured; it is a caller/config-supplied value, never hard-coded.

    TODO(validate): the ``ea - base_ea`` flat mapping assumes the reloc image
    shares one contiguous EA->file-offset region. A multi-segment image whose
    file layout differs from its virtual layout would need a per-segment
    translator; supply the pre-read bytes for the specific table span in that
    case, or open IDA directly on the reloc image and pass ``use_reloc`` with no
    registered image (the database path is then already relocated).
    """
    __slots__ = ('loom_data', 'loom_base')

    def __init__(record, content: bytes, loom_base_ea: int=0) -> None:
        record.loom_data = bytes(content)
        record.loom_base = int(loom_base_ea)

    def loom_slice(record, address: int, loom_n_value: int) -> loom_Optional[bytes]:
        cursor = address - record.loom_base
        if cursor < 0 or cursor + loom_n_value > len(record.loom_data):
            return None
        return record.loom_data[cursor:cursor + loom_n_value]

    def loom_dword(record, address: int) -> loom_Optional[int]:
        loom_b = record.loom_slice(address, 4)
        return None if loom_b is None else int.from_bytes(loom_b, 'little')

    def loom_qword(record, address: int) -> loom_Optional[int]:
        loom_b = record.loom_slice(address, 8)
        return None if loom_b is None else int.from_bytes(loom_b, 'little')
LOOM__RELOC: loom_Optional[MappedImage] = None

def loom_set_reloc_image(loom_reloc: loom_Optional[MappedImage]) -> None:
    """Register (or clear, with ``None``) the reloc image used for table reads."""
    global LOOM__RELOC
    LOOM__RELOC = loom_reloc

def loom_clear_reloc_image() -> None:
    """Drop any registered reloc image (subsequent reads fall back to the DB)."""
    global LOOM__RELOC
    LOOM__RELOC = None

def loom_open_reloc(settings: 'AnalysisSettings', loom_base_ea: int=0) -> loom_Optional[MappedImage]:
    """Load ``settings.loom_reloc_image`` into a :class:`MappedImage` and register it.

    Returns the registered image, or ``None`` when ``settings.loom_reloc_image`` is unset
    (in which case any previously-registered image is cleared and table reads
    fall back to the database). ``base_ea`` is the module load base under which
    the image was captured (default 0 == file-offset equals EA); it is
    caller-supplied so no target base is baked in.
    """
    location_path = getattr(settings, 'loom_reloc_image', None)
    if not location_path:
        loom_clear_reloc_image()
        return None
    with open(location_path, 'rb') as stream:
        content = stream.read()
    loom_reloc = MappedImage(content, loom_base_ea)
    loom_set_reloc_image(loom_reloc)
    return loom_reloc

def loom_read_dword(bridge, address: int, loom_use_reloc: bool) -> loom_Optional[int]:
    if loom_use_reloc and LOOM__RELOC is not None:
        loom_v = LOOM__RELOC.loom_dword(address)
        if loom_v is not None:
            return loom_v
    return bridge.loom_get_dword(address)

def loom_read_qword(bridge, address: int, loom_use_reloc: bool) -> loom_Optional[int]:
    if loom_use_reloc and LOOM__RELOC is not None:
        loom_v = LOOM__RELOC.loom_qword(address)
        if loom_v is not None:
            return loom_v
    return bridge.loom_get_qword(address)

def loom_target_valid(bridge, destination: loom_Optional[int]) -> bool:
    """True iff ``target`` is a plausible resolved branch destination.

    Faithful to the reference ``_target_valid`` plus the adapter's segment model:

      * non-zero,
      * not the 64-bit all-ones sentinel (BADADDR),
      * 4-byte aligned (every AArch64 instruction is word-aligned),
      * lands in an executable-permission segment (``bridge.loom_is_exec``).

    A ``None`` target (an unreadable table slot) is never valid.
    """
    if destination is None:
        return False
    if destination == 0 or destination == LOOM__ALL_ONES:
        return False
    if destination & 3:
        return False
    return bool(bridge.loom_is_exec(destination))

def loom_resolve_state(bridge, loom_idx_tbl_ea: int, loom_tgt_tbl_ea: int, loom_state: int, loom_entry_size: int, loom_idx_scale: int, loom_use_reloc: bool) -> loom_Tuple[loom_Optional[int], loom_Optional[int]]:
    """Resolve one concrete ``state`` to ``(idx, target)``.

    Returns ``(idx, target)`` on success. On failure the second element is
    ``None`` while ``idx`` is still returned when it could be read (so callers can
    log a plausible-but-out-of-range or invalid-target index), mirroring the
    reference's ``(idx, None)`` contract. Returns ``(None, None)`` only when even
    the index word could not be read or ``state`` is negative.

    Lookups::

        idx    = sign32( read32(idx_tbl_ea + (state << idx_scale)) )
        target =         read64(tgt_tbl_ea + (idx   *  entry_size))

    ``idx`` is rejected unless ``0 <= idx <= 0xFFFF`` (the reference's sanity
    window against a mis-identified table); ``target`` is rejected unless
    :func:`loom_target_valid`.
    """
    if loom_state < 0:
        return (None, None)
    loom_idx_off = loom_state << loom_idx_scale
    loom_idx_raw = loom_read_dword(bridge, loom_idx_tbl_ea + loom_idx_off, loom_use_reloc)
    if loom_idx_raw is None:
        return (None, None)
    loom_idx = LOOM_D.loom_sign_extend(loom_idx_raw & 4294967295, 32)
    if loom_idx < 0 or loom_idx > 65535:
        return (loom_idx, None)
    destination = loom_read_qword(bridge, loom_tgt_tbl_ea + loom_idx * loom_entry_size, loom_use_reloc)
    if not loom_target_valid(bridge, destination):
        return (loom_idx, None)
    return (loom_idx, destination)

# TODO(validate): the reference only ever fed non-negative CONST/COND2
