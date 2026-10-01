"""
branchloom.database.bridge — the single, thin IDA boundary.

This is the **only** module in the package that imports ``idaapi`` / ``ida_*``.
Every other layer (arm_words/, integrity/, target_sources/, dispatch_shapes/, pipeline/, equivalence/) is
IDA-free and reaches the database exclusively through the free functions
defined here. Keeping the surface tiny and stateless makes the rest of the
tool unit-testable off-device and keeps target-specific knowledge out of the
adapter entirely — segment selection comes from the AnalysisSettings, never from a
hardcoded name like ``.text``.

All functions operate on linear effective addresses (EAs). Instruction words
are read as 4-byte little-endian dwords (the AArch64 target is little-endian).

py_compile note: importing idaapi at module load is expected — these wrappers
only ever run inside a live IDA. ``py_compile`` does not execute imports, so
byte-compiling this file off-device is fine.
"""
from __future__ import annotations as loom_annotations
from typing import List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
import idaapi as loom_idaapi
import idautils as loom_idautils
import ida_auto as loom_ida_auto
import ida_bytes as loom_ida_bytes
import ida_funcs as loom_ida_funcs
import ida_name as loom_ida_name
import ida_nalt as loom_ida_nalt
import ida_segment as loom_ida_segment
import ida_ua as loom_ida_ua
import ida_xref as loom_ida_xref

def loom_get_byte(address: int) -> int:
    """Single byte at ``ea`` (as stored in the DB)."""
    return loom_ida_bytes.get_byte(address)

def loom_get_dword(address: int) -> int:
    """4-byte little-endian value at ``ea`` — i.e. one AArch64 instruction word."""
    return loom_ida_bytes.get_dword(address)

def loom_get_qword(address: int) -> int:
    """8-byte little-endian value at ``ea`` (used for table-entry pointers)."""
    return loom_ida_bytes.get_qword(address)

def loom_get_bytes(address: int, loom_n_value: int) -> bytes:
    """``n`` raw bytes starting at ``ea`` from the DB. Returns b'' if unmapped."""
    return loom_ida_bytes.get_bytes(address, loom_n_value) or b''

def loom_patch_bytes(address: int, content: bytes) -> None:
    """Write ``data`` at ``ea`` and record it in IDA's reversible patch table.

    Callers are responsible for the strict-orig / already-patched checks; this
    is a dumb writer so the higher layers own the policy (see integrity/pristine).
    """
    loom_ida_bytes.patch_bytes(address, bytes(content))
LOOM__INPUT_BLOB: loom_Optional[bytes] = None

def loom_input_file_blob() -> bytes:
    """Lazily load + cache the full on-disk input file IDA was opened on.

    Cached because pristine-restore diffs whole exec ranges dword-by-dword; a
    per-call open() would be pathologically slow. The file is the image IDA
    recorded at load time (``get_input_file_path``), i.e. the untouched
    original — DB patches never propagate back to it.
    """
    global LOOM__INPUT_BLOB
    if LOOM__INPUT_BLOB is None:
        location_path = loom_ida_nalt.get_input_file_path()
        with open(location_path, 'rb') as stream:
            LOOM__INPUT_BLOB = stream.read()
    return LOOM__INPUT_BLOB

def loom_read_input_bytes(address: int, loom_n_value: int) -> bytes:
    """Pristine ``n`` bytes for ``ea`` read from the on-disk input file.

    The EA is translated to a file offset via ``get_fileregion_offset`` so this
    works for any loaded segment (never assumes file-offset == vaddr). Returns
    b'' when ``ea`` has no backing bytes in the file (e.g. .bss).
    """
    loom_fo = loom_idaapi.get_fileregion_offset(address)
    if loom_fo is None or loom_fo < 0 or loom_fo == loom_idaapi.BADADDR:
        return b''
    loom_blob = loom_input_file_blob()
    return bytes(loom_blob[loom_fo:loom_fo + loom_n_value])

def loom_xrefs_to_code(address: int) -> loom_List[int]:
    """Source EAs of every *code* xref pointing at ``ea`` (deduped, sorted).

    Only code references (calls/jumps: fl_CN/fl_CF/fl_JN/fl_JF) are returned;
    data references (function-pointer tables etc.) are excluded — those are the
    caller's concern via ``loom_get_qword`` on the resolved table.
    """
    loom_srcs = set()
    for loom_x in loom_idautils.XrefsTo(address, 0):
        if loom_x.iscode:
            loom_srcs.add(loom_x.frm)
    return sorted(loom_srcs)

def loom_add_jump_xref(loom_src: int, loom_dst: int) -> None:
    """Add a synthetic ordinary (near) code-jump xref ``src`` -> ``dst``.

    Used to teach IDA an edge it cannot recover statically (e.g. a resolved
    indirect branch that is being kept, not rewritten). AArch64 branches stay
    inside the same segment, so a *near* jump (fl_JN) is the right kind.
    """
    loom_ida_xref.add_cref(loom_src, loom_dst, loom_ida_xref.fl_JN)

def loom_del_jump_xref(loom_src: int, loom_dst: int) -> None:
    """Remove a code-jump xref ``src`` -> ``dst`` without touching the target.

    ``expand=0`` keeps IDA from undefining ``dst`` if this was its last
    reference — we only want to drop the edge, not the code.
    """
    loom_ida_xref.del_cref(loom_src, loom_dst, 0)

def loom_func_at(address: int) -> loom_Optional[loom_Tuple[int, str]]:
    """``(func_start_ea, name)`` for the function containing ``ea``, or None."""
    loom_f = loom_ida_funcs.get_func(address)
    if loom_f is None:
        return None
    label = loom_ida_funcs.get_func_name(loom_f.start_ea) or ''
    return (loom_f.start_ea, label)

def loom_reanalyze(loom_fn_start: int) -> None:
    """Re-run IDA's analysis over the function starting at ``fn_start``.

    Call after patching branch edges so the recovered control-flow graph
    reflects the new B / B.cond instructions. Pair with ``loom_auto_wait``.
    """
    loom_f = loom_ida_funcs.get_func(loom_fn_start)
    if loom_f is not None:
        loom_ida_funcs.reanalyze_function(loom_f)

def loom_auto_wait() -> None:
    """Block until IDA's auto-analysis queue drains."""
    loom_ida_auto.auto_wait()

def loom_name_at(address: int) -> str:
    """The (possibly empty) symbol name at ``ea``."""
    return loom_ida_name.get_name(address) or ''

def loom_exec_perm_segments() -> loom_List[loom_Tuple[int, int, str]]:
    """All executable-permission segments as ``(start, end, name)`` tuples."""
    output: loom_List[loom_Tuple[int, int, str]] = []
    for loom_seg_ea in loom_idautils.Segments():
        loom_seg = loom_ida_segment.getseg(loom_seg_ea)
        if loom_seg is None:
            continue
        if not loom_seg.perm & loom_ida_segment.SEGPERM_EXEC:
            continue
        output.append((loom_seg.start_ea, loom_seg.end_ea, loom_ida_segment.get_segm_name(loom_seg)))
    return output

def loom_exec_segments(settings) -> loom_List[loom_Tuple[int, int, str]]:
    """Resolve ``settings.loom_exec_segments`` to concrete ``(start, end, name)`` ranges.

    Each config selector is either a segment ``name`` or an explicit
    ``[start, end)`` range. Both are intersected with the set of
    executable-permission segments so a selector can never widen coverage into
    non-code (a named non-exec segment is dropped; a range is clipped to the
    exec segments it overlaps). This is the only place segment selection
    happens — '.text' is never assumed.
    """
    loom_perm_segs = loom_exec_perm_segments()
    loom_resolved: loom_List[loom_Tuple[int, int, str]] = []
    for loom_spec in settings.loom_exec_segments:
        if loom_spec.label is not None:
            for loom_s, loom_e, loom_nm_value in loom_perm_segs:
                if loom_nm_value == loom_spec.label:
                    loom_resolved.append((loom_s, loom_e, loom_nm_value))
        if loom_spec.loom_range is not None:
            loom_a, loom_b = (int(loom_spec.loom_range[0]), int(loom_spec.loom_range[1]))
            for loom_s, loom_e, loom_nm_value in loom_perm_segs:
                loom_lo, loom_hi = (max(loom_a, loom_s), min(loom_b, loom_e))
                if loom_lo < loom_hi:
                    loom_resolved.append((loom_lo, loom_hi, loom_nm_value))
    loom_seen = set()
    loom_uniq: loom_List[loom_Tuple[int, int, str]] = []
    for loom_r in loom_resolved:
        if loom_r not in loom_seen:
            loom_seen.add(loom_r)
            loom_uniq.append(loom_r)
    return loom_uniq

def loom_is_exec(address: int) -> bool:
    """True iff ``ea`` lies in an executable-permission segment."""
    loom_seg = loom_ida_segment.getseg(address)
    return loom_seg is not None and bool(loom_seg.perm & loom_ida_segment.SEGPERM_EXEC)

def loom_make_code(address: int) -> None:
    """Force a 4-byte AArch64 instruction to exist at ``ea``.

    Any stale item covering ``ea`` is undefined first so ``create_insn`` is not
    blocked by leftover data. Used after folding trap sequences / NOP-ing DCB
    so the disassembly re-flows as code.
    """
    loom_ida_bytes.del_items(address, loom_ida_bytes.DELIT_SIMPLE, 4)
    loom_ida_ua.create_insn(address)

def loom_clear_switch_info(address: int) -> None:
    """Drop any jump-table (switch) metadata IDA attached to the branch at ``ea``.

    Needed before a resolved indirect branch is rewritten, otherwise IDA keeps
    rendering the stale N-way switch it inferred from the dispatch table.
    """
    if hasattr(loom_ida_nalt, 'del_switch_info'):
        loom_ida_nalt.del_switch_info(address)
    elif hasattr(loom_ida_nalt, 'del_switch_info_ex'):
        loom_ida_nalt.del_switch_info_ex(address)

# TODO(validate): the sole proven reference (fix_eh_landing_pads.py) used

__all__ = [export_binding for export_binding in ['loom_List', 'loom_Optional', 'loom_Tuple', 'loom_add_jump_xref', 'loom_annotations', 'loom_auto_wait', 'loom_clear_switch_info', 'loom_del_jump_xref', 'loom_exec_segments', 'loom_func_at', 'loom_get_byte', 'loom_get_bytes', 'loom_get_dword', 'loom_get_qword', 'loom_ida_auto', 'loom_ida_bytes', 'loom_ida_funcs', 'loom_ida_nalt', 'loom_ida_name', 'loom_ida_segment', 'loom_ida_ua', 'loom_ida_xref', 'loom_idaapi', 'loom_idautils', 'loom_is_exec', 'loom_make_code', 'loom_name_at', 'loom_patch_bytes', 'loom_read_input_bytes', 'loom_reanalyze', 'loom_xrefs_to_code'] if export_binding in globals()]
