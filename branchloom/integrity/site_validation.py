"""
branchloom.integrity.site_validation — per-site self-checks (IDA-free).

Ports the target-validity and branch-round-trip self-checks from
``_self_check_site`` / ``_self_check_patch_target`` / ``_self_check_encoded_branch``
in the reference ``misc/deobf/deobf_br_dispatch.py``, phrased against a
caller-supplied ``loom_is_exec`` predicate and the pure-Python decoders in
:mod:`branchloom.arm_words.recognition` so the layer carries no IDA dependency. See
``docs/SAFETY.md`` §9.
"""
from __future__ import annotations as loom_annotations
from typing import Callable as loom_Callable, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from ..arm_words import recognition as LOOM_D
LOOM__BADADDR = (4294967295, 18446744073709551615)

def loom_self_check_targets(loom_is_exec: loom_Callable[[int], bool], loom_targets: loom_List[loom_Optional[int]]) -> loom_Tuple[bool, loom_List[str]]:
    """Validate every resolved branch target per SAFETY.md §9.

    A target is accepted only if it is non-None, nonzero, not a BADADDR sentinel,
    non-negative, 4-byte aligned, and inside an executable segment as decided by
    the caller's ``loom_is_exec(ea) -> bool`` predicate. Duplicate targets are checked
    once. Returns ``(ok, errors)`` where ``ok`` is True iff ``errors`` is empty.

    (The ``idx in [0, 0xFFFF]`` clause of §9 is a table-index bound enforced by
    the resolver; this helper only receives targets, so it does not test idx —
    see the module's assumptions note.)
    """
    loom_errors: loom_List[str] = []
    loom_seen = set()
    for loom_i, destination in enumerate(loom_targets):
        loom_label = 'target[%d]' % loom_i
        if destination is None:
            loom_errors.append('%s is None' % loom_label)
            continue
        if destination in loom_seen:
            continue
        loom_seen.add(destination)
        if destination == 0:
            loom_errors.append('%s is null (0x0)' % loom_label)
            continue
        if destination in LOOM__BADADDR:
            loom_errors.append('%s is BADADDR (%#x)' % (loom_label, destination))
            continue
        if destination < 0:
            loom_errors.append('%s is negative (%d)' % (loom_label, destination))
            continue
        if destination & 3:
            loom_errors.append('%s not 4-byte aligned (%#x)' % (loom_label, destination))
            continue
        try:
            loom_executable = bool(loom_is_exec(destination))
        except Exception as loom_exc:
            loom_errors.append('%s is_exec raised: %r' % (loom_label, loom_exc))
            continue
        if not loom_executable:
            loom_errors.append('%s outside executable segment (%#x)' % (loom_label, destination))
    return (len(loom_errors) == 0, loom_errors)

def loom_tb_target(location: int, opcode: int) -> int:
    return location + LOOM_D.loom_sign_extend(LOOM_D.loom_bits(opcode, 18, 5) << 2, 16)

def loom_cb_target(location: int, opcode: int) -> int:
    return location + LOOM_D.loom_sign_extend(LOOM_D.loom_bits(opcode, 23, 5) << 2, 21)

def loom_verify_branch_roundtrip(location: int, opcode: int, loom_expected_target: int) -> bool:
    """Re-decode an emitted branch and confirm it lands on ``expected_target``.

    Given the freshly-encoded instruction ``word`` that will replace the bytes at
    ``pc``, decode it back and compare the reconstructed PC-relative target to the
    one the encoder was asked for. This catches an out-of-range/mis-encoded branch
    before it is ever written (SAFETY.md §9's "branch encoders range-check ...").

    Handles the ``B`` and ``B.loom_cond`` forms named in the contract; ``CBZ/CBNZ`` and
    ``TBZ/TBNZ`` are also supported for robustness. Any other word (i.e. the
    encoders did not produce a recognised branch) returns False.
    """
    opcode &= 4294967295
    if LOOM_D.loom_is_b(opcode):
        return LOOM_D.loom_b_target(location, opcode) == loom_expected_target
    if LOOM_D.loom_is_bcond(opcode):
        return LOOM_D.loom_bcond_target(location, opcode) == loom_expected_target
    if LOOM_D.loom_is_cbz_cbnz(opcode):
        return loom_cb_target(location, opcode) == loom_expected_target
    if LOOM_D.loom_is_tbz_tbnz(opcode):
        return loom_tb_target(location, opcode) == loom_expected_target
    return False

# TODO(validate): TBZ/TBNZ imm14 (bits[18:5]) target math is derived locally;
# TODO(validate): CBZ/CBNZ imm19 (bits[23:5]) target math is derived locally;

__all__ = [export_binding for export_binding in ['LOOM_D', 'loom_Callable', 'loom_List', 'loom_Optional', 'loom_Tuple', 'loom_annotations', 'loom_self_check_targets', 'loom_verify_branch_roundtrip'] if export_binding in globals()]
