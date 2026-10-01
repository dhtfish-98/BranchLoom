"""
branchloom.equivalence.machine_oracle — the reference (Unicorn) behavioural oracle.

This backend implements :meth:`BehaviorOracle.evaluate_io` by emulating the (unmodified)
function at ``entry`` on a raw input byte string and reading back the output byte
string. It is a **faithful port of the algorithm** in the private reference harness
``misc/final/part3_trigger4/tools/emu_part3_standalone.py`` (map/merge segments, map
stack/heap/TLS/IO/trap regions, a RET sentinel, SP/TPIDR/canary/LR/X0 setup, and a
per-instruction IAT-shim hook including an AArch64-PCS ``va_list`` walker for the
``__vsprintf_chk`` / ``__vsnprintf_chk`` family) with **every target specific value
stripped out**:

- All memory-layout constants (stack/heap/TLS/IO/trap bases + sizes, the RET magic,
  the stack canary and its TLS offset) come from ``settings.loom_verifier['memory_layout']``.
- The IAT (``name -> address`` map of imported-libc stubs) comes from
  ``settings.loom_verifier['iat']`` (an inline mapping or a path to a JSON one).
- The set of enabled libc **shims** comes from ``settings.loom_verifier['shims']`` and is
  resolved against an **extensible registry** (:data:`SHIM_MODELS`) that anyone can
  add to via :func:`loom_register_shim` / :meth:`MachineOracle.loom_register_shim`.
- The image bytes come from ``settings.loom_image`` / ``settings.loom_reloc_image`` (ELF), or an explicit
  ``verifier['segments']`` dump — never a baked-in path.
- The entry address comes from the ``evaluate_io`` argument (or ``verifier['entry']``).
- The input placement and output extraction are config-driven (``verifier['input']`` /
  ``verifier['output']``) so the run-on-IO shape is not hard-coded to one target.

``import unicorn`` is done **lazily inside methods** so that merely importing this
module (or the ``branchloom.equivalence`` package) never requires the optional dependency.
"""
from __future__ import annotations as loom_annotations
import json as loom_json
import os as loom_os
import struct as loom_struct
from typing import Callable as loom_Callable, Dict as loom_Dict, List as loom_List, Optional as loom_Optional, Tuple as loom_Tuple
from .contracts import BehaviorOracle as BehaviorOracle
LOOM__M64 = 18446744073709551615

def loom_as_int(loom_v, loom_default=None):
    """Accept an int, a hex/decimal string, or None (-> default)."""
    if loom_v is None:
        return loom_default
    if isinstance(loom_v, bool):
        return int(loom_v)
    if isinstance(loom_v, int):
        return loom_v
    if isinstance(loom_v, str):
        loom_s = loom_v.strip()
        if not loom_s:
            return loom_default
        return int(loom_s, 0)
    return int(loom_v)
LOOM_SHIM_MODELS: loom_Dict[str, loom_Callable[['MachineOracle', object], None]] = {}

def loom_register_shim(label: str, records: loom_Callable[['MachineOracle', object], None]) -> None:
    """Register (or override) the libc model bound to IAT symbol ``name``."""
    LOOM_SHIM_MODELS[label] = records

def loom_shim(label: str):
    """Decorator form of :func:`loom_register_shim`."""

    def loom_deco(loom_fn):
        LOOM_SHIM_MODELS[label] = loom_fn
        return loom_fn
    return loom_deco

def loom_m_ret0(loom_vrf, loom_uc_value):
    """A no-op that returns 0 (e.g. pthread_mutex_lock/unlock)."""
    loom_vrf.loom_wx(loom_uc_value, 0, 0)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_memcpy(loom_vrf, loom_uc_value):
    """memcpy / __memcpy_chk / memmove: X0=dst, X1=src, X2=n. Returns dst."""
    loom_dst = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_src = loom_vrf.loom_rx(loom_uc_value, 1)
    loom_n_value = loom_vrf.loom_rx(loom_uc_value, 2) & 4294967295
    try:
        loom_uc_value.mem_write(loom_dst, bytes(loom_uc_value.mem_read(loom_src, loom_n_value)))
    except Exception:
        pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_dst)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_memset(loom_vrf, loom_uc_value):
    """memset / __memset_chk: X0=dst, X1=byte, X2=n. Returns dst."""
    loom_dst = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_val = loom_vrf.loom_rx(loom_uc_value, 1) & 255
    loom_n_value = loom_vrf.loom_rx(loom_uc_value, 2) & 4294967295
    try:
        loom_uc_value.mem_write(loom_dst, bytes([loom_val]) * loom_n_value)
    except Exception:
        pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_dst)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_strlen(loom_vrf, loom_uc_value):
    loom_p = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_n_value = 0
    try:
        for loom_k in range(1 << 20):
            if loom_uc_value.mem_read(loom_p + loom_k, 1)[0] == 0:
                break
            loom_n_value += 1
    except Exception:
        pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_n_value)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_malloc(loom_vrf, loom_uc_value):
    loom_n_value = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_vrf.loom_wx(loom_uc_value, 0, loom_vrf.loom_alloc(loom_n_value))
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_calloc(loom_vrf, loom_uc_value):
    loom_nmemb = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_sz = loom_vrf.loom_rx(loom_uc_value, 1)
    loom_n_value = loom_nmemb * loom_sz
    loom_p = loom_vrf.loom_alloc(loom_n_value)
    try:
        loom_uc_value.mem_write(loom_p, b'\x00' * loom_n_value)
    except Exception:
        pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_p)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_realloc(loom_vrf, loom_uc_value):
    loom_old = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_n_value = loom_vrf.loom_rx(loom_uc_value, 1)
    loom_p = loom_vrf.loom_alloc(loom_n_value)
    if loom_old:
        try:
            loom_uc_value.mem_write(loom_p, bytes(loom_uc_value.mem_read(loom_old, loom_n_value)))
        except Exception:
            pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_p)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_free(loom_vrf, loom_uc_value):
    loom_vrf.loom_wx(loom_uc_value, 0, 0)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_strcmp(loom_vrf, loom_uc_value):
    loom_p1 = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_p2 = loom_vrf.loom_rx(loom_uc_value, 1)
    loom_r = 0
    try:
        for loom_k in range(1 << 20):
            loom_a = loom_uc_value.mem_read(loom_p1 + loom_k, 1)[0]
            loom_b = loom_uc_value.mem_read(loom_p2 + loom_k, 1)[0]
            if loom_a != loom_b:
                loom_r = loom_a - loom_b
                break
            if loom_a == 0:
                break
    except Exception:
        pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_r & LOOM__M64)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_strncmp(loom_vrf, loom_uc_value):
    loom_p1 = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_p2 = loom_vrf.loom_rx(loom_uc_value, 1)
    loom_n_value = loom_vrf.loom_rx(loom_uc_value, 2) & 4294967295
    loom_r = 0
    try:
        for loom_k in range(loom_n_value):
            loom_a = loom_uc_value.mem_read(loom_p1 + loom_k, 1)[0]
            loom_b = loom_uc_value.mem_read(loom_p2 + loom_k, 1)[0]
            if loom_a != loom_b:
                loom_r = loom_a - loom_b
                break
            if loom_a == 0:
                break
    except Exception:
        pass
    loom_vrf.loom_wx(loom_uc_value, 0, loom_r & LOOM__M64)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_vsprintf_chk(loom_vrf, loom_uc_value):
    """__vsprintf_chk(dest, flag, dstlen, fmt, va_list): dst=X0, fmt=X3, va=X4."""
    loom_dst = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_fmt = loom_vrf.loom_rx(loom_uc_value, 3)
    loom_va = loom_vrf.loom_rx(loom_uc_value, 4)
    loom_vrf.loom_vformat(loom_uc_value, loom_dst, loom_fmt, loom_va)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_vsnprintf_chk(loom_vrf, loom_uc_value):
    """__vsnprintf_chk(dest, maxlen, flag, slen, fmt, va_list): dst=X0, fmt=X4, va=X5."""
    loom_dst = loom_vrf.loom_rx(loom_uc_value, 0)
    loom_fmt = loom_vrf.loom_rx(loom_uc_value, 4)
    loom_va = loom_vrf.loom_rx(loom_uc_value, 5)
    loom_vrf.loom_vformat(loom_uc_value, loom_dst, loom_fmt, loom_va)
    loom_vrf.loom_ret(loom_uc_value)

def loom_m_abort(loom_vrf, loom_uc_value):
    loom_vrf.loom_stop(loom_uc_value, 'abort() called')

def loom_m_stack_chk_fail(loom_vrf, loom_uc_value):
    loom_vrf.loom_stop(loom_uc_value, '__stack_chk_fail (stack canary mismatch)')
for loom_n in ('pthread_mutex_lock', 'pthread_mutex_unlock'):
    loom_register_shim(loom_n, loom_m_ret0)
for loom_n in ('memcpy', '__memcpy_chk', 'memmove', '__memmove_chk'):
    loom_register_shim(loom_n, loom_m_memcpy)
for loom_n in ('memset', '__memset_chk'):
    loom_register_shim(loom_n, loom_m_memset)
loom_register_shim('strlen', loom_m_strlen)
loom_register_shim('malloc', loom_m_malloc)
loom_register_shim('calloc', loom_m_calloc)
loom_register_shim('realloc', loom_m_realloc)
loom_register_shim('free', loom_m_free)
loom_register_shim('strcmp', loom_m_strcmp)
loom_register_shim('strncmp', loom_m_strncmp)
loom_register_shim('__vsprintf_chk', loom_m_vsprintf_chk)
loom_register_shim('__vsnprintf_chk', loom_m_vsnprintf_chk)
loom_register_shim('abort', loom_m_abort)
loom_register_shim('__stack_chk_fail', loom_m_stack_chk_fail)

class MachineOracle(BehaviorOracle):
    """Reference run-on-IO oracle backed by the Unicorn CPU emulator.

    Construction reads only *config* (no ``import unicorn`` at build time). The
    emulator is built lazily on the first ``evaluate_io`` call and cached; each run
    resets the volatile regions (stack/IO/TLS + heap bump pointer) so calls are
    independent.
    """
    loom_backend = 'unicorn'

    def __init__(record, settings=None) -> None:
        super().__init__(settings)
        loom_ml = dict(record.loom_vcfg.get('memory_layout') or {})
        record.loom_page = loom_as_int(loom_ml.get('page_size'), 4096)
        record.loom_stack_base = loom_as_int(loom_ml.get('stack_base'), 17179869184)
        record.loom_stack_size = loom_as_int(loom_ml.get('stack_size'), 2097152)
        record.loom_io_base = loom_as_int(loom_ml.get('io_base'), 21474836480)
        record.loom_io_size = loom_as_int(loom_ml.get('io_size'), 2097152)
        record.loom_input_ptr = loom_as_int(loom_ml.get('input_ptr'), record.loom_io_base + 256)
        record.loom_heap_base = loom_as_int(loom_ml.get('heap_base'), 25769803776)
        record.loom_heap_size = loom_as_int(loom_ml.get('heap_size'), 16777216)
        record.loom_tls_base = loom_as_int(loom_ml.get('tls_base'), 30064771072)
        record.loom_tls_size = loom_as_int(loom_ml.get('tls_size'), 65536)
        record.loom_ret_magic = loom_as_int(loom_ml.get('ret_magic'), 244837814094590)
        record.loom_canary = loom_as_int(loom_ml.get('canary'), 14627333965257922168)
        record.loom_canary_off = loom_as_int(loom_ml.get('canary_off'), 40)
        record.loom_sp_offset = loom_as_int(loom_ml.get('sp_offset'), 16384)
        record.loom_iat: loom_Dict[str, int] = record.loom_load_iat()
        record.loom_iat_by_addr: loom_Dict[int, str] = {loom_a: loom_n_value for loom_n_value, loom_a in record.loom_iat.items()}
        record.loom_iat_pages = {loom_a & ~(record.loom_page - 1) for loom_a in record.loom_iat.values()}
        loom_shims_cfg = record.loom_vcfg.get('shims')
        record.loom_enabled_shims: loom_Optional[set] = None if loom_shims_cfg is None else set(loom_shims_cfg)
        record.loom_max_insns = int(record.loom_vcfg.get('max_insns', 200000000))
        record.loom_timeout = int(record.loom_vcfg.get('timeout_us', 0))
        record.loom_input_spec = dict(record.loom_vcfg.get('input') or {})
        record.loom_output_spec = dict(record.loom_vcfg.get('output') or {})
        record.loom_uc = None
        record.LOOM__RX: loom_Optional[loom_List[int]] = None
        record.LOOM__LR = None
        record.LOOM__PC = None
        record.LOOM__SP = None
        record.LOOM__TPIDR = None
        record.loom_heap_ptr = record.loom_heap_base
        record.loom_stop_reason: loom_Optional[str] = None

    @classmethod
    def loom_register_shim(record_type, label: str, records) -> None:
        """Add/override a libc model in the shared registry (see module docs)."""
        loom_register_shim(label, records)

    def loom_load_iat(record) -> loom_Dict[str, int]:
        source = record.loom_vcfg.get('iat')
        if source is None:
            return {}
        if isinstance(source, dict):
            return {loom_k: loom_as_int(loom_v) for loom_k, loom_v in source.items()}
        if isinstance(source, str):
            if not loom_os.path.exists(source):
                raise RuntimeError(f'verifier.iat path not found: {source}')
            with open(source, 'r', encoding='utf-8') as stream:
                loom_d_value = loom_json.load(stream)
            return {loom_k: loom_as_int(loom_v) for loom_k, loom_v in loom_d_value.items()}
        raise RuntimeError('verifier.iat must be a name->address mapping or a path to a JSON one')

    def loom_shim_enabled(record, label: str) -> bool:
        if label not in LOOM_SHIM_MODELS:
            return False
        if record.loom_enabled_shims is None:
            return True
        return label in record.loom_enabled_shims

    def loom_pdown(record, loom_x: int) -> int:
        return loom_x & ~(record.loom_page - 1)

    def loom_pup(record, loom_x: int) -> int:
        return loom_x + record.loom_page - 1 & ~(record.loom_page - 1)

    def loom_load_segments(record) -> loom_List[loom_Tuple[int, int, bytes]]:
        """Return the image as a list of ``(start_vaddr, end_vaddr, file_data)``.

        Source priority: an explicit ``verifier.segments`` dump (pickle/json/ELF by
        extension), else the top-level ``reloc_image`` (relocation-applied — correct
        for GOT/table reads) or ``image`` parsed as an ELF.
        """
        loom_seg = record.loom_vcfg.get('segments')
        if loom_seg:
            loom_s = str(loom_seg).lower()
            if loom_s.endswith(('.pkl', '.pickle')):
                return record.loom_load_pickle_segments(loom_seg)
            if loom_s.endswith('.json'):
                return record.loom_load_json_segments(loom_seg)
            return record.loom_load_elf_segments(loom_seg)
        loom_img = record.loom_vcfg.get('reloc_image') or record.loom_vcfg.get('image')
        if loom_img is None and record.settings is not None:
            loom_img = getattr(record.settings, 'loom_reloc_image', None) or getattr(record.settings, 'loom_image', None)
        if loom_img:
            return record.loom_load_elf_segments(loom_img)
        raise RuntimeError('verifier needs a segment source: set verifier.segments (a pickle/json segment dump) or image/reloc_image (an ELF) in the config')

    @staticmethod
    def loom_load_pickle_segments(location_path: str) -> loom_List[loom_Tuple[int, int, bytes]]:
        import pickle as loom_pickle
        with open(location_path, 'rb') as stream:
            items = loom_pickle.load(stream)
        output: loom_List[loom_Tuple[int, int, bytes]] = []
        for item in items:
            if len(item) >= 5:
                loom_sa, address, content = (item[0], item[1], item[4])
            elif len(item) == 3:
                loom_sa, address, content = item
            else:
                raise RuntimeError(f'unrecognised segment tuple in {location_path}: {item!r}')
            output.append((int(loom_sa), int(address), bytes(content) if content else b''))
        return output

    @staticmethod
    def loom_load_json_segments(location_path: str) -> loom_List[loom_Tuple[int, int, bytes]]:
        with open(location_path, 'r', encoding='utf-8') as stream:
            items = loom_json.load(stream)
        output: loom_List[loom_Tuple[int, int, bytes]] = []
        for item in items:
            if isinstance(item, dict):
                loom_sa = loom_as_int(item.get('start', item.get('vaddr')))
                content = bytes.fromhex(item.get('data', item.get('bytes', '')) or '')
                address = loom_as_int(item.get('end'), loom_sa + len(content))
            else:
                loom_sa, address = (loom_as_int(item[0]), loom_as_int(item[1]))
                content = bytes.fromhex(item[2] or '')
            output.append((loom_sa, address, content))
        return output

    @staticmethod
    def loom_load_elf_segments(location_path: str) -> loom_List[loom_Tuple[int, int, bytes]]:
        """Minimal ELF64-LE PT_LOAD reader (pure struct; no external deps)."""
        with open(location_path, 'rb') as stream:
            loom_blob = stream.read()
        if loom_blob[:4] != b'\x7fELF':
            raise RuntimeError(f'not an ELF image: {location_path}')
        if loom_blob[4] != 2:
            raise RuntimeError(f'only ELF64 is supported (EI_CLASS!=2): {location_path}')
        if loom_blob[5] != 1:
            raise RuntimeError(f'only little-endian ELF is supported (EI_DATA!=1): {location_path}')
        loom_e_phoff = loom_struct.unpack_from('<Q', loom_blob, 32)[0]
        loom_e_phentsize = loom_struct.unpack_from('<H', loom_blob, 54)[0]
        loom_e_phnum = loom_struct.unpack_from('<H', loom_blob, 56)[0]
        output: loom_List[loom_Tuple[int, int, bytes]] = []
        for loom_i in range(loom_e_phnum):
            cursor = loom_e_phoff + loom_i * loom_e_phentsize
            loom_p_type = loom_struct.unpack_from('<I', loom_blob, cursor)[0]
            if loom_p_type != 1:
                continue
            loom_p_offset = loom_struct.unpack_from('<Q', loom_blob, cursor + 8)[0]
            loom_p_vaddr = loom_struct.unpack_from('<Q', loom_blob, cursor + 16)[0]
            loom_p_filesz = loom_struct.unpack_from('<Q', loom_blob, cursor + 32)[0]
            loom_p_memsz = loom_struct.unpack_from('<Q', loom_blob, cursor + 40)[0]
            content = loom_blob[loom_p_offset:loom_p_offset + loom_p_filesz]
            output.append((loom_p_vaddr, loom_p_vaddr + loom_p_memsz, bytes(content)))
        if not output:
            raise RuntimeError(f'no PT_LOAD segments in {location_path}')
        return output

    def loom_ensure_emu(record):
        if record.loom_uc is None:
            import unicorn as loom_unicorn
            from unicorn import arm64_const as loom_a64
            record.loom_uc = record.loom_build_emu(loom_unicorn, loom_a64)
            record.LOOM__RX = [getattr(loom_a64, 'UC_ARM64_REG_X%d' % loom_i) for loom_i in range(31)]
            record.LOOM__LR = loom_a64.UC_ARM64_REG_LR
            record.LOOM__PC = loom_a64.UC_ARM64_REG_PC
            record.LOOM__SP = loom_a64.UC_ARM64_REG_SP
            record.LOOM__TPIDR = loom_a64.UC_ARM64_REG_TPIDR_EL0
        return record.loom_uc

    def loom_build_emu(record, loom_unicorn, loom_a64):
        loom_segs = record.loom_load_segments()
        loom_mu = loom_unicorn.Uc(loom_unicorn.UC_ARCH_ARM64, loom_unicorn.UC_MODE_ARM)
        loom_ranges = sorted(((record.loom_pdown(loom_sa), record.loom_pup(address)) for loom_sa, address, loom_d in loom_segs))
        loom_merged: loom_List[loom_List[int]] = []
        for loom_a, loom_b in loom_ranges:
            if loom_merged and loom_a <= loom_merged[-1][1]:
                loom_merged[-1][1] = max(loom_merged[-1][1], loom_b)
            else:
                loom_merged.append([loom_a, loom_b])
        loom_mapped: loom_List[loom_Tuple[int, int]] = []
        for loom_a, loom_b in loom_merged:
            loom_mu.mem_map(loom_a, loom_b - loom_a, loom_unicorn.UC_PROT_ALL)
            loom_mapped.append((loom_a, loom_b))
        for loom_sa, address, content in loom_segs:
            if content:
                loom_mu.mem_write(loom_sa, bytes(content))
        record.loom_map_region(loom_mu, loom_unicorn, record.loom_stack_base, record.loom_stack_size, loom_mapped)
        record.loom_map_region(loom_mu, loom_unicorn, record.loom_io_base, record.loom_io_size, loom_mapped)
        record.loom_map_region(loom_mu, loom_unicorn, record.loom_heap_base, record.loom_heap_size, loom_mapped)
        record.loom_map_region(loom_mu, loom_unicorn, record.loom_tls_base, record.loom_tls_size, loom_mapped)
        loom_mu.mem_write(record.loom_tls_base + record.loom_canary_off, loom_struct.pack('<Q', record.loom_canary & LOOM__M64))
        loom_trap = record.loom_pdown(record.loom_ret_magic)
        record.loom_map_region(loom_mu, loom_unicorn, loom_trap, record.loom_page, loom_mapped)
        loom_mu.mem_write(record.loom_ret_magic, b'\xc0\x03_\xd6')
        return loom_mu

    def loom_map_region(record, loom_mu, loom_unicorn, loom_base_value, span, loom_mapped: loom_List[loom_Tuple[int, int]]):
        loom_lo = record.loom_pdown(loom_base_value)
        loom_hi = record.loom_pup(loom_base_value + span)
        for loom_a, loom_b in loom_mapped:
            if loom_lo < loom_b and loom_a < loom_hi:
                raise RuntimeError('verifier scratch region [%#x,%#x) overlaps an already-mapped range [%#x,%#x); relocate it via verifier.memory_layout' % (loom_lo, loom_hi, loom_a, loom_b))
        loom_mu.mem_map(loom_lo, loom_hi - loom_lo, loom_unicorn.UC_PROT_ALL)
        loom_mapped.append((loom_lo, loom_hi))

    def loom_rx(record, loom_uc_value, loom_n_value: int) -> int:
        return loom_uc_value.reg_read(record.LOOM__RX[loom_n_value])

    def loom_wx(record, loom_uc_value, loom_n_value: int, loom_v: int) -> None:
        loom_uc_value.reg_write(record.LOOM__RX[loom_n_value], loom_v & LOOM__M64)

    def loom_ret(record, loom_uc_value) -> None:
        loom_uc_value.reg_write(record.LOOM__PC, loom_uc_value.reg_read(record.LOOM__LR))

    def loom_regconst(record, loom_a64, label: str) -> int:
        return getattr(loom_a64, 'UC_ARM64_REG_%s' % str(label).upper())

    def loom_alloc(record, loom_n_value: int) -> int:
        loom_p = record.loom_heap_ptr + 15 & ~15
        record.loom_heap_ptr = loom_p + (int(loom_n_value) + 15 & ~15)
        return loom_p

    def loom_stop(record, loom_uc_value, loom_reason: str) -> None:
        record.loom_stop_reason = loom_reason
        loom_uc_value.emu_stop()

    def loom_vformat(record, loom_uc_value, loom_dst: int, loom_fmt_ea: int, loom_va: int) -> int:
        loom_fmt_bytes = bytearray()
        for loom_i in range(4096):
            loom_b = loom_uc_value.mem_read(loom_fmt_ea + loom_i, 1)[0]
            if loom_b == 0:
                break
            loom_fmt_bytes.append(loom_b)
        loom_fmt_str = bytes(loom_fmt_bytes).decode('latin-1', errors='replace')
        loom_stk = int.from_bytes(loom_uc_value.mem_read(loom_va, 8), 'little')
        loom_gr_top = int.from_bytes(loom_uc_value.mem_read(loom_va + 8, 8), 'little')
        loom_gr_offs = int.from_bytes(loom_uc_value.mem_read(loom_va + 24, 4), 'little', signed=True)
        loom_cur_gr_offs = loom_gr_offs
        loom_cur_stk = loom_stk

        def loom_pop_int() -> int:
            nonlocal loom_cur_gr_offs, loom_cur_stk
            if loom_cur_gr_offs < 0:
                loom_val_ptr = loom_gr_top + loom_cur_gr_offs
                loom_cur_gr_offs += 8
            else:
                loom_val_ptr = loom_cur_stk
                loom_cur_stk += 8
            return int.from_bytes(loom_uc_value.mem_read(loom_val_ptr, 8), 'little') & LOOM__M64
        output = bytearray()
        loom_i = 0
        LOOM_L = len(loom_fmt_str)
        while loom_i < LOOM_L:
            loom_c = loom_fmt_str[loom_i]
            if loom_c != '%':
                output.append(ord(loom_c))
                loom_i += 1
                continue
            loom_j = loom_i + 1
            while loom_j < LOOM_L and loom_fmt_str[loom_j] in '-+ 0#':
                loom_j += 1
            while loom_j < LOOM_L and loom_fmt_str[loom_j].isdigit():
                loom_j += 1
            if loom_j < LOOM_L and loom_fmt_str[loom_j] == '.':
                loom_j += 1
                while loom_j < LOOM_L and loom_fmt_str[loom_j].isdigit():
                    loom_j += 1
            while loom_j < LOOM_L and loom_fmt_str[loom_j] in 'hljzt':
                loom_j += 1
            if loom_j >= LOOM_L:
                break
            loom_conv = loom_fmt_str[loom_j]
            loom_spec = loom_fmt_str[loom_i:loom_j + 1]
            loom_i = loom_j + 1
            if loom_conv == '%':
                output.append(ord('%'))
                continue
            if loom_conv in ('d', 'i'):
                loom_v = loom_pop_int() & 4294967295
                if loom_v & 2147483648:
                    loom_v -= 4294967296
                try:
                    output.extend((loom_spec % loom_v).encode('latin-1'))
                except Exception:
                    output.extend(str(loom_v).encode())
            elif loom_conv in ('x', 'X', 'o', 'u'):
                loom_v = loom_pop_int() & 4294967295
                try:
                    output.extend((loom_spec % loom_v).encode('latin-1'))
                except Exception:
                    output.extend(('%x' % loom_v).encode())
            elif loom_conv == 's':
                loom_p = loom_pop_int()
                loom_sb = bytearray()
                for loom_k in range(4096):
                    loom_b = loom_uc_value.mem_read(loom_p + loom_k, 1)[0]
                    if loom_b == 0:
                        break
                    loom_sb.append(loom_b)
                output.extend(loom_sb)
            elif loom_conv == 'c':
                output.append(loom_pop_int() & 255)
            elif loom_conv == 'p':
                output.extend(('0x%x' % loom_pop_int()).encode())
            else:
                output.extend(loom_spec.encode('latin-1'))
                loom_pop_int()
        output.append(0)
        loom_uc_value.mem_write(loom_dst, bytes(output))
        record.loom_wx(loom_uc_value, 0, len(output) - 1)
        return len(output) - 1

    def loom_on_code(record, loom_uc_value, loom_address, span, loom_user_data):
        if loom_address == record.loom_ret_magic:
            loom_uc_value.emu_stop()
            return
        label = record.loom_iat_by_addr.get(loom_address)
        if label is not None:
            if record.loom_shim_enabled(label):
                LOOM_SHIM_MODELS[label](record, loom_uc_value)
            else:
                record.loom_stop(loom_uc_value, 'unhandled IAT %s@%#x (no enabled shim)' % (label, loom_address))
            return
        if record.loom_iat_pages and loom_address & ~(record.loom_page - 1) in record.loom_iat_pages:
            record.loom_stop(loom_uc_value, 'unknown IAT-page target %#x' % loom_address)
            return

    def loom_place_input(record, loom_uc_value, loom_a64, loom_input_bytes: bytes) -> None:
        loom_mode = record.loom_input_spec.get('mode', 'cstr_ptr_x0')
        if loom_mode in ('cstr_ptr_x0', 'bytes_ptr_x0'):
            loom_ptr = loom_as_int(record.loom_input_spec.get('ptr'), record.loom_input_ptr)
            loom_payload = bytes(loom_input_bytes)
            if loom_mode == 'cstr_ptr_x0':
                loom_payload = loom_payload + b'\x00'
            loom_uc_value.mem_write(loom_ptr, loom_payload)
            loom_uc_value.reg_write(record.loom_regconst(loom_a64, record.loom_input_spec.get('ptr_reg', 'X0')), loom_ptr & LOOM__M64)
            loom_len_reg = record.loom_input_spec.get('len_reg')
            if loom_len_reg:
                loom_uc_value.reg_write(record.loom_regconst(loom_a64, loom_len_reg), len(loom_input_bytes) & LOOM__M64)
        elif loom_mode in ('scalar_x0', 'retval_x0'):
            loom_v = int.from_bytes(bytes(loom_input_bytes)[:8].ljust(8, b'\x00'), 'little')
            loom_uc_value.reg_write(loom_a64.UC_ARM64_REG_X0, loom_v & LOOM__M64)
        else:
            raise RuntimeError('unknown verifier.input.mode %r' % loom_mode)

    def loom_extract_output(record, loom_uc_value, loom_a64) -> bytes:
        loom_mode = record.loom_output_spec.get('mode', 'cstr_x0')
        if loom_mode in ('cstr_x0', 'cstr_ptr'):
            loom_ptr = loom_uc_value.reg_read(record.loom_regconst(loom_a64, record.loom_output_spec.get('ptr_reg', 'X0')))
            if not loom_ptr:
                raise RuntimeError('output pointer (return value) is null')
            loom_maxlen = int(record.loom_output_spec.get('max_len', 256))
            source = bytes(loom_uc_value.mem_read(loom_ptr, loom_maxlen))
            return source.split(b'\x00', 1)[0]
        if loom_mode == 'bytes_x0':
            loom_ptr = loom_uc_value.reg_read(record.loom_regconst(loom_a64, record.loom_output_spec.get('ptr_reg', 'X0')))
            loom_n_value = int(record.loom_output_spec.get('len', 0))
            return bytes(loom_uc_value.mem_read(loom_ptr, loom_n_value)) if loom_n_value else b''
        if loom_mode == 'retval':
            span = int(record.loom_output_spec.get('size', 8))
            loom_v = loom_uc_value.reg_read(loom_a64.UC_ARM64_REG_X0)
            return (loom_v & (1 << span * 8) - 1).to_bytes(span, 'little')
        if loom_mode == 'region':
            loom_base_value = loom_as_int(record.loom_output_spec.get('base'), record.loom_input_ptr)
            loom_n_value = int(record.loom_output_spec.get('len', 0))
            return bytes(loom_uc_value.mem_read(loom_base_value, loom_n_value)) if loom_n_value else b''
        raise RuntimeError('unknown verifier.output.mode %r' % loom_mode)

    def evaluate_io(record, loom_entry_value: int, loom_input_bytes: bytes) -> bytes:
        import unicorn as loom_unicorn
        from unicorn import arm64_const as loom_a64
        if loom_entry_value is None:
            loom_entry_value = record.loom_entry_value()
        if loom_entry_value is None:
            raise RuntimeError('no entry address: pass entry to run_on_io or set verifier.entry')
        loom_mu = record.loom_ensure_emu()
        record.loom_stop_reason = None
        record.loom_heap_ptr = record.loom_heap_base
        loom_mu.mem_write(record.loom_stack_base, b'\x00' * record.loom_stack_size)
        loom_mu.mem_write(record.loom_io_base, b'\x00' * record.loom_io_size)
        loom_mu.mem_write(record.loom_tls_base + record.loom_canary_off, loom_struct.pack('<Q', record.loom_canary & LOOM__M64))
        for loom_i in range(31):
            loom_mu.reg_write(record.LOOM__RX[loom_i], 0)
        loom_mu.reg_write(record.LOOM__SP, record.loom_stack_base + record.loom_stack_size - record.loom_sp_offset & LOOM__M64)
        loom_mu.reg_write(record.LOOM__TPIDR, record.loom_tls_base & LOOM__M64)
        loom_mu.reg_write(record.LOOM__LR, record.loom_ret_magic & LOOM__M64)
        record.loom_place_input(loom_mu, loom_a64, loom_input_bytes)
        loom_h = loom_mu.hook_add(loom_unicorn.UC_HOOK_CODE, record.loom_on_code)
        try:
            loom_mu.emu_start(int(loom_entry_value), 0, timeout=record.loom_timeout, count=record.loom_max_insns)
        except loom_unicorn.UcError as loom_exc:
            location = loom_mu.reg_read(record.LOOM__PC)
            raise RuntimeError('unicorn fault at pc=%#x: %s' % (location, loom_exc)) from loom_exc
        finally:
            loom_mu.hook_del(loom_h)
        if record.loom_stop_reason:
            raise RuntimeError('emulation aborted: %s' % record.loom_stop_reason)
        return record.loom_extract_output(loom_mu, loom_a64)

# TODO(validate): the reference read a single pickle of segments dumped from
# TODO(validate): the reference hard-coded "write a NUL-terminated buffer at
# TODO(validate): default output extraction reproduces the reference (read the
# TODO(validate): the reference reused the emulator across calls and only set

__all__ = [export_binding for export_binding in ['BehaviorOracle', 'LOOM_SHIM_MODELS', 'MachineOracle', 'loom_Callable', 'loom_Dict', 'loom_List', 'loom_Optional', 'loom_Tuple', 'loom_annotations', 'loom_json', 'loom_os', 'loom_register_shim', 'loom_shim', 'loom_struct'] if export_binding in globals()]
