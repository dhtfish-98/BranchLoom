"""
Unit tests for the config loader (branchloom.settings).

The config is the single home of every target-specific value, which makes it the
single place a mistake becomes a wrong write. Two properties matter most and are
pinned here:

  * **the aggressive-mode gate** — ``linear``/``full`` rewrite real bytes, so the
    loader must refuse them unless a behavioural verifier with known I/O vectors is
    configured. There is no flag, default or ordering that opens that gate quietly.
  * **no implicit target assumptions** — an empty or malformed ``exec_segments`` is
    an error, never a silent fallback to ``.text``.

JSON configs are used throughout so the tests run with no PyYAML installed.

Run:  pytest -q
"""
import json as loom_json
import os as loom_os
import tempfile as loom_tempfile
from branchloom import settings as LOOM_CFG
LOOM_SEGS = [{'name': '.text'}]

def loom_write(loom_cfg_dict, loom_suffix='.json'):
    loom_fd, location_path = loom_tempfile.mkstemp(prefix='branchloom-cfg-', suffix=loom_suffix)
    with loom_os.fdopen(loom_fd, 'w', encoding='utf-8') as stream:
        loom_json.dump(loom_cfg_dict, stream)
    return location_path

def loom_load(loom_cfg_dict):
    return LOOM_CFG.read_settings(loom_write(loom_cfg_dict))

def loom_err(loom_cfg_dict):
    """Load a config expected to be rejected; return the ConfigError message."""
    try:
        loom_load(loom_cfg_dict)
    except LOOM_CFG.SettingsFault as loom_exc:
        return str(loom_exc)
    raise AssertionError('expected ConfigError, config was accepted')

def test_loom_minimal_config_loads_with_safe_defaults():
    settings = loom_load({'exec_segments': LOOM_SEGS})
    assert settings.loom_mode == 'switch'
    assert settings.loom_strict_orig_check is True
    assert settings.loom_image is None
    assert settings.loom_jobs == []

def test_loom_missing_file_is_a_config_error():
    try:
        LOOM_CFG.read_settings('/nonexistent/branchloom/config.json')
    except LOOM_CFG.SettingsFault as loom_exc:
        assert 'not found' in str(loom_exc)
    else:
        raise AssertionError('expected ConfigError for a missing config')

def test_loom_raw_document_is_kept_for_pass_through_keys():
    settings = loom_load({'exec_segments': LOOM_SEGS, 'some_future_key': {'a': 1}})
    assert settings.source['some_future_key'] == {'a': 1}

def test_loom_empty_exec_segments_is_rejected():
    loom_msg = loom_err({'exec_segments': []})
    assert 'exec_segments' in loom_msg

def test_loom_exec_segment_needs_a_name_or_a_range():
    assert 'name' in loom_err({'exec_segments': [{}]})

def test_loom_exec_segment_range_is_validated():
    assert 'range' in loom_err({'exec_segments': [{'range': [8192, 4096]}]})
    assert 'range' in loom_err({'exec_segments': [{'range': [4096]}]})

def test_loom_exec_segment_accepts_a_name_or_a_range():
    loom_by_name = loom_load({'exec_segments': [{'name': '__text'}]})
    assert loom_by_name.loom_exec_segments[0].loom_matches_name('__text')
    assert not loom_by_name.loom_exec_segments[0].loom_matches_name('.text')
    loom_by_range = loom_load({'exec_segments': [{'range': [4096, 8192]}]})
    assert loom_by_range.loom_exec_segments[0].loom_range == [4096, 8192]
    assert loom_by_range.loom_exec_segments[0].loom_matches_name('.text') is False

def test_loom_switch_mode_needs_no_verifier():
    """The default mode changes no bytes, so it is always allowed."""
    assert loom_load({'exec_segments': LOOM_SEGS, 'mode': 'switch'}).loom_mode == 'switch'

def test_loom_linear_and_full_are_refused_without_known_vectors():
    for loom_mode in ('linear', 'full'):
        loom_msg = loom_err({'exec_segments': LOOM_SEGS, 'mode': loom_mode})
        assert 'verifier' in loom_msg and 'known_vectors' in loom_msg

def test_loom_a_verifier_backend_alone_does_not_open_the_gate():
    """A configured oracle with nothing to check against proves nothing."""
    loom_msg = loom_err({'exec_segments': LOOM_SEGS, 'mode': 'full', 'verifier': {'backend': 'unicorn'}})
    assert 'known_vectors' in loom_msg

def test_loom_linear_is_allowed_once_known_vectors_exist():
    settings = loom_load({'exec_segments': LOOM_SEGS, 'mode': 'linear', 'verifier': {'backend': 'unicorn', 'entry': '0x1000', 'known_vectors': [{'in': '00', 'out': '01'}]}})
    assert settings.loom_mode == 'linear'

def test_loom_unknown_mode_is_rejected():
    loom_msg = loom_err({'exec_segments': LOOM_SEGS, 'mode': 'rewrite-everything'})
    assert 'mode' in loom_msg
    assert set(LOOM_CFG.LOOM_VALID_MODES) == {'switch', 'linear', 'full'}

def test_loom_strict_orig_check_can_be_disabled_explicitly():
    """Documented as dangerous — but it must take an explicit false, not a default."""
    assert loom_load({'exec_segments': LOOM_SEGS, 'strict_orig_check': False}).loom_strict_orig_check is False

def test_loom_cff_accessor_defaults():
    settings = loom_load({'exec_segments': LOOM_SEGS})
    assert settings.loom_idx_table_scale == 2
    assert settings.loom_tgt_table_scale == 3
    assert settings.loom_entry_size == 8
    assert settings.loom_state_slot_bases == ['X29', 'SP']
    assert settings.loom_index_reg_allowlist == []
    assert settings.loom_dispatch_base_overrides == {}

def test_loom_cff_accessors_take_config_overrides():
    settings = loom_load({'exec_segments': LOOM_SEGS, 'cff': {'idx_table_scale': 1, 'tgt_table_scale': 2, 'entry_size': 4, 'state_slot_bases': ['SP'], 'index_reg_allowlist': [8, 9]}})
    assert settings.loom_idx_table_scale == 1
    assert settings.loom_tgt_table_scale == 2
    assert settings.loom_entry_size == 4
    assert settings.loom_state_slot_bases == ['SP']
    assert settings.loom_index_reg_allowlist == [8, 9]

def test_loom_dispatch_base_overrides_are_parsed_as_hex():
    """String keys and values are hex, matching the ``0x..`` convention everywhere else.

    Worth knowing because JSON and YAML mapping keys are *always* strings: a
    decimal-looking key like ``"8192"`` is read as ``0x8192``, not 8192. Write
    every address with an explicit ``0x`` prefix. An int value stays decimal —
    only strings go through the hex parse.
    """
    settings = loom_load({'exec_segments': LOOM_SEGS, 'cff': {'dispatch_base_overrides': {'0x1000': '0x20000', '8192': 131072}}})
    assert settings.loom_dispatch_base_overrides == {4096: 131072, 33170: 131072}

def test_loom_yaml_config_reports_a_clear_error_when_pyyaml_is_missing():
    """A .yml config without PyYAML must say so, not fail as a JSON parse error."""
    if LOOM_CFG.LOOM__HAVE_YAML:
        location_path = loom_write({'exec_segments': LOOM_SEGS}, loom_suffix='.yml')
        assert LOOM_CFG.read_settings(location_path).loom_mode == 'switch'
        return
    location_path = loom_write({'exec_segments': LOOM_SEGS}, loom_suffix='.yml')
    try:
        LOOM_CFG.read_settings(location_path)
    except LOOM_CFG.SettingsFault as loom_exc:
        assert 'PyYAML' in str(loom_exc)
    else:
        raise AssertionError('expected ConfigError naming PyYAML')
