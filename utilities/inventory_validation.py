"""Regenerate the ``TODO(validate)`` marker inventory for guides/VALIDATION_STATUS.md.

Read-only, standard library only. It prints one ``path:line: text`` record per
marker found plus counts by area, so the inventory in
``guides/VALIDATION_STATUS.md`` can be re-checked later instead of going stale.

Scope: every text file in this repository except VCS/build directories, compiled
bytecode and other binary artifacts, and the three files that quote the marker by
design while documenting it (``guides/VALIDATION_STATUS.md``, ``guides/VERIFICATION.md``
and this script, whose docstring names it). The needle is assembled from two string
literals as well, and the exclusions are printed so the scope is never implicit.

Usage::

    python3 utilities/inventory_validation.py [--expect N]

Exit status is 0; with ``--expect N`` it is 1 when the total differs from N.
"""
import argparse as loom_argparse
import hashlib as loom_hashlib
import os as loom_os
import sys as loom_sys
LOOM_NEEDLE = 'TODO(' + 'validate)'
LOOM_SKIP_DIRS = frozenset({'Build', '.git', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.venv', 'venv', 'build', 'dist', '.idea', '.vscode', '.eggs', 'node_modules', '.tox'})
LOOM_SKIP_SUFFIXES = ('.pyc', '.pyo', '.so', '.o', '.a', '.bin', '.elf', '.dump', '.pkl', '.pickle', '.i64', '.idb', '.id0', '.id1', '.id2', '.til', '.nam', '.zip')
LOOM_QUOTES_MARKER = frozenset({'guides/VALIDATION_STATUS.md', 'guides/VERIFICATION.md', 'utilities/inventory_validation.py'})
LOOM_AREAS = (('branchloom/database/', 'ida adapter'), ('branchloom/arm_words/', 'isa'), ('branchloom/dispatch_shapes/', 'patterns'), ('branchloom/target_sources/', 'resolve'), ('branchloom/equivalence/', 'verify'), ('branchloom/pipeline/', 'phases'), ('branchloom/integrity/', 'safety'), ('branchloom/console/', 'cli'))
LOOM_AREA_ORDER = ('ida adapter', 'isa', 'patterns', 'resolve', 'verify', 'phases', 'safety', 'cli', 'docs', 'other')

def loom_area_of(loom_rel_path):
    """Area label for a repository-relative path."""
    for loom_prefix, loom_label in LOOM_AREAS:
        if loom_rel_path.startswith(loom_prefix):
            return loom_label
    if loom_rel_path.endswith('.md'):
        return 'docs'
    return 'other'

def loom_repo_root():
    """Repository root: the parent of the directory holding this script."""
    return loom_os.path.dirname(loom_os.path.dirname(loom_os.path.abspath(__file__)))

def loom_looks_binary(location_path):
    """True when the first block contains a NUL byte (compiled/opaque file)."""
    try:
        with open(location_path, 'rb') as stream:
            return b'\x00' in stream.read(8192)
    except OSError:
        return True

def loom_iter_files(loom_root):
    """Yield repository-relative paths of candidate text files, sorted."""
    for loom_dirpath, loom_dirnames, loom_filenames in loom_os.walk(loom_root):
        loom_dirnames[:] = sorted((loom_d_value for loom_d_value in loom_dirnames if loom_d_value not in LOOM_SKIP_DIRS and (not loom_d_value.endswith('.egg-info'))))
        for label in sorted(loom_filenames):
            if label.endswith(LOOM_SKIP_SUFFIXES):
                continue
            loom_abs_path = loom_os.path.join(loom_dirpath, label)
            loom_rel = loom_os.path.relpath(loom_abs_path, loom_root).replace(loom_os.sep, '/')
            if loom_os.path.islink(loom_abs_path) or not loom_os.path.isfile(loom_abs_path):
                continue
            # Canonical documents and staged aliases represent one logical input.
            if loom_rel.startswith('项目文档/'):
                loom_rel = loom_rel[len('项目文档/'):]
                if loom_rel.startswith('历史/'):
                    continue
                loom_alias = loom_os.path.join(loom_root, *loom_rel.split('/'))
                if (loom_os.path.realpath(loom_alias) == loom_os.path.abspath(loom_alias)
                        and loom_os.path.isfile(loom_alias) and not loom_os.path.islink(loom_alias)):
                    with open(loom_alias, 'rb') as loom_original, open(loom_abs_path, 'rb') as loom_saved:
                        if loom_hashlib.sha256(loom_original.read()).digest() == loom_hashlib.sha256(loom_saved.read()).digest():
                            continue
            if loom_rel in LOOM_QUOTES_MARKER:
                continue
            yield (loom_rel, loom_abs_path)

def loom_scan(loom_root):
    """Return ``[(rel_path, lineno, text)]`` for every occurrence, path-sorted."""
    loom_hits = []
    for loom_rel, loom_abs_path in loom_iter_files(loom_root):
        if loom_looks_binary(loom_abs_path):
            continue
        try:
            with open(loom_abs_path, 'r', encoding='utf-8', errors='replace') as stream:
                for loom_lineno, loom_line in enumerate(stream, 1):
                    if LOOM_NEEDLE in loom_line:
                        loom_hits.append((loom_rel, loom_lineno, loom_line.strip()))
        except OSError:
            continue
    return sorted(loom_hits, key=lambda loom_h: (loom_h[0], loom_h[1]))

def launch(tokens=None):
    arguments = loom_argparse.ArgumentParser(description=__doc__.splitlines()[0])
    arguments.add_argument('--expect', type=int, default=None, help='exit non-zero unless exactly N markers are found')
    options = arguments.parse_args(tokens)
    loom_root = loom_repo_root()
    loom_hits = loom_scan(loom_root)
    for loom_rel, loom_lineno, loom_text in loom_hits:
        print('%s:%d: %s' % (loom_rel, loom_lineno, loom_text))
    loom_files = sorted({loom_rel for loom_rel, loom_ln, loom_t in loom_hits})
    loom_by_area = {}
    for loom_rel, loom_ln, loom_t in loom_hits:
        loom_by_area[loom_area_of(loom_rel)] = loom_by_area.get(loom_area_of(loom_rel), 0) + 1
    print('---')
    print('needle            : %s' % LOOM_NEEDLE)
    print('root              : %s' % loom_root)
    print('excluded (quotes) : %s' % ', '.join(sorted(LOOM_QUOTES_MARKER)))
    print('occurs in files   : %d' % len(loom_files))
    print('total occurrences : %d' % len(loom_hits))
    for loom_area in LOOM_AREA_ORDER:
        if loom_by_area.get(loom_area):
            print('  %-13s %d' % (loom_area, loom_by_area[loom_area]))
    if options.expect is not None and len(loom_hits) != options.expect:
        print('MISMATCH: expected %d, found %d' % (options.expect, len(loom_hits)))
        return 1
    return 0
if __name__ == '__main__':
    loom_sys.exit(launch())
