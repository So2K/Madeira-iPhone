#!/usr/bin/env python3
"""Retain only bounded public build outputs; never collect logs or environment."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
MAX_JSON = 1024 * 1024


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def regular(root, rel, limit):
    """Refuse symlinks in every component, escape, and unexpectedly large files."""
    name = PurePosixPath(rel)
    if name.is_absolute() or '..' in name.parts or not name.parts:
        return None
    path = root
    for part in name.parts:
        path = path / part
        if path.is_symlink():
            return None
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    return path if stat.S_ISREG(info.st_mode) and info.st_size <= limit else None


def read_json(root, rel):
    path = regular(root, rel, MAX_JSON)
    if path is None:
        return None
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, OSError):
        return None
    return value if isinstance(value, dict) else None


def selected_report(value):
    """No recursive export: unknown fields, paths and strings are discarded."""
    out = {}
    for key in ('raw_input_sha256', 'raw_output_sha256', 'normalized_input_sha256', 'normalized_output_sha256'):
        if isinstance(value.get(key), str) and HEX.fullmatch(value[key]):
            out[key] = value[key]
    for key in ('raw_bytes', 'raw_timestamp', 'raw_debug_timestamp', 'official_timestamp'):
        if type(value.get(key)) is int and 0 <= value[key] <= 0xffffffff:
            out[key] = value[key]
    if value.get('mode') == 'pe-build-timestamps-v3':
        out['mode'] = value['mode']
    if value.get('changed_file_offsets') == [0x28400, 0x28404]:
        out['changed_file_offsets'] = value['changed_file_offsets']
    if value.get('raw_timestamp_unchanged') is True:
        out['raw_timestamp_unchanged'] = True
    return out


def main():
    # RUNNER_TEMP selects a local output directory, but its value is never saved.
    # GitHub's hosted runner owns this directory; do not reuse existing contents.
    raw_temp = os.environ.get('RUNNER_TEMP')
    if not raw_temp:
        raise SystemExit('RUNNER_TEMP required; no repository fallback')
    temp = Path(raw_temp).resolve(strict=True)
    output = temp / 'oni-failure-diagnostics'
    output.mkdir(mode=0o700)
    public = {'schema': 1, 'scope': 'Whitelisted public compiler/source pins and staged ntdll only; no logs or environment'}
    try:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        if COMMIT.fullmatch(head):
            public['source_commit'] = head
    except (OSError, subprocess.CalledProcessError):
        pass
    cfg = read_json(ROOT, 'tools/oxygen/ci-inputs.json') or {}
    source_records = {}
    # The reviewed config lists only repository-owned public sources. Export
    # hashes/status, never arbitrary source bytes or values from a failed report.
    sources = cfg.get('files', {})
    if isinstance(sources, dict):
        for rel, expected in list(sources.items())[:32]:
            if not isinstance(rel, str) or not isinstance(expected, str) or not HEX.fullmatch(expected):
                continue
            path = regular(ROOT, rel, 2 * 1024 * 1024)
            if path is not None:
                source_records[rel] = {'sha256': digest(path), 'expected_sha256': expected}
    public['source_files'] = source_records
    pins_rel = 'build/windows-runtime/oni-ntdll/provenance-pins.json'
    pins = read_json(ROOT, pins_rel) or {}
    compiler = {}
    toolchain = ROOT / 'toolchains/llvm-mingw-20260421-ucrt-macos-universal'
    # These filenames are a fixed public-toolchain whitelist, not report input.
    for rel in ('bin/clang-22', 'bin/ld.lld', 'bin/llvm-objcopy', 'bin/arm64ec-w64-mingw32-clang',
                'bin/arm64ec-w64-windows-gnu.cfg', 'lib/libclang-cpp.dylib', 'lib/libLLVM.dylib',
                'bin/arm64ec-w64-mingw32-strip', 'bin/arm64ec-w64-mingw32-ld'):
        # Official llvm-mingw uses internal tool symlinks. Only hash their target
        # if it resolves within this exact root; never export its path/content.
        path = toolchain / rel
        try:
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(toolchain.resolve()) or not resolved.is_file():
                continue
            info = resolved.stat()
            if info.st_size > 256 * 1024 * 1024:
                continue
            compiler[rel] = {'sha256': digest(resolved), 'bytes': info.st_size}
        except (OSError, RuntimeError):
            pass
    public['compiler_files'] = compiler
    if isinstance(pins.get('toolchain_archive_sha256'), str) and HEX.fullmatch(pins['toolchain_archive_sha256']):
        public['compiler_release_sha256'] = pins['toolchain_archive_sha256']
    for key in ('base_upstream_commit', 'wine_gitlink'):
        if isinstance(pins.get(key), str) and COMMIT.fullmatch(pins[key]):
            public[key] = pins[key]
    reports = []
    # The hook creates only fresh oni-ntdll-* dirs in RUNNER_TEMP. Inspect at
    # most eight entries; do not recurse or copy raw reports/logs.
    for folder in sorted(temp.glob('oni-ntdll-*'))[:8]:
        if folder.is_symlink() or not folder.is_dir():
            continue
        value = read_json(folder, 'report.json')
        if value is not None:
            reports.append(selected_report(value))
    public['patch_reports'] = reports
    pe = regular(ROOT, 'app/Madeira/arm64ec-windows/ntdll.dll', 2 * 1024 * 1024)
    if pe is not None:
        data = pe.read_bytes()
        (output / 'ntdll.dll').write_bytes(data)
        public['ntdll'] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
    (output / 'public-build-pins.json').write_text(json.dumps(public, indent=2) + '\n')
    print('Retained only public staged ntdll and selected compiler/source/report hashes')


if __name__ == '__main__':
    main()
