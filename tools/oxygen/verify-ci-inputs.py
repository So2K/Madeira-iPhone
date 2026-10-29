#!/usr/bin/env python3
"""Fail closed before cold jobs, and verify the strict PE result after packaging."""
from pathlib import Path, PurePosixPath
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def fail(message):
    raise SystemExit('ONI CI input refusal: ' + message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def regular(rel):
    path = PurePosixPath(rel)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        fail('unsafe manifest member')
    p = ROOT / rel
    cursor = ROOT
    for part in path.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail('symlink source member: ' + rel)
    if not p.is_file():
        fail('missing source member: ' + rel)
    return p.read_bytes()


config = json.loads((ROOT / 'tools/oxygen/ci-inputs.json').read_text())
if config.get('schema') != 1:
    fail('unknown schema')
packet = config.get('ntdll_packet', {})
if packet.get('ready') is not True:
    fail('reviewed latest-ntdll packet is not bound; workflow is intentionally not dispatch-ready')
if packet.get('mode') not in ('strict-prebuilt', 'coff-timestamp-only-v2', 'pe-build-timestamps-v3'):
    fail('unknown PE verification mode; no pattern fallback')
for field in ('baseline_sha256', 'candidate_sha256'):
    value = packet.get(field)
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        fail('missing exact PE pin ' + field)
files = packet.get('files')
if not isinstance(files, dict) or not files or packet.get('entrypoint') not in files:
    fail('missing strict patch source members')
for rel in files:
    if not rel.startswith('build/windows-runtime/oni-ntdll/'):
        fail('patch source outside content-key-owned directory')
for rel, digest in {**config['files'], **files}.items():
    if sha(regular(rel)) != digest:
        fail('source hash mismatch: ' + rel)

if len(sys.argv) == 3 and sys.argv[1] == '--ipa':
    with zipfile.ZipFile(sys.argv[2]) as archive:
        name = 'Payload/Madeira.app/arm64ec-windows/ntdll.dll'
        if archive.namelist().count(name) != 1:
            fail('complete IPA lacks a unique patched ntdll')
        data = archive.read(name)
    mode = packet.get('mode')
    if mode == 'strict-prebuilt':
        if sha(data) != packet['candidate_sha256']:
            fail('complete IPA does not contain the exact patched ntdll')
    elif mode in ('coff-timestamp-only-v2', 'pe-build-timestamps-v3'):
        # Every source member was hash-checked above, before importing this reviewed guard.
        entry = ROOT / packet['entrypoint']
        spec = importlib.util.spec_from_file_location('oni_ntdll_ci_guard', entry)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        original_path = sys.path[:]
        original_bytecode = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            sys.path.insert(0, str(entry.parent))
            spec.loader.exec_module(module)
            module.verify_candidate(data)
            if sha(module.normalize_timestamp(data)) != packet['candidate_sha256']:
                fail('normalized whole-file ntdll candidate pin mismatch')
        except Exception as error:
            fail('reviewed CI output contract refused ntdll: ' + str(error))
        finally:
            sys.path[:] = original_path
            sys.dont_write_bytecode = original_bytecode
    else:
        fail('unknown PE verification mode; no pattern fallback')
    print('ONI PE postcondition:', mode, 'raw SHA256', sha(data), 'canonical SHA256', packet['candidate_sha256'])
elif len(sys.argv) == 1:
    if os.environ.get('GITHUB_REPOSITORY') != config['repository_target']:
        fail('unexpected fork repository')
    if os.environ.get('RUNNER_ARCH') != 'ARM64':
        fail('expected standard Apple Silicon runner')
    xcode = config['xcode']
    if os.environ.get('DEVELOPER_DIR') != xcode['developer_dir']:
        fail('wrong explicit developer directory')
    if command('xcodebuild', '-version') != xcode['version_output']:
        fail('selected Xcode changed; no silent SDK/cache fallback')
    for sdk, expected in [('iphoneos', xcode['iphoneos_sdk']), ('macosx', xcode['macos_sdk'])]:
        if command('xcrun', '--sdk', sdk, '--show-sdk-version') != expected:
            fail('selected SDK changed: ' + sdk)
    for path, pin in config['gitlinks'].items():
        if command('git', 'rev-parse', 'HEAD:' + path) != pin:
            fail('gitlink mismatch: ' + path)
    ancestry = subprocess.run(['git', 'merge-base', '--is-ancestor', config['upstream_commit'], 'HEAD'],
                              cwd=ROOT, capture_output=True)
    if ancestry.returncode != 0:
        fail('reviewed c2 base is not a proven ancestor in bounded checkout history')
    print('Reviewed source and selected Xcode match; SDK keys must still be freshly computed by ci-input-key.sh')
    print('Source commit:', command('git', 'rev-parse', 'HEAD'))
    print('Source tree:', command('git', 'rev-parse', 'HEAD^{tree}'))
else:
    fail('usage: verify-ci-inputs.py [--ipa PATH]')
