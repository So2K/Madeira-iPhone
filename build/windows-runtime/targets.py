#!/usr/bin/env python3
"""Select the versioned Wine PE farm from the pinned source, preserving owners."""
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DXMT = {'d3d9.dll', 'd3d9shim.dll', 'd3d9-emulated.dll', 'd3d10core.dll',
        'd3d11.dll', 'dxgi.dll', 'winemetal.dll', 'nvapi64.dll'}
CUSTOM = {'faultrep.dll', 'madeira_d3d12.dll', 'xtajit64.dll', 'xtajit.dll',
          'dockhost.exe', 'dock-notices.txt'}
# These two files have no PE target in this Wine pin. Keep their versioned bytes.
VERSIONED = {'wineios.drv', 'tftrace-x64.dll'}


def targets(arch):
    modules = {}
    for category in ('dlls', 'programs'):
        for makefile in (ROOT / 'wine' / category).glob('*/Makefile.in'):
            match = re.search(r'^MODULE\s*=\s*(\S+)', makefile.read_text(), re.M)
            if match:
                modules[match[1].lower()] = (makefile.parent.name, category, match[1])
    result = []
    farm = ROOT / f'app/Madeira/{arch}-windows'
    for dest in sorted(farm.iterdir()):
        name = dest.name.lower()
        dxmt = DXMT if arch == 'arm64ec' else {'d3d11.dll', 'dxgi.dll', 'winemetal.dll'}
        if name in dxmt | CUSTOM | VERSIONED or (arch == 'arm64ec' and name in {'d3d12.dll', 'd3d12core.dll'}):
            continue
        source = 'd3d9.dll' if name == 'd3d9-wined3d.dll' else name
        if source not in modules:
            if dest.suffix.lower() in {'.exe', '.tlb'} or name.startswith('.'):
                continue  # versioned test programs and type libraries
            raise ValueError(f'No source owner for {dest.relative_to(ROOT)}')
        directory, category, module = modules[source]
        result.append((f'{category}/{directory}/{arch}-windows/{module}', dest.name, directory))
    if not result:
        raise ValueError(f'No Wine targets selected for {arch}')
    return result


def main():
    arch, action = sys.argv[1:]
    selected = targets(arch)
    if action == 'list':
        print('\n'.join(directory if name != 'd3d9-wined3d.dll' else 'd3d9-wined3d'
                        for _, name, directory in selected))
        return
    build = ROOT / 'wine/build-macos'
    subprocess.run(['make', '-C', str(build), '-j' + __import__('os').environ.get('JOBS', '8'),
                    *(target for target, _, _ in selected)], check=True)
    strip = ROOT / 'toolchains/llvm-mingw-20260421-ucrt-macos-universal/bin/aarch64-w64-mingw32-strip'
    for target, name, _ in selected:
        dest = ROOT / f'app/Madeira/{arch}-windows' / name
        shutil.copyfile(build / target, str(dest) + '.tmp')
        if dest.suffix != '.tlb':
            subprocess.run([str(strip), '--strip-debug', str(dest) + '.tmp'], check=True)
        Path(str(dest) + '.tmp').replace(dest)


if __name__ == '__main__':
    main()
