#!/usr/bin/env python3
"""A3: NDK compile/link of ts2_core plus the already-verified private 9550 lift.

No lift or new x86 reference is generated. Optional QEMU is ndk_bionic_qemu,
never Android. All build products, commands and reference-derived output stay private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PINS = {
    'transport.cpp': '164c1dfcd4d70a7ad7e9cbd97f8ac90bea12afa5f3b35509075a7fd05346ed11',
    'valid.cpp': 'bd27c68a50ed850f7d431ecf017e71b3937915cb1f2db99c853a4a33c2edc824',
    'switch/lifted.c': 'bb3708539e425085333ddc2001e95e563493af57e596131695f7359da2428a46',
    'input.bin': '77c97165cacbc2c712aca464bdd5dd2665699e453b0ced5c570a8ce3c267f9ad',
    'reference.json': 'c98ca26337ba28a003f6b419490824950ebfb3ef50c42cb7d76c994e0c05f39a',
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def audit(fixture):
    for name, sha in PINS.items():
        if digest(fixture/name) != sha:
            raise ValueError('private fixture pin mismatch: '+name)
    if (fixture/'transport.cpp').read_text().count((fixture/'switch/lifted.c').read_text()) != 1:
        raise ValueError('lift is not verbatim in transport')


def check_elf(binary):
    header = binary.read_bytes()[:20]
    if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != 183:
        raise ValueError('not little-endian ELF64 AArch64')


def check_static_tls(binary):
    """Check the actual ELF program header, not section/page alignment claims."""
    check_elf(binary)
    data = binary.read_bytes()
    if len(data) < 64:
        raise ValueError('truncated ELF header')
    offset = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    if size != 56 or not count or offset < 64 or offset + size * count > len(data):
        raise ValueError('invalid ELF program header table')
    tls = []
    for index in range(count):
        entry = struct.unpack_from('<IIQQQQQQ', data, offset + index * size)
        if entry[0] == 7:  # PT_TLS
            tls.append(entry)
    if len(tls) != 1:
        raise ValueError('expected exactly one PT_TLS segment')
    _, _, file_offset, address, _, file_size, memory_size, alignment = tls[0]
    if (alignment < 64 or alignment & (alignment - 1) or
            address % alignment != file_offset % alignment or
            memory_size < file_size or file_offset + file_size > len(data)):
        raise ValueError('invalid or underaligned Bionic static TLS segment')
    return alignment


def commands(ndk, fixture, output):
    compiler = ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++'
    build = output/'core'
    return [
        ('configure', ['cmake', '-S', ROOT, '-B', build, '-G', 'Ninja',
            '-DCMAKE_TOOLCHAIN_FILE='+str(ndk/'build/cmake/android.toolchain.cmake'),
            '-DANDROID_ABI=arm64-v8a', '-DANDROID_PLATFORM=android-26',
            '-DANDROID_STL=c++_static', '-DCMAKE_BUILD_TYPE=Debug',
            '-DCMAKE_MAKE_PROGRAM='+str(shutil.which('ninja'))]),
        ('core-build', ['cmake', '--build', build, '--target', 'ts2_core', '-j4']),
        ('fixture-link', [compiler, '-std=c++20', '-static', '-O0',
            '-I'+str(ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'),
            '-I'+str(ROOT/'native/include'), fixture/'transport.cpp', fixture/'valid.cpp',
            build/'libts2_core.a', ROOT/'scripts/recomp/ndk_static_tls.S',
            '-lm', '-o', output/'leaf-ndk']),
    ]


def run(ndk, fixture, output, execute=False):
    output = output.resolve()
    if not output.is_relative_to(ROOT/'work') or output.exists():
        raise ValueError('use a new private work/ output directory')
    audit(fixture)
    if 'Pkg.Revision = 27.2.12479018' not in (ndk/'source.properties').read_text():
        raise ValueError('wrong NDK revision')
    runtime_header = ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32/recomp_types.h'
    if digest(runtime_header) != '1ab5b031e600cbfbc97649e3958b45014de99e812addb165728fdf2c90508cf9':
        raise ValueError('pcrecomp runtime header pin mismatch')
    compiler = ndk/'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++'
    version = subprocess.run([str(compiler), '--version'], capture_output=True, check=True, timeout=20)
    output.mkdir(parents=True)
    result = dict(compiler_version=version.stdout.decode(), compiler_sha256=digest(compiler),
        runtime_header_sha256=digest(runtime_header), schema='ts2-ndk-fixture/1', rva='0x9550', reused_fixture_pins=PINS,
        compiled_linked=False, ndk_bionic_qemu=False, android_executed=False,
        commands=[], limits='Compile/link only unless QEMU explicitly requested; no Android, APK, new lift, new x86 reference or game binding.')
    try:
        stages = commands(ndk, fixture, output)
        if execute:
            stages.append(('ndk_bionic_qemu', [ROOT/'scripts/campaign/arm64-run.sh', output/'leaf-ndk']))
        for name, argv in stages:
            start = time.monotonic()
            proc = subprocess.run(list(map(str, argv)), input=(fixture/'input.bin').read_bytes()
                if name == 'ndk_bionic_qemu' else None, capture_output=True, timeout=180)
            (output/(name+'.stdout')).write_bytes(proc.stdout)
            (output/(name+'.stderr')).write_bytes(proc.stderr)
            result['commands'].append(dict(stage=name, argv=list(map(str, argv)),
                exit=proc.returncode, seconds=time.monotonic()-start))
            if proc.returncode:
                raise RuntimeError('NDK stage failed: '+name)
            if name == 'fixture-link':
                check_elf(output/'leaf-ndk')
                alignment = check_static_tls(output/'leaf-ndk')
                result.update(compiled_linked=True, binary_sha256=digest(output/'leaf-ndk'),
                    static_tls_alignment=alignment,
                    static_tls_source_sha256=digest(ROOT/'scripts/recomp/ndk_static_tls.S'))
            if name == 'ndk_bionic_qemu':
                sys.path.insert(0, str(Path(__file__).parent))
                from execute_cache_dispatch import compare
                compare(proc.stdout.decode(), json.loads((fixture/'reference.json').read_text()))
                result.update(ndk_bionic_qemu=True, matched_cases=64,
                    compared=['eight GPRs', 'six complete pages'])
        audit(fixture)
    except Exception as exc:
        result['failure'] = str(exc)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ndk', type=Path, required=True)
    p.add_argument('--fixture', type=Path, default=ROOT/'work/recomp-bench/leaf-d1')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--run-qemu', action='store_true')
    a = p.parse_args()
    r = run(a.ndk.resolve(), a.fixture.resolve(), a.output, a.run_qemu)
    print('NDK compile/link:', r['compiled_linked'], 'ndk_bionic_qemu:', r['ndk_bionic_qemu'], 'Android: false')
