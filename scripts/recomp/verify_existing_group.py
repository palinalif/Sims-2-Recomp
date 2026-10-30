#!/usr/bin/env python3
"""Build the pinned existing lift for both ISAs; compare saved x86 states.

No new lifting or x86 execution. Private source, stdout and command logs remain
under a NEW work/recomp-bench directory. Linux/QEMU is not Android/hardware.
Source bodies and input cases are adapted by the existing pinned preparer only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from prepare_private_readonly_dispatch import prepare, SOURCE_SHA, REFERENCE_SHA
from check_private_readonly_dispatch import check
from fetch_pcrecomp import verify

IMAGE_SHA = '63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_complete(runs):
    """Never publish an execution claim from compilation or a partial run."""
    if set(runs) != {'host', 'arm64'}:
        raise ValueError('Both ISAs required')
    for isa, run in runs.items():
        if run['exit_code'] != 0 or run['matched'] != 96 or not run['executed']:
            raise ValueError('Incomplete execution/comparison: ' + isa)
    if runs['host']['stdout_sha256'] != runs['arm64']['stdout_sha256']:
        raise ValueError('Cross-ISA transport differs')


def image_source(text):
    """Adapt only the already pinned preparer's boundary, never lifted bodies."""
    edits = {'#include "readonly_dispatch_bridge.h"': '#include "image_dispatch.h"',
             'ts2_bridge_read32(': 'ts2_image_read32(',
             'ts2_read_dispatch(': 'ts2_image_dispatch('}
    for old, new in edits.items():
        if text.count(old) != 1:
            raise ValueError('Unexpected prepared image seam')
        text = text.replace(old, new)
    return text


def run(output, image_memory=False):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Output must be under work/recomp-bench')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    records = []
    report = {'schema': 'ts2-existing-group-benchmark/1', 'success': False,
              'arm64_executed': False, 'android_executed': False,
              'fresh_lift': False, 'fresh_x86_reference': False, 'runs': {},
              'persistent_image_memory': image_memory}

    def command(name, argv, stdout=None, allow_failure=False):
        start = time.monotonic()
        with (output / (name + '.stderr')).open('xb') as err, \
             (output / (stdout or name + '.stdout')).open('xb') as out:
            result = subprocess.run([str(a) for a in argv], cwd=ROOT,
                                    stdout=out, stderr=err, timeout=180)
        records.append({'name': name, 'argv': [str(a) for a in argv],
                        'seconds': time.monotonic() - start,
                        'exit_code': result.returncode})
        if result.returncode and not allow_failure:
            raise ValueError('Command failed: ' + name)
        return result.returncode

    try:
        fixture = ROOT / 'work/interop-legacy-002'
        if digest(fixture / 'analysis-image.bin') != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        reference = fixture / 'group-bundle/reference.json'
        if digest(reference) != REFERENCE_SHA:
            raise ValueError('Reference pin mismatch')
        # Pins the existing generated artifact; does not replace lifted bodies.
        prepare(fixture / 'group.c', output / 'group.c')
        if image_memory:
            adapted = image_source((output / 'group.c').read_text())
            with (output / 'image-group.c').open('x') as stream:
                (output / 'image-group.c').chmod(0o600)
                stream.write(adapted)
            report['image_adapted_source_sha256'] = digest(output / 'image-group.c')
            report['image_adapter_sha256'] = digest(ROOT / 'scripts/recomp/image_dispatch.cpp')
        report.update({'image_sha256': IMAGE_SHA, 'source_sha256': SOURCE_SHA,
                       'reference_sha256': REFERENCE_SHA,
                       'adapted_source_sha256': digest(output / 'group.c'),
                       'rvas': ['0x1240', '0x1250', '0x1270']})
        upstream = ROOT / 'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(upstream)  # Existing reviewed-file pins; never fetch or patch.
        report['pcrecomp_revision'] = 'c0cbd3e3653010782b17e8a87b58953608ea411c'
        for isa in ('host', 'arm64'):
            build = ROOT / 'build' / isa
            command(isa + '-build', ['cmake', '--build', build, '-j4'])
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
            obj, exe = output / (isa + '.o'), output / (isa + '-private')
            command(isa + '-compile', ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L',
                    '-std=c11', '-O0', '-I' + str(ROOT / 'tools'),
                    '-I' + str(ROOT / 'scripts/recomp'),
                    '-I' + str(upstream / 'runtime/recomp32'),
                    *(['-Dmain=fixture_main'] if image_memory else []),
                    '-c', output / ('image-group.c' if image_memory else 'group.c'), '-o', obj])
            extra = [build / 'libts2_readonly_dispatch_bridge.a']
            if image_memory:
                image_obj = output / (isa + '-image.o')
                command(isa + '-image-compile', ['zig-cxx', *opts, '-std=c++20', '-O0',
                        '-I' + str(ROOT / 'native/include'), '-I' + str(ROOT / 'tools'),
                        '-c', ROOT / 'scripts/recomp/image_dispatch.cpp', '-o', image_obj])
                extra = [image_obj]  # Old copying bridge is deliberately NOT linked.
            command(isa + '-link', ['zig-cxx', *opts, obj, *extra,
                    build / 'libts2_core.a', '-lm', '-o', exe])
            # Check ISA independently, before trusting the runner's output.
            header = exe.read_bytes()[:20]
            machine = 62 if isa == 'host' else 183
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
                raise ValueError('Wrong ELF ISA')
            argv = [exe] if isa == 'host' else [ROOT / 'scripts/campaign/arm64-run.sh', exe]
            if image_memory:
                argv.append(fixture / 'analysis-image.bin')
            code = command(isa + '-execute', argv, isa + '.txt', allow_failure=image_memory)
            if code:
                reason = (output / (isa + '-execute.stderr')).read_text()
                overlap = 'Image input span overlaps mapped image; rejected before copy/dispatch' in reason
                report['runs'][isa] = {'executed': True, 'exit_code': code, 'matched': 0,
                    'rejected_before_dispatch': overlap,
                    'rejection': 'image_input_overlap' if overlap else 'execution_failed',
                    'comparison_seconds': None, 'binary_sha256': digest(exe),
                    'stdout_sha256': digest(output / (isa + '.txt'))}
                continue  # Record BOTH ISA failures, never compare a partial stream.
            start = time.monotonic()
            matched = check(reference, output / (isa + '.txt'))
            report['runs'][isa] = {'executed': True, 'exit_code': code,
                'matched': matched, 'comparison_seconds': time.monotonic() - start,
                'binary_sha256': digest(exe),
                'stdout_sha256': digest(output / (isa + '.txt'))}
        if digest(fixture / 'analysis-image.bin') != IMAGE_SHA:
            raise ValueError('Image changed during experiment')
        report['image_unchanged'] = True
        require_complete(report['runs'])
        report.update(success=True, arm64_executed=True)
    finally:
        report['commands'] = records
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image-memory', action='store_true',
                        help='Invoke on one persistent GuestImage memory per ISA process')
    args = parser.parse_args()
    try:
        result = run(args.output, image_memory=args.image_memory)
    except (OSError, ValueError, subprocess.TimeoutExpired, KeyError, TypeError):
        parser.exit(1, 'Existing-group verification failed; inspect private output.\n')
    print('Saved x86 comparison: host 96/96; AArch64 Linux/QEMU 96/96; Android untested')
    return 0 if result['success'] else 1


if __name__ == '__main__':
    sys.exit(main())
