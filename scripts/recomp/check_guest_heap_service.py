#!/usr/bin/env python3
"""Exercise the authored portable heap and rejecting controls; NOT a game lift.

--arm64 requires the documented Zig C++ wrapper and Linux/QEMU runner.
All three variants must compile and execute per ISA. Compiler/run failures are
not accepted as successful negative controls. Outputs go to a NEW work/ folder.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT/'native/src/guest_heap.cpp'


def variants(source):
    changes = {
        'wrong-cleanup': ('r.esp=sp+16;', 'r.esp=sp+12;'),
        'lost-zero': ('if (flags==8) {', 'if (false) {'),
    }
    out = {'valid': source}
    for mode, (before, after) in changes.items():
        if source.count(before) != 1:
            raise ValueError(f'{mode}: mutation anchor changed')
        out[mode] = source.replace(before, after)
    return out


def accepted(mode, returncode, stdout, stderr):
    if mode == 'valid':
        return returncode == 0 and '4000 model operations' in stdout and not stderr
    errors = {'wrong-cleanup': 'r.eax==base && r.esp==stack+32',
              'lost-zero': 'm.read32(p)==0'}
    # The C++ fixture returns 1 for failed CHECKs, not a signal or runner failure.
    return returncode == 1 and stderr.strip() == errors[mode] and not stdout


def run(output, compiler, arm64=False):
    output = output.resolve()
    if not output.is_relative_to(ROOT/'work'):
        raise ValueError('Output must be a new directory under work/')
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    rows = []
    for mode, source in variants(SOURCE.read_text()).items():
        path = output/f'{mode}.cpp'
        path.write_text(source)
        for isa in (('host', 'aarch64_linux_qemu') if arm64 else ('host',)):
            binary = output/f'{mode}-{isa}'
            command = [compiler, '-std=c++20', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
                       '-I', str(ROOT/'native/include'), str(path),
                       str(ROOT/'native/src/guest_memory.cpp'),
                       str(ROOT/'native/src/guest_dispatch.cpp'),
                       str(ROOT/'tests/guest_heap_tests.cpp'), '-o', str(binary)]
            if isa != 'host':
                command[1:1] = ['-target', 'aarch64-linux-musl', '-static']
            row = dict(mode=mode, isa=isa, compile_command=command)
            build = subprocess.run(command, capture_output=True, text=True, timeout=120)
            (output/f'{mode}-{isa}-compile.stderr').write_text(build.stderr)
            row['compile_exit'] = build.returncode
            if build.returncode:
                raise RuntimeError(f'{mode}/{isa}: compile failed (see private log)')
            command = ([str(ROOT/'scripts/campaign/arm64-run.sh')] if isa != 'host' else []) + [str(binary)]
            executed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            (output/f'{mode}-{isa}-run.stdout').write_text(executed.stdout)
            (output/f'{mode}-{isa}-run.stderr').write_text(executed.stderr)
            row.update(execute_command=command, execute_exit=executed.returncode,
                       expected_observed=accepted(mode, executed.returncode, executed.stdout, executed.stderr))
            rows.append(row)
    result = dict(schema='ts2-portable-guest-heap-check/1', rows=rows,
                  passed=all(row['expected_observed'] for row in rows),
                  android_executed=False, original_code_executed=False,
                  seconds=time.monotonic()-started,
                  limits=['Authored portable policy and integer ABI, not Windows heap internals',
                          'No original allocator execution, IAT/global initialization or game integration'])
    (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', default='c++')
    parser.add_argument('--arm64', action='store_true')
    args = parser.parse_args()
    result = run(args.output, args.compiler, args.arm64)
    print(json.dumps(dict(passed=result['passed'], seconds=result['seconds'], rows=len(result['rows']))))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
