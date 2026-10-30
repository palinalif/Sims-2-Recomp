#!/usr/bin/env python3
"""Compare one unchanged helper lift with composed nonzero-FS x86 frames.

Development only. Caller prefix is executed by x86, NOT translated; native input
is its independently checked post-CALL frame. Native RET target/flags/SEH omitted.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_startup_dependency import (require, exercise, caller_plan, GPRS,
    STACK, MASK, ENTRY, DEPENDENCY, inspect_body, crosscheck_index, ROOT,
    IMAGE_SHA, digest, BASE)
from inspect_startup_dependency import first_direct_call, CALLER_BOUND
from measure_startup import TAIL_RVA

TEMPLATE = Path(__file__).with_name('frame_transport.c.in')


def assemble(body):
    require(isinstance(body, str) and bool(body.strip()))
    template = TEMPLATE.read_text()
    require(template.count('\n@BODY@\n') == 1)
    result = template.replace('\n@BODY@\n', '\n'+body+'\n')
    require(result.count(body) == 1)
    return result


def compare(text, expected):
    records = [json.loads(line) for line in text.splitlines()]
    require(len(records) == len(expected) == 64)
    matched, rejected, mismatches = 0, 0, []
    for n, (actual, wanted) in enumerate(zip(records, expected)):
        require(type(actual) is dict and type(actual.get('case')) is int and actual['case'] == n)
        if set(actual) == {'case', 'rejected'}:
            require(actual['rejected'] == 'memory-contract')
            rejected += 1
            continue
        require(set(actual) == {'case', 'regs', 'stack', 'fs', 'cookie'})
        require(type(actual['regs']) is list and len(actual['regs']) == 8 and
                all(type(v) is int and 0 <= v <= MASK for v in actual['regs']))
        for key in ('stack', 'fs', 'cookie'):
            require(isinstance(actual[key], str) and len(actual[key]) == 8192)
            actual[key] = bytes.fromhex(actual[key])
        if actual == wanted:
            matched += 1
        else:
            mismatches.append(n)
    return dict(cases=64, matched=matched, rejected=rejected,
                mismatched_cases=mismatches, verified=matched == 64)


def reference(index):
    image = ROOT/'work/interop-legacy-002/analysis-image.bin'
    require(digest(image) == IMAGE_SHA)
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
    caller = pe.get_data(TAIL_RVA, CALLER_BOUND)
    require(len(caller) == CALLER_BOUND)
    site, target = first_direct_call(caller, BASE+TAIL_RVA)
    require(target == ENTRY)
    prefix = caller[:site-(BASE+TAIL_RVA)+5]
    helper = pe.get_data(DEPENDENCY, 128)
    body = inspect_body(helper, ENTRY)
    indexed = crosscheck_index(json.loads(index.read_text()), body)
    code = helper[:body['size_bytes']]
    rng = random.Random(11818721)
    inputs, expected = bytearray(), []
    for n in range(64):
        regs = {r: rng.getrandbits(32) for r in GPRS}
        regs['esp'] = STACK+(0x800, 0xC00)[(n//2) % 2]
        stack = bytearray([0xA5]*4096)
        struct.pack_into('<I', stack, regs['esp']-STACK, 0x71000000)
        fs = (0x74000000, 0x75000000)[n % 2]
        chain = (MASK, 0x76000100)[(n//4) % 2]
        cookie = (0, MASK, 0xBB40E64E, 0x12345678)[(n//8) % 4]
        state = exercise(code, regs, stack, fs, chain, cookie,
                         prefix=prefix, prefix_entry=BASE+TAIL_RVA)
        require(state.pc == BASE+TAIL_RVA+len(prefix))
        # Caller oracle and x86 rig already agree after EVERY prefix instruction.
        pre = caller_plan(prefix, BASE+TAIL_RVA, ENTRY, regs, stack)[-1]
        inputs.extend(struct.pack('<11I', *(pre[2][r] for r in GPRS), fs, chain, cookie))
        inputs.extend(pre[4])
        expected.append(dict(case=n, regs=[state.regs[r] for r in GPRS],
            stack=bytes(state.pages[STACK]), fs=bytes(state.pages[fs]),
            cookie=bytes(state.pages[(BASE+0x104F540) & ~4095])))
    require(digest(image) == IMAGE_SHA)
    return bytes(inputs), expected, indexed


def run(output, index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-frame-native/1', success=False, rva=hex(DEPENDENCY),
        android_executed=False, continuation_executed=False,
        matched_x86_reference=False, executed_under_qemu=False, commands=[], runs={},
        timings={}, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), template_sha256=digest(TEMPLATE),
        compared=['eight GPRs', 'full stack/FS/cookie pages'],
        limits=['native final-state only; no native PC/RET target or flags/FP/SIMD',
                'caller prefix reference only, NOT translated or natively executed',
                'helper model/guard share Capstone; synthetic caller/page slack',
                'checked lvalue memory is not access-mode isolation or sandboxing',
                'no SEH dispatch/unwind, Windows services, GuestMemory integration or startup'])

    def command(name, argv, stdin=None, expected=0):
        record = dict(name=name, argv=[str(a) for a in argv], exit_code=None)
        row['commands'].append(record)
        start = time.monotonic()
        try:
            with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
                p = subprocess.run(record['argv'], cwd=ROOT, input=stdin,
                                   stdout=out, stderr=err, timeout=120)
            record['exit_code'] = p.returncode
            require(p.returncode == expected)
        finally:
            record['seconds'] = time.monotonic()-start

    stage = 'reference'
    try:
        start = time.monotonic()
        inputs, expected, indexed = reference(index)
        row['timings']['reference'] = time.monotonic()-start
        row['index'] = indexed
        (output/'input.bin').write_bytes(inputs)
        (output/'reference.json').write_text(json.dumps([
            {k: v.hex() if isinstance(v, bytes) else v for k, v in s.items()} for s in expected]))
        row['reference_sha256'] = digest(output/'reference.json')
        stage = 'lift'
        command('lift', [sys.executable, ROOT/'scripts/recomp/measure_startup.py',
            '--rva', format(DEPENDENCY, 'X'), '--output', output/'lift'], expected=2)
        metrics = json.loads((output/'lift/metrics.jsonl').read_text())
        require(metrics['lifted'] and metrics['compiled_for_aarch64'])
        row['lift'] = metrics
        body_path = output/'lift/lifted.c'
        require(digest(body_path) == metrics['lifted_sha256'])
        (output/'transport.c').write_text(assemble(body_path.read_text()))
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        for isa in ('host', 'arm64'):
            stage = isa+'-compile'
            binary = output/isa
            command(stage, ['zig-cc', *([] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']),
                '-D_POSIX_C_SOURCE=200809L', '-std=c11', '-O0', '-Werror=implicit-function-declaration',
                '-I'+str(upstream/'runtime/recomp32'), output/'transport.c', '-o', binary])
            header = binary.read_bytes()[:20]
            require(header[:6] == b'\x7fELF\x02\x01' and
                    int.from_bytes(header[18:20], 'little') == (62 if isa == 'host' else 183))
            stage = isa+'-execute'
            command(stage, ([binary] if isa == 'host' else [ROOT/'scripts/campaign/arm64-run.sh', binary]), stdin=inputs)
            stdout = output/(stage+'.stdout')
            stage = isa+'-comparison'
            start = time.monotonic()
            row['runs'][isa] = compare(stdout.read_text(), expected)
            row['runs'][isa]['comparison_seconds'] = time.monotonic()-start
            row['runs'][isa]['compiled'] = True
            row['runs'][isa]['executed'] = True
            row['runs'][isa]['binary_sha256'] = digest(binary)
        stage = 'final-verification'
        require(digest(ROOT/'work/interop-legacy-002/analysis-image.bin') == IMAGE_SHA)
        row['native_streams_equal'] = (output/'host-execute.stdout').read_bytes() == (output/'arm64-execute.stdout').read_bytes()
        require(row['native_streams_equal'] and all(r['verified'] for r in row['runs'].values()))
        row['matched_x86_reference'] = True
        row['executed_under_qemu'] = True
        row['success'] = True
    except Exception as exc:
        row['failed_stage'], row['error_type'] = stage, type(exc).__name__
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--index', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.output, args.index)
    except Exception:
        print('Frame comparison failed; inspect private results; no verification claimed', file=sys.stderr)
        return 1
    print('Helper final frame matched on host and Linux AArch64/QEMU; NOT startup/SEH')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
