#!/usr/bin/env python3
"""Execute the unchanged pinned selector lift with explicit authored endpoints.

Development-only transport. No resolver body, Windows services or runtime binding.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_storage_selector import ROOT, IMAGE_SHA, RVA, SIZE, digest, require

TEMPLATE = Path(__file__).with_name('selector_transport.c.in')


def assemble(body):
    require(type(body) is str and bool(body.strip()))
    template = TEMPLATE.read_text()
    require(template.count('\n@BODY@\n') == 1)
    result = template.replace('\n@BODY@\n', '\n'+body+'\n')
    require(result.count(body) == 1)
    return result


def cases():
    # Reuse the existing opaque-resolver selector ABI contract, not hot-resolver
    # composition (which has different ECX/EDX and scratch-stack effects).
    sys.path.insert(0, str(ROOT/'tools'))
    import ptd_query_probe as q
    for target in (0, q.FLS):
        for result in (0, 1, 0x80000000, 0xFFFFFFFF):
            for index in (0, 1, 0x80000000, 0xFFFFFFFF):
                for salt in range(4):
                    for clobber in (False, True):
                        yield q, target, result, index, salt, clobber


def reference(code=None):
    data, expected = bytearray(), []
    for n, (q, target, result, index, salt, clobber) in enumerate(cases()):
        wanted = q.oracle(target, result, index, salt, clobber=clobber)
        if code is not None:
            q.r.verify(q.exercise(code, target, result, index, salt, clobber=clobber), wanted)
        regs, stack = q.free.inputs(index, salt)
        data.extend(struct.pack('<11I', *regs, target, result, clobber))
        data.extend(stack)
        expected.append(dict(case=n, registers=wanted['registers'], stack=wanted['stack'].hex(),
            events=json.loads(json.dumps(wanted['events']))))
    require(len(expected) == 256)
    return bytes(data), expected


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def compare(text, expected):
    rows = [json.loads(line, object_pairs_hook=strict_object) for line in text.splitlines()]
    require(len(rows) == len(expected) == 256)
    for n, (actual, wanted) in enumerate(zip(rows, expected)):
        require(type(actual) is dict and set(actual) == {'case', 'registers', 'stack', 'events'})
        require(type(actual['case']) is int and actual['case'] == n)
        require(type(actual['registers']) is list and len(actual['registers']) == 8 and
                all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in actual['registers']))
        require(type(actual['stack']) is str and len(actual['stack']) == 8192)
        require(type(actual['events']) is list and len(actual['events']) in (2, 3))
        for event in actual['events']:
            require(type(event) is list and len(event) == 5 and type(event[0]) is str and
                    type(event[1]) is list and all(type(v) is int and 0 <= v <= 0xFFFFFFFF
                    for v in event[1]+event[2:]))
        require(actual == wanted)
    return dict(cases=256, matched=256)


def run(output, index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-storage-selector-native/1', rva=hex(RVA), success=False,
        selected=True, attempted=False, lifted=False, compiled_for_aarch64=False,
        matched_x86_reference=False, executed_under_qemu=False, android_executed=False,
        linked_isas=[], commands=[], runs={}, timings={},
        invocation=[sys.executable, *sys.argv], harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE),
        compared=['eight caller GPRs', 'entire 4096-byte stack', 'ordered endpoint arguments/return RVAs/SP/ECX'],
        limits=['authored resolver/guard/storage endpoints, NOT actual resolver or Windows services',
                'site-specific CALL return macros; unchanged generated body; bounded selector only',
                'no native flags/PC/FP/SIMD/SEH/transient-write or full endpoint CPU comparison',
                'stack and explicit synthetic slot page only, no image/GuestMemory/runtime integration',
                'no cold storage, ownership/lifecycle/races/reentry, Android or game startup'])

    def command(name, argv, data=None, expected=0):
        record = dict(name=name, argv=[str(a) for a in argv])
        row['commands'].append(record)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            p = subprocess.run(record['argv'], input=data, cwd=ROOT, stdout=out, stderr=err, timeout=120)
        record.update(exit_code=p.returncode, seconds=time.monotonic()-start)
        require(p.returncode == expected)

    stage = 'lift'
    try:
        row['attempted'] = True
        command('lift', [sys.executable, ROOT/'scripts/recomp/measure_storage_selector.py',
            '--index', index, '--output', output/'lift'], expected=2)
        lift = json.loads((output/'lift/metrics.jsonl').read_text())
        row['lift'] = lift
        require(lift['lifted'] and lift['compiled_for_aarch64'])
        body = output/'lift/lifted.c'
        require(digest(body) == lift['lifted_sha256'])
        row.update(lifted=True, compiled_for_aarch64=True, lifted_sha256=digest(body))
        (output/'transport.c').write_text(assemble(body.read_text()))
        stage = 'reference'; start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == 0xA0000000 and pe.FILE_HEADER.Machine == 0x14C)
        code = pe.get_data(RVA, SIZE)
        require(len(code) == SIZE)
        inputs, expected = reference(code)
        row['timings']['reference'] = time.monotonic()-start
        (output/'input.bin').write_bytes(inputs)
        (output/'reference.json').write_text(json.dumps(expected))
        row['reference_sha256'] = digest(output/'reference.json')
        upstream = ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'
        for isa in ('host', 'arm64'):
            stage = isa+'-compile'; binary = output/isa
            command(stage, ['zig-cc', *([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream), output/'transport.c','-o', binary])
            h = binary.read_bytes()[:20]
            require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
            row['linked_isas'].append(isa)
            row.setdefault('binary_sha256', {})[isa] = digest(binary)
            stage = isa+'-execute'
            command(stage, [binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary], inputs)
            if isa == 'arm64': row['executed_under_qemu'] = True
            stage = isa+'-compare'; start = time.monotonic()
            row['runs'][isa] = compare((output/(isa+'-execute.stdout')).read_text(), expected)
            row['timings'][isa+'_comparison'] = time.monotonic()-start
            # Rejections are observed native executions, not skipped cases or a
            # reference that agrees with itself. Subsequent cases must recover.
            row['runs'][isa]['invalid_input_rejections'] = 0
            for label, word, value in (('stack', 7, 0xB8000000), ('target', 8, 123), ('clobber', 10, 2)):
                bad = bytearray(inputs)
                struct.pack_into('<I', bad, word*4, value)
                stage = isa+'-reject-'+label
                command(stage, [binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary], bytes(bad))
                rows = (output/(stage+'.stdout')).read_text().splitlines()
                require(len(rows) == 256 and json.loads(rows[0]) == dict(case=0, rejected=True))
                # The rejected first case must not leak into the next 255.
                compare('\n'.join([json.dumps(expected[0]), *rows[1:]]), expected)
                row['runs'][isa]['invalid_input_rejections'] += 1
        stage = 'audit'
        require((output/'host-execute.stdout').read_bytes() == (output/'arm64-execute.stdout').read_bytes())
        require(digest(image) == IMAGE_SHA and digest(body) == row['lifted_sha256'])
        row.update(success=True, matched_x86_reference=True)
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        run(args.output, args.index)
    except Exception:
        print('Selector native comparison failed; inspect private metrics', file=sys.stderr)
        return 1
    print('Selector matched 256 host and Linux AArch64/QEMU frames; NOT Windows/Android/startup')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
