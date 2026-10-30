#!/usr/bin/env python3
"""Execute the unchanged whole resolver lift, with hot-only memory and no services."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_encoded_resolver import ROOT, IMAGE_SHA, RVA, SIZE, digest, require
from execute_storage_selector import strict_object

TEMPLATE = Path(__file__).with_name('resolver_transport.c.in')


def assemble(body):
    require(type(body) is str and bool(body.strip()))
    template = TEMPLATE.read_text()
    require(template.count('\n@BODY@\n') == 1)
    result = template.replace('\n@BODY@\n', '\n'+body+'\n')
    require(result.count(body) == 1)
    return result


def cases():
    # Preserve the earlier eight-cookie suite and add every missing rotate count.
    cookies = list(dict.fromkeys([0, 1, 31, 32, 33, 0x80000000, 0x12345678,
                                 0xFFFFFFFF, *range(32)]))
    for cookie in cookies:
        for value in (1, 2, 0x7FFFFFFF, 0x80000000, 0xC7000020, 0xFFFFFFFF):
            for index in (0, 33, 63):
                for salt in (0, 7):
                    yield cookie, value, index, salt


def reference(code=None):
    sys.path.insert(0, str(ROOT/'tools'))
    import encoded_cache_probe as hot
    from unicorn import UcError
    data, expected = bytearray(), []
    for n, (cookie, value, index, salt) in enumerate(cases()):
        wanted = hot.oracle(value, cookie, index, salt)
        if code is not None:
            hot.r.verify(hot.exercise(code, cookie, hot.encode(value, cookie), index, salt), wanted)
        regs, stack = hot.inputs(index, salt)
        data.extend(struct.pack('<11I', *regs, cookie, hot.encode(value, cookie), index))
        data.extend(stack)
        expected.append(dict(case=n, registers=wanted['registers'], stack=wanted['stack'].hex()))
    # Encoded null is unresolved, never a successful cached-null response.
    for cookie in (0, 31, 0x12345678, 0xFFFFFFFF):
        if code is not None:
            try:
                hot.exercise(code, cookie, hot.encode(0, cookie))
            except (ValueError, UcError):
                pass
            else:
                raise ValueError('cold reference unexpectedly returned')
        regs, stack = hot.inputs(33, 0)
        data.extend(struct.pack('<11I', *regs, cookie, hot.encode(0, cookie), 33))
        data.extend(stack)
        expected.append(dict(case=len(expected), rejected=True))
    require(len(expected) == 1336)
    return bytes(data), expected


def compare(text, expected):
    rows = [json.loads(line, object_pairs_hook=strict_object) for line in text.splitlines()]
    require(len(rows) == len(expected) == 1336)
    for n, (actual, wanted) in enumerate(zip(rows, expected)):
        require(type(actual) is dict and type(actual.get('case')) is int and actual['case'] == n)
        if 'rejected' in wanted:
            require(set(actual) == {'case', 'rejected'} and actual['rejected'] is True)
        else:
            require(set(actual) == {'case', 'registers', 'stack'})
            require(type(actual['registers']) is list and len(actual['registers']) == 8 and
                    all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in actual['registers']))
            require(type(actual['stack']) is str and len(actual['stack']) == 8192)
        require(actual == wanted)
    return dict(cases=1332, matched=1332, cold_rejections=4)


def run(output, index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-encoded-resolver-native/1', rva=hex(RVA), success=False,
        selected=True, attempted=False, lifted=False, compiled_for_aarch64=False,
        matched_x86_reference=False, executed_under_qemu=False, android_executed=False,
        linked_isas=[], commands=[], runs={}, timings={},
        invocation=[sys.executable, *sys.argv], harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE),
        compared=['eight final GPRs', 'entire 4096-byte stack', 'immutable cookie/cache pages'],
        limits=['whole unchanged generated body; hot-only exact word data access; every external call rejects',
                'native flags/PC/RET target/FP/SIMD/SEH/transient writes NOT compared',
                'no selector composition, cold dependency behavior, Windows service or runtime binding',
                'synthetic isolated memory, NOT GuestMemory/image/Android/startup integration'])

    def command(name, argv, data=None, expected=0):
        record = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(record)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            p = subprocess.run(record['argv'], input=data, cwd=ROOT, stdout=out, stderr=err, timeout=120)
        record.update(exit_code=p.returncode, seconds=time.monotonic()-start)
        require(p.returncode == expected)

    stage = 'lift'
    try:
        row['attempted'] = True
        command('lift', [sys.executable, ROOT/'scripts/recomp/measure_encoded_resolver.py',
            '--index', index, '--output', output/'lift'], expected=2)
        lift = json.loads((output/'lift/metrics.jsonl').read_text()); row['lift'] = lift
        require(lift['lifted'] and lift['compiled_for_aarch64'])
        body = output/'lift/lifted.c'; require(digest(body) == lift['lifted_sha256'])
        row.update(lifted=True, compiled_for_aarch64=True, lifted_sha256=digest(body))
        (output/'transport.c').write_text(assemble(body.read_text()))
        stage = 'reference'; start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == 0xA0000000 and pe.FILE_HEADER.Machine == 0x14C)
        code = pe.get_data(RVA, SIZE); require(len(code) == SIZE)
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
            argv = [binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary]
            command(stage, argv, inputs)
            if isa == 'arm64': row['executed_under_qemu'] = True
            stage = isa+'-compare'; start = time.monotonic()
            row['runs'][isa] = compare((output/(isa+'-execute.stdout')).read_text(), expected)
            row['timings'][isa+'_comparison'] = time.monotonic()-start
            row['runs'][isa]['invalid_input_rejections'] = 0
            for label, word, value in (('stack', 7, 0xB8000000), ('index', 10, 64), ('frame', 10, 1)):
                bad = bytearray(inputs); struct.pack_into('<I', bad, word*4, value)
                stage = isa+'-reject-'+label; command(stage, argv, bytes(bad))
                rows = (output/(stage+'.stdout')).read_text().splitlines()
                require(len(rows) == len(expected) and json.loads(rows[0]) == dict(case=0, rejected=True))
                compare('\n'.join([json.dumps(expected[0]), *rows[1:]]), expected)
                row['runs'][isa]['invalid_input_rejections'] += 1
        stage = 'audit'
        require((output/'host-execute.stdout').read_bytes() == (output/'arm64-execute.stdout').read_bytes())
        audit = dict(image_unchanged=digest(image) == IMAGE_SHA,
            body_unchanged=digest(body) == row['lifted_sha256'],
            body_inserted_once=(output/'transport.c').read_text().count(body.read_text()) == 1,
            source_exact=(output/'transport.c').read_text() == assemble(body.read_text()),
            template_unchanged=digest(TEMPLATE) == row['template_sha256'])
        (output/'source-audit.json').write_text(json.dumps(audit))
        require(all(audit.values()))
        row.update(success=True, matched_x86_reference=True)
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True); ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        run(args.output, args.index)
    except Exception:
        print('Resolver native comparison failed; inspect private metrics', file=sys.stderr); return 1
    print('Whole resolver hot path matched host and Linux AArch64/QEMU; NOT cold/Windows/Android/startup')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
