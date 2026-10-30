#!/usr/bin/env python3
"""Compare two unchanged original lifts in one hot frame; development only."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_encoded_resolver import ROOT, IMAGE_SHA, digest, require
from execute_storage_selector import strict_object

TEMPLATE = Path(__file__).with_name('storage_composed_transport.c.in')
sys.path.insert(0, str(ROOT/'tools'))
import storage_hot_composed_probe as oracle


def assemble(selector, resolver):
    require(all(type(body) is str and bool(body.strip()) for body in (selector, resolver)))
    source = TEMPLATE.read_text()
    for marker, body in (('@SELECTOR@', selector), ('@RESOLVER@', resolver)):
        require(source.count('\n'+marker+'\n') == 1 and marker not in body)
        source = source.replace('\n'+marker+'\n', '\n'+body+'\n')
    require(source.count(selector) == source.count(resolver) == 1)
    return source


def reference(codes=None):
    data, expected = bytearray(), []
    for n, (value, cookie, result, index, salt, clobber) in enumerate(oracle.cases()):
        wanted = oracle.oracle(value, cookie, result, index, salt, clobber=clobber)
        encoded = oracle.hot.encode(value, cookie)
        if codes is not None:
            oracle.r.verify(oracle.exercise(codes, cookie, encoded, result, index, salt,
                            clobber=clobber), wanted)
        regs, stack = oracle.query.free.inputs(index, salt)
        data.extend(struct.pack('<12I', *regs, cookie, encoded, result, clobber))
        data.extend(stack)
        events = [[e['kind'], e['args'], e['returnRva'], e['registers'][7], e['registers'][2]]
                  for e in wanted['events']]
        expected.append(dict(case=n, registers=wanted['registers'], stack=wanted['stack'].hex(), events=events))
    require(len(expected) == 3456)
    return bytes(data), expected


def compare(text, expected):
    rows = [json.loads(line, object_pairs_hook=strict_object) for line in text.splitlines()]
    require(len(rows) == len(expected) == 3456)
    for n, (actual, wanted) in enumerate(zip(rows, expected)):
        require(type(actual) is dict and set(actual) == {'case','registers','stack','events'})
        require(type(actual['case']) is int and actual['case'] == n)
        require(type(actual['registers']) is list and len(actual['registers']) == 8 and
                all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in actual['registers']))
        require(type(actual['stack']) is str and len(actual['stack']) == 8192)
        require(type(actual['events']) is list and len(actual['events']) in (2,3))
        for event in actual['events']:
            require(type(event) is list and len(event) == 5 and type(event[0]) is str and
                    type(event[1]) is list and all(type(v) is int and 0 <= v <= 0xFFFFFFFF
                    for v in event[1]+event[2:]))
        require(actual == wanted)
    return dict(cases=3456, matched=3456)


def run(output, selector_index, resolver_index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-storage-composed-native/1', success=False, original_bodies=2,
        rvas=['0x8480bf','0x847e6c'], lifted=False, compiled_for_aarch64=False,
        matched_x86_reference=False, executed_under_qemu=False, android_executed=False,
        commands=[], runs={}, timings={}, lifts={},
        invocation=[sys.executable, *sys.argv], harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE),
        compared=['eight caller GPRs','entire 4096-byte stack','ordered endpoint args/return RVA/SP/ECX',
                  'immutable cookie/cache/slot pages'],
        limits=['two unchanged whole generated bodies; guard/storage endpoints authored NOT Windows',
                'no native flags/PC/RET-target/endpoint full CPU/FP/SIMD/SEH/transient write comparison',
                'all cold/unsupported calls reject; no cold ABI, image/GuestMemory/runtime binding or Android'])

    def command(name, argv, data=None, expected=0):
        record = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(record)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            p = subprocess.run(record['argv'], input=data, cwd=ROOT, stdout=out, stderr=err, timeout=180)
        record.update(exit_code=p.returncode, seconds=time.monotonic()-start)
        require(p.returncode == expected)

    stage = 'lift'
    try:
        bodies = {}
        for name, script, index in (('selector','measure_storage_selector.py',selector_index),
                                    ('resolver','measure_encoded_resolver.py',resolver_index)):
            command(name+'-lift', [sys.executable, ROOT/'scripts/recomp'/script,
                    '--index', index, '--output', output/name], expected=2)
            lift = json.loads((output/name/'metrics.jsonl').read_text()); row['lifts'][name] = lift
            require(lift['lifted'] and lift['compiled_for_aarch64'])
            body = output/name/'lifted.c'; require(digest(body) == lift['lifted_sha256'])
            bodies[name] = body.read_text()
        row['lifted'] = True
        (output/'transport.c').write_text(assemble(bodies['selector'], bodies['resolver']))
        stage = 'reference'; start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        pe = oracle.r.load_image()
        try:
            codes = {p.ENTRY: pe.get_data(p.RVA, p.SIZE) for p in oracle.BODIES}
            require(all(len(codes[p.ENTRY]) == p.SIZE for p in oracle.BODIES))
            inputs, expected = reference(codes)
        finally:
            pe.close()
        row['timings']['reference'] = time.monotonic()-start
        (output/'input.bin').write_bytes(inputs); (output/'reference.json').write_text(json.dumps(expected))
        row['reference_sha256'] = digest(output/'reference.json')
        upstream = ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'
        for isa in ('host','arm64'):
            stage = isa+'-compile'; binary = output/isa
            command(stage, ['zig-cc', *([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream),output/'transport.c','-o',binary])
            h = binary.read_bytes()[:20]
            require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
            if isa == 'arm64': row['compiled_for_aarch64'] = True
            row.setdefault('binary_sha256', {})[isa] = digest(binary)
            argv = [binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary]
            stage = isa+'-execute'; command(stage, argv, inputs)
            if isa == 'arm64': row['executed_under_qemu'] = True
            stage = isa+'-compare'
            row['runs'][isa] = compare((output/(isa+'-execute.stdout')).read_text(), expected)
            row['runs'][isa]['rejection_controls'] = 0
            # Mutate only the first case. Every subsequent case must recover.
            for label, word, value in (('stack',7,0xB8000000),('clobber',11,2),
                    ('cold',9,oracle.hot.encode(0,0x12345660)),
                    ('target',9,oracle.hot.encode(oracle.query.FLS+4,0x12345660))):
                bad = bytearray(inputs); struct.pack_into('<I',bad,word*4,value)
                stage = isa+'-reject-'+label; command(stage,argv,bytes(bad))
                rows = (output/(stage+'.stdout')).read_text().splitlines()
                require(len(rows) == 3456 and json.loads(rows[0]) == dict(case=0,rejected=True))
                compare('\n'.join([json.dumps(expected[0]),*rows[1:]]),expected)
                row['runs'][isa]['rejection_controls'] += 1
        stage = 'audit'
        require((output/'host-execute.stdout').read_bytes() == (output/'arm64-execute.stdout').read_bytes())
        audit = dict(image_unchanged=digest(image)==IMAGE_SHA,
            source_exact=(output/'transport.c').read_text()==assemble(bodies['selector'],bodies['resolver']),
            template_unchanged=digest(TEMPLATE)==row['template_sha256'])
        for name, body in bodies.items():
            audit[name+'_unchanged'] = (output/name/'lifted.c').read_text()==body
            audit[name+'_inserted_once'] = (output/'transport.c').read_text().count(body)==1
        (output/'source-audit.json').write_text(json.dumps(audit)); require(all(audit.values()))
        row.update(success=True,matched_x86_reference=True)
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__)
        raise
    finally:
        (output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--selector-index',type=Path,required=True)
    ap.add_argument('--resolver-index',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args = ap.parse_args()
    try:
        run(args.output,args.selector_index,args.resolver_index)
    except Exception:
        print('Composed comparison failed; inspect private metrics',file=sys.stderr); return 1
    print('Two whole lifts matched host and Linux AArch64/QEMU; NOT cold/Windows/Android/startup')
    return 0


if __name__ == '__main__': raise SystemExit(main())
