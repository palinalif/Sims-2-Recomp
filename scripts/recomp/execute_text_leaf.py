#!/usr/bin/env python3
"""Campaign D: standalone 9550 fresh lift and bounded two-ISA differential.

Private image/bodies/states never leave work/. No encoding oracle or game binding.
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
from execute_cache_dispatch import (BASE, PAGES, IMAGE_PAGES, DATA_PAGES, REGS,
    RETURN, reference, entry_state, compare, thunk_function)
from execute_cache_caller import TEMPLATE, BRIDGE
from execute_cache_skip import private_output, require
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest
from measure_local_switch import decode_switch

MODES = ('valid', 'counter-destinations', 'return-frame')


def leaf_state(n, image_pages):
    require(type(n) is int and 0 <= n < 64)
    regs, pages = entry_state(n, 0x1290, random.Random(9550+n), image_pages,
                              complete_units=True)
    text, out = DATA_PAGES[2]+128, DATA_PAGES[1]+128+0x1c8
    # Full byte-domain input, grouped deterministically; padding backs every
    # multibyte read and ends in ASCII. Invalid bytes are deliberate fixtures.
    samples = (b'', b'A', b'\r\n', b'\x80', b'\xc2\xa2',
               b'\xe2\x82\xac', b'\xf0\x9f\x98\x80', b'\xff\xfe')
    sample = (bytes(range(n*8, n*8+8)) + b'\x80'*8 + b'AAAA'
              if n < 32 else samples[n % len(samples)] * (1+n % 3))
    require(len(sample) <= 64)
    pages[DATA_PAGES[2]][128:128+len(sample)] = sample
    struct.pack_into('<5I', pages[DATA_PAGES[0]], regs['esp']-DATA_PAGES[0],
                     RETURN, BASE+0xe17ab0, text, text+len(sample), out)
    return regs, pages


def thunk_state(n, image_pages):
    regs, pages = leaf_state(n, image_pages)
    # A real inline service pointer, not the descriptor the thunk must publish.
    struct.pack_into('<I', pages[DATA_PAGES[0]], regs['esp']-DATA_PAGES[0]+4,
                     DATA_PAGES[1]+128+0x7c)
    return regs, pages


def assert_thunk_poststate(regs, pages, state):
    final = bytes.fromhex(state['pages'])
    require(len(final) == len(PAGES)*4096)
    offset = regs['esp']-DATA_PAGES[0]
    require(state['regs'][-1] == regs['esp']+4)
    require(struct.unpack_from('<I', final, offset)[0] == RETURN)
    require(struct.unpack_from('<I', final, offset+4)[0] == BASE+0xe17ab0)
    require(final[offset+8:offset+20] == pages[DATA_PAGES[0]][offset+8:offset+20])


def lift_thunk(pe, upstream, index):
    env = json.loads(index.read_text())
    p, q = env['provenance'], env['result']
    require(env['schema'] == 'sims2-ghidra-query-envelope/1' and
            p['sourceImageSha256'] == IMAGE_SHA and p['mode'] == 'readOnly' and
            p['analysisPerformed'] is False and p['headlessExitCode'] == 0 and
            p['outputParseError'] is None and int(q['query']['rva'], 16) == 0xfcf0 and
            int(q['program']['imageBaseVa'], 16) == BASE)
    sys.path.insert(0, str(upstream))
    from tools.lift.lift32 import Lifter
    from tools.lift.generate import LinearInstruction
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from measure_startup import supported
    require(Path(sys.modules[Lifter.__module__].__file__).resolve() ==
            (upstream/'tools/lift/lift32.py').resolve())
    raw = pe.get_data(0xfcf0, 32)
    span = sum(i.size for i in Cs(CS_ARCH_X86, CS_MODE_32).disasm(raw, BASE+0xfcf0, count=2))
    function, nodes = thunk_function(raw[:span], LinearInstruction)
    require(all(BASE+int(i['rva'], 16) in nodes for i in q['function']['disassembly']['items']))
    start = time.monotonic()
    body = Lifter(precise_carry=True, lifted={BASE+0xfcf0, BASE+0x9550}).lift_function(function)
    require(supported(body) and body.strip())
    return body, nodes, dict(seconds=time.monotonic()-start,
        api='Lifter(precise_carry=True,lifted={thunk_va,leaf_va}).lift_function(two_instruction_thunk)',
        index_sha256=digest(index), resolution=q['function']['resolution'])


def assemble(body, thunk_body=None):
    require(type(body) is str and body.strip())
    text = TEMPLATE.read_text()
    replacements = {
        '@PROTOTYPES@': 'static void startup_009550(void);',
        '@SELECT@': 'case 0xA0009550u: startup_009550();break;',
        '@ADAPTERS@': 'static void adapter_009550(uint32_t* s) {select_body(0xA0009550u,s);}',
        '@CALLBACKS@': 'case 0xA0009550u:callback=adapter_009550;break;',
        '@DIRECT_RETURNS@': '', '@INDIRECT_RETURNS@': '', '@BODY@': body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)':
            'cache_invoke(0xA0009550u,in,adapter_009550)',
    }
    for key, value in replacements.items():
        require(text.count(key) == 1)
        text = text.replace(key, value)
    require(text.count(body) == 1)
    if thunk_body is not None:
        require(type(thunk_body) is str and thunk_body.strip())
        for old, new in {
            'static void startup_009550(void);':
                'static void startup_009550(void);\nstatic void startup_00FCF0(void);',
            'case 0xA0009550u: startup_009550();break;':
                'case 0xA0009550u: startup_009550();break; case 0xA000FCF0u: startup_00FCF0();break;',
            'static void adapter_009550(uint32_t* s) {select_body(0xA0009550u,s);}':
                'static void adapter_009550(uint32_t* s) {select_body(0xA0009550u,s);}\n'
                'static void adapter_00FCF0(uint32_t* s) {select_body(0xA000FCF0u,s);}',
            'case 0xA0009550u:callback=adapter_009550;break;':
                'case 0xA0009550u:callback=adapter_009550;break; case 0xA000FCF0u:callback=adapter_00FCF0;break;',
            'cache_invoke(0xA0009550u,in,adapter_009550)':
                'cache_invoke(0xA000FCF0u,in,adapter_00FCF0)',
        }.items():
            require(text.count(old) == 1)
            text = text.replace(old, new)
        text += '\n'+thunk_body
        require(text.count(body) == text.count(thunk_body) == 1)
    return text


def bridge_source(text, mode):
    require(mode in MODES)
    if mode == 'valid':
        return text
    if mode == 'counter-destinations':
        old = '    check(a,size,true);'
        new = old + '\n    if(size==4 && (a==0x72000248u || a==0x7200024Cu)) a^=4;'
    else:
        old = '    current(s.data());'
        new = old + '\n    if(depth==1) s[7]-=4;'
    require(text.count(old) == 1)
    return text.replace(old, new)


def assess(text, expected, mode):
    require(mode in MODES)
    rows = [json.loads(line) for line in text.splitlines()]
    # Reject malformed/partial/crashed mutants: they are not behavioral kills.
    compare(text, rows)
    differences = sum(a != b for a, b in zip(rows, expected))
    try:
        compare(text, expected)
        matched = True
    except ValueError:
        matched = False
    require(matched if mode == 'valid' else not matched)
    require(differences == 0 if mode == 'valid' else differences > 0)
    return dict(executed=True, cases=64, matched=64-differences,
                differing_cases=differences, negative_control=mode != 'valid')


def run(output, index, *, thunk_index=None):
    output = private_output(output)
    row = dict(schema='ts2-text-leaf-native/1', success=False, rva='0x9550',
        image_sha256=IMAGE_SHA, pcrecomp_revision=REVISION,
        invocation=[sys.executable, *sys.argv], commands=[], runs={},
        harness_sha256=digest(Path(__file__)), template_sha256=digest(TEMPLATE),
        bridge_sha256=digest(BRIDGE), arm64_executed=False, android_executed=False,
        compared=['eight GPRs', 'six complete pages including image tables'],
        limits=['synthetic buffer-backed nonregressing ranges, no behavior responses',
                'no flags/FP/PC/transient writes or independent encoding semantics oracle',
                'negative controls alter authored bridge, not original instructions',
                'standalone leaf only; no production binding, Android or gameplay'])
    if thunk_index is not None:
        row.update(schema='ts2-text-thunk-native/1', rva='0xfcf0',
                   closure=['0xfcf0', '0x9550'])
        row['limits'][-1] = 'standalone thunk with real leaf tail callee; no production binding, Android or gameplay'
    stage = 'fresh-switch-lift'
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err,
                                   cwd=ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        require(child.returncode == 0)
    try:
        command('switch-lift', [sys.executable, Path(__file__).with_name('measure_local_switch.py'),
            '--index', index, '--output', output/'switch'])
        lift = json.loads((output/'switch/result.json').read_text())
        require(lift['success'] and digest(output/'switch/lifted.c') == lift['lifted_sha256'])
        row['switch_sha256'] = digest(output/'switch/result.json')
        row['body_sha256'] = lift['lifted_sha256']
        row['upstream_files'] = lift['upstream_files']
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        targets = struct.unpack('<6I', pe.get_data(0x95c8, 24))
        _, nodes, _ = decode_switch(pe.get_data(0x9550, 0x78), BASE+0x9550,
                                   BASE+0x95c8, targets, lambda i:i)
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        require(all(digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        thunk_body = None
        entry = BASE+0x9550
        if thunk_index is not None:
            stage = 'fresh-thunk-lift'
            thunk_body, thunk_nodes, provenance = lift_thunk(pe, upstream, thunk_index)
            (output/'thunk.c').write_text(thunk_body)
            row['thunk_lift'] = dict(provenance, sha256=digest(output/'thunk.c'))
            require(not set(thunk_nodes) & set(nodes))
            nodes.update(thunk_nodes)
            entry = BASE+0xfcf0
        code_pages = {BASE+0x9000: pe.get_data(0x9000, 4096)}
        if thunk_index is not None:
            code_pages[BASE+0xf000] = pe.get_data(0xf000, 4096)
        image_pages = {p:pe.get_data(p-BASE, 4096) for p in IMAGE_PAGES}
        stage = 'original-reference'
        inputs, expected, visited = bytearray(), [], set()
        for n in range(64):
            row['current_reference_case'] = n
            regs, pages = (thunk_state if thunk_index is not None else leaf_state)(n, image_pages)
            state, seen = reference(nodes, code_pages, entry, regs, pages)
            require(state['regs'][-1] == regs['esp']+4)
            if thunk_index is not None:
                assert_thunk_poststate(regs, pages, state)
            expected.append(dict(case=n, **state)); visited.update(seen)
            inputs.extend(struct.pack('<8I', *(regs[r] for r in REGS)))
            inputs.extend(b''.join(bytes(pages[p]) for p in PAGES))
        row.pop('current_reference_case')
        row['coverage'] = dict(visited=len(visited), total=len(nodes),
            switch_arms=len(visited & set(targets)), total_switch_arms=len(set(targets)),
            invalid_arm_visited=BASE+0x95c2 in visited,
            uncovered_rvas=[hex(a-BASE) for a in sorted(set(nodes)-visited)])
        require(set(targets) <= visited and BASE+0x95c2 in visited)
        if thunk_index is not None:
            require(set(thunk_nodes) <= visited)
            row['thunk_poststate_cases'] = 64
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        row['reference_sha256'] = digest(output/'reference.json')
        row['input_sha256'] = digest(output/'input.bin')
        transport = output/'transport.cpp'
        body = (output/'switch/lifted.c').read_text()
        transport.write_text(assemble(body, thunk_body))
        row['transport_sha256'] = digest(transport)
        row['verbatim_body_audited'] = transport.read_text().count(body) == 1
        if thunk_body is not None:
            row['verbatim_thunk_audited'] = transport.read_text().count(thunk_body) == 1
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        require(all(digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(BRIDGE.read_text(), mode))
            for isa in ('host', 'arm64'):
                stage = mode+'-'+isa
                binary = output/stage
                command(stage+'-compile', ['zig-cxx', *([] if isa == 'host' else
                    ['-target', 'aarch64-linux-musl', '-static']), '-std=c++20',
                    '-D_POSIX_C_SOURCE=200809L', '-O0', '-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(ROOT/'native/include'), transport, bridge,
                    ROOT/'native/src/guest_memory.cpp', ROOT/'native/src/guest_dispatch.cpp',
                    '-lm', '-o', binary])
                h = binary.read_bytes()[:20]
                require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20], 'little') ==
                        (62 if isa == 'host' else 183))
                command(stage+'-execute', [binary] if isa == 'host' else
                        [ROOT/'scripts/campaign/arm64-run.sh', binary], bytes(inputs))
                row['runs'][stage] = assess((output/(stage+'-execute.stdout')).read_text(), expected, mode)
                if isa == 'arm64': row['arm64_executed'] = True
        require(digest(image) == IMAGE_SHA)
        row['success'] = True
    except Exception as exc:
        import traceback
        row.update(failed_stage=stage, error_type=type(exc).__name__,
            harness_failure_lines=[f.lineno for f in traceback.extract_tb(exc.__traceback__)
                                   if Path(f.filename).resolve() == Path(__file__).resolve()])
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--thunk-index', type=Path, help='Verify standalone FCF0 entry with fresh real leaf callee')
    a = p.parse_args()
    try: run(a.output, a.index, thunk_index=a.thunk_index)
    except Exception: p.exit(1, 'Standalone leaf failed; inspect private outputs.\n')
    print('Standalone text unit: 64/64 host and AArch64; two bridge faults rejected per ISA. NOT Android.')


if __name__ == '__main__': main()
