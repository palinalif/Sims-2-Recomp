#!/usr/bin/env python3
"""1460 null-provider path: fresh whole lift, bounded x86/native comparison.

Only authored infrastructure is public. This does NOT verify nonnull providers,
REP STOSD, callbacks, allocation, whole 20D0 or whole initialization.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_initialization_setter as c
from inspect_startup_dependency import crosscheck_index
from measure_startup import decode_flow, dependencies

RVA, SIZE = 0x1460, 279
FUNCTION_SHA = '2de6058360421ad27edad91d19c076e6b68f27aa464457d995b0b29674ca2d7c'
GUARD_PATH = (0x1460, 0x1461, 0x1463, 0x1466, 0x146c, 0x146f, 0x1471,
              0x1472, 0x156d, 0x1572, 0x1573, 0x1575, 0x1576)
MODES = ('valid', 'wrong-result', 'wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random((RVA << 8)+n)
    regs = {r:rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    regs['esi'] = c.DATA_PAGES[1]+(0x80 if n % 2 else 0xd00)
    # Incoming EAX is intentionally not the receiver (custom ESI ABI).
    pages = {p:bytearray(rng.randbytes(4096)) for p in c.PAGES}
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0], c.RETURN)
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], regs['esi']-c.DATA_PAGES[1]+0x74, 0)
    return regs, pages


def oracle(regs, pages):
    """Independent full final-state contract for the null-provider path ONLY."""
    c.require(set(regs) == set(c.REGS) and set(pages) == set(c.PAGES))
    c.require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
    c.require(all(len(b) == 4096 for b in pages.values()))
    sp, obj = regs['esp'], regs['esi']
    c.require(sp in (c.DATA_PAGES[0]+0x800, c.DATA_PAGES[0]+0xc00))
    c.require(c.DATA_PAGES[1] <= obj <= c.DATA_PAGES[1]+4096-0x78 and obj % 4 == 0)
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[1]], obj-c.DATA_PAGES[1]+0x74)[0] == 0)
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[0]], sp-c.DATA_PAGES[0])[0] == c.RETURN)
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<I', after[c.DATA_PAGES[0]], sp-c.DATA_PAGES[0]-4, regs['ebp'])
    struct.pack_into('<I', after[c.DATA_PAGES[0]], sp-c.DATA_PAGES[0]-1056, regs['edi'])
    out = dict(regs, eax=18, edx=0, esp=sp+4)
    return dict(regs=[out[r] for r in c.REGS], pages=b''.join(after[p] for p in c.PAGES).hex())


def assemble(body):
    c.require(type(body) is str and body.strip())
    replacements = {
        '@PROTOTYPES@': 'static void service_guard_1460(void);\n'
            'static constexpr unsigned address_sub_A00102D0=0xA00102D0u;\n'
            'static constexpr unsigned address_sub_A0831A6F=0xA0831A6Fu;',
        '@SELECT@': 'case 0xA0001460u: service_guard_1460();break;',
        '@ADAPTERS@': 'static void adapter_1460(uint32_t* s) {select_body(0xA0001460u,s);}',
        '@CALLBACKS@': 'case 0xA0001460u:callback=adapter_1460;break;',
        '@DIRECT_RETURNS@': '', '@INDIRECT_RETURNS@': '', '@BODY@': body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA0001460u,in,adapter_1460)',
    }
    text = c.TEMPLATE.read_text()
    for old, new in replacements.items():
        c.require(text.count(old) == 1)
        text = text.replace(old, new)
    c.require(text.count(body) == 1)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = c.BRIDGE.read_text()
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    c.require(text.count(old) == 1)
    text = text.replace(old, 'constexpr std::array<uint32_t,1> targets{0xA0001460u};')
    if mode != 'valid':
        old = '    current(s.data());'
        c.require(text.count(old) == 1)
        text = text.replace(old, old+('\n    s[0]^=4;' if mode == 'wrong-result' else '\n    s[7]+=8;'))
    return text


def run(index, output):
    output = c.private_output(output)
    row = dict(schema='ts2-service-null-guard-native/1', success=False, rva=hex(RVA), size=SIZE,
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)), helper_sha256=c.digest(Path(c.__file__)),
        template_sha256=c.digest(c.TEMPLATE), bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable, *sys.argv], commands=[], runs={}, timings={},
        lifted=False, arm64_executed=False, android_executed=False, stub=False,
        whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['ONLY null [ESI+74] path; synthetic receiver and two aligned stack positions',
                'Eight final GPRs and six full pages; no flags/FP/PC/native transient writes',
                'Nonnull provider, REP STOSD, callbacks, allocation and ownership remain unverified',
                'No whole 20D0/1AB665, E3/E4, production registration or Android execution'])
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err, cwd=c.ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    stage = 'preflight'
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        c.require(all(c.digest(upstream/n) == c.digest(pristine/n) for n in used))
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0, str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        stage = 'fresh-lift'; start = time.monotonic()
        code = pe.get_data(RVA, SIZE)
        c.require(hashlib.sha256(code).hexdigest() == FUNCTION_SHA)
        function, nodes, _, flow = decode_flow(code, c.BASE+RVA, LinearInstruction)
        c.require(len(nodes) == 82)
        body_meta = dict(flow, instruction_rvas=[hex(a-c.BASE) for a in sorted(nodes)])
        row['index'] = crosscheck_index(json.loads(index.read_text()), body_meta, RVA)
        row['index_sha256'] = c.digest(index)
        deps = dependencies(nodes, pe)
        c.require(deps['direct_calls'] == ['0x102d0', '0x831a6f'] and deps['indirect_calls'] == 4)
        function.name = 'service_guard_1460'
        body = Lifter(precise_carry=True).lift_function(function)
        c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
        (output/'lifted.c').write_text(body)
        row.update(lifted=True, function_sha256=FUNCTION_SHA, dependencies=deps,
            lift_invocation=dict(api='Lifter(precise_carry=True).lift_function', address=hex(c.BASE+RVA), name=function.name))
        row['timings']['translation_and_index'] = time.monotonic()-start
        stage = 'original-reference'; start = time.monotonic()
        code_pages = {c.BASE+0x1000:bytearray(4096)}
        code_pages[c.BASE+0x1000][0x460:0x460+SIZE] = code
        expected, inputs, visited = [], bytearray(), set()
        for n in range(64):
            regs, pages = state(n)
            observed, seen = c.reference(nodes, code_pages, c.BASE+RVA, regs, pages)
            c.require(seen == {c.BASE+a for a in GUARD_PATH})
            c.require(observed == oracle(regs, pages))
            visited |= seen
            expected.append(dict(case=n, **observed))
            inputs.extend(struct.pack('<8I', *(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in c.PAGES))
        row.update(x86_oracle_matches=64, coverage=dict(visited=len(visited), total=len(nodes), callee_calls=0))
        row['timings']['reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(body))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(mode))
            for isa in ('host', 'arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile', ['zig-cxx', *([] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']),
                    '-std=c++20', '-D_POSIX_C_SOURCE=200809L', '-O0', '-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'), transport, bridge, c.ROOT/'native/src/guest_memory.cpp',
                    c.ROOT/'native/src/guest_dispatch.cpp', '-lm', '-o', binary])
                header = binary.read_bytes()[:20]
                c.require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == (62 if isa == 'host' else 183))
                command(stage+'-execute', [binary] if isa == 'host' else [c.ROOT/'scripts/campaign/arm64-run.sh', binary], bytes(inputs))
                row['runs'][stage] = dict(compiled=True, **c.assess((output/(stage+'-execute.stdout')).read_text(), expected, mode))
                if isa == 'arm64': row['arm64_executed'] = True
        row['artifact_sha256'] = {n:c.digest(output/n) for n in ('lifted.c', 'transport.cpp', 'reference.json', 'input.bin')}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try: run(a.index, a.output)
    except Exception: p.exit(1, 'Service guard failed; inspect private receipt.\n')
    print('Null-provider fragment: 64/64 host + Linux/AArch64; two controls reject. NOT whole 1460 or Android.')


if __name__ == '__main__': main()
