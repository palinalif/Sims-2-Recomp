#!/usr/bin/env python3
"""Fresh composed 2570 -> 1A40/1A00 initialization differential.

Authored transport only. Original-derived bodies and states remain private.
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

ROOT_RVA = 0x2570
SPAN = 116
UNITS = {
    ROOT_RVA: (81, 18, 'f37d4eb203688c778645d578d723e1449e58d78f67f8661f84f49b7ec33bc187'),
    c.ZERO_INIT: (17, 7, c.ZERO_INIT_SHA),
    c.BUFFER_INIT: (14, 6, c.BUFFER_INIT_SHA),
}
MODES = ('valid', 'wrong-slot', 'wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random(0x257000+n)
    regs = {r:rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    regs['edx'] = c.DATA_PAGES[1]+(0, 128, 1024, 4096-SPAN)[n % 4]
    pages = {p:bytearray(rng.randbytes(4096)) for p in c.PAGES}
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0], c.RETURN)
    # Every tested field must change, including at the exact page end.
    off = regs['edx']-c.DATA_PAGES[1]
    pages[c.DATA_PAGES[1]][off:off+SPAN] = bytes(1+rng.randrange(255) for _ in range(SPAN))
    return regs, pages


def oracle(regs, pages, last_return):
    c.require(set(regs) == set(c.REGS) and set(pages) == set(c.PAGES))
    c.require(all(len(pages[p]) == 4096 for p in c.PAGES))
    c.require(type(last_return) is int and c.BASE+ROOT_RVA < last_return < c.BASE+ROOT_RVA+81)
    sp, off = regs['esp']-c.DATA_PAGES[0], regs['edx']-c.DATA_PAGES[1]
    c.require(4 <= sp <= 4092 and sp % 4 == 0)
    c.require(0 <= off <= 4096-SPAN and off % 4 == 0)
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[0]], sp)[0] == c.RETURN)
    after = {p:bytearray(b) for p,b in pages.items()}
    after[c.DATA_PAGES[1]][off:off+SPAN] = bytes(SPAN)
    struct.pack_into('<I', after[c.DATA_PAGES[1]], off+84, 1)
    struct.pack_into('<I', after[c.DATA_PAGES[0]], sp-4, last_return)
    out = dict(regs, eax=1, ecx=0, esp=regs['esp']+4)
    return dict(regs=[out[r] for r in c.REGS], pages=b''.join(after[p] for p in c.PAGES).hex())


def validate_calls(calls):
    c.require(type(calls) is list and len(calls) == 6)
    c.require([t for t, ret in calls] == [c.BASE+c.ZERO_INIT]+[c.BASE+c.BUFFER_INIT]*5)
    returns = [ret for t, ret in calls]
    c.require(all(type(ret) is int and c.BASE+ROOT_RVA < ret < c.BASE+ROOT_RVA+81 for ret in returns))
    c.require(returns == sorted(set(returns)))


def assemble(bodies, calls):
    c.require(set(bodies) == set(UNITS) and all(type(b) is str and b.strip() for b in bodies.values()))
    validate_calls(calls)
    # The pinned caller is straight-line. Record the actual return PC at each
    # direct edge, not one guessed return per target (1A00 is called five times).
    sequence = '\n'.join(f'case {n}: if(target!=0x{t:08X}u) reject(); return 0x{ret:08X}u;'
                         for n, (t, ret) in enumerate(calls))
    replacements = {
        '@PROTOTYPES@': '\n'.join(f'static void opener_{r:X}(void);' for r in UNITS)+
            '\nstatic unsigned call_index=0;\n'+
            '\n'.join(f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;' for r in (c.ZERO_INIT,c.BUFFER_INIT)),
        '@SELECT@': ''.join(f'case 0x{c.BASE+r:08X}u:opener_{r:X}();break;' for r in UNITS),
        '@ADAPTERS@': '\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}' for r in UNITS),
        '@CALLBACKS@': ''.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in UNITS),
        '@DIRECT_RETURNS@': f'if(caller!=0x{c.BASE+ROOT_RVA:08X}u) reject();\nswitch(call_index++) {{\n{sequence}\ndefault:reject();}}',
        '@INDIRECT_RETURNS@': '', '@BODY@': '\n'.join(bodies.values()),
        'cache_reset(pages);': 'cache_reset(pages);call_index=0;',
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40);':
            'cache_invoke(0xA0002570u,in,adapter_2570);if(call_index!=6) reject();',
    }
    text = c.TEMPLATE.read_text()
    for old, new in replacements.items():
        c.require(text.count(old) == 1)
        text = text.replace(old, new)
    for body in bodies.values(): c.require(text.count(body) == 1)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = c.BRIDGE.read_text()
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    c.require(text.count(old) == 1)
    text = text.replace(old, 'constexpr std::array<uint32_t,3> targets{0xA0002570u,0xA0001A40u,0xA0001A00u};')
    old = '    current(s.data());'
    c.require(text.count(old) == 1)
    if mode == 'wrong-cleanup':
        text = text.replace(old, old+'\n    if(depth==1) s[7]+=8;')
    elif mode == 'wrong-slot':
        text = text.replace(old, old+'\n    if(depth==1) memory->write32(s[3]+112,1);')
    return text


def run(index_dir, output):
    output = c.private_output(output)
    row = dict(schema='ts2-opener-init-native/1', success=False,
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)), helper_sha256=c.digest(Path(c.__file__)),
        template_sha256=c.digest(c.TEMPLATE), bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable, *sys.argv], functions={}, commands=[], runs={},
        lifted=False, host_native_executed=False, arm64_executed=False, android_executed=False,
        stub=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['Aligned, writable, disjoint EDX receiver spans only; no invalid pointers or aliases',
                'Eight final GPRs/six full pages vs x86 and independent final-state oracle',
                'No flags/FP/PC/native transient-write comparison',
                'No allocation, callback/lifetime, whole opener/1AB665, E3/E4 or Android evidence'])
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
        stage = 'fresh-lifts'
        nodes, bodies, code_pages, calls = {}, {}, {}, []
        from capstone import CS_GRP_CALL, CS_GRP_JUMP
        for rva, (size, count, pin) in UNITS.items():
            code = pe.get_data(rva, size)
            c.require(hashlib.sha256(code).hexdigest() == pin)
            function, ns, _, flow = decode_flow(code, c.BASE+rva, LinearInstruction)
            c.require(len(ns) == count and flow['size_bytes'] == size)
            c.require(not any(i.group(CS_GRP_JUMP) for i in ns.values()))
            index = index_dir/f'{rva:x}.json.env.json'
            meta = dict(flow, instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)])
            check = crosscheck_index(json.loads(index.read_text()), meta, rva)
            deps = dependencies(ns, pe)
            c.require(deps['direct_calls'] == (['0x1a40']+['0x1a00']*5 if rva == ROOT_RVA else []))
            c.require(deps['indirect_calls'] == 0 and not deps['absolute_memory_va'] and not deps['segmented_memory_operands'])
            if rva == ROOT_RVA:
                calls = [(i.operands[0].imm, i.address+i.size) for i in ns.values() if i.group(CS_GRP_CALL)]
                calls.sort(key=lambda pair:pair[1]); validate_calls(calls)
            function.name = f'opener_{rva:X}'
            body = Lifter(precise_carry=True).lift_function(function)
            c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
            bodies[rva] = body; nodes.update(ns)
            (output/f'{rva:x}.c').write_text(body)
            page = c.BASE+(rva//4096)*4096
            code_pages.setdefault(page,bytearray(4096))[rva%4096:rva%4096+size] = code
            row['functions'][hex(rva)] = dict(index=check, index_sha256=c.digest(index), function_sha256=pin,
                dependencies=deps, size=size, instructions=count,
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function', address=hex(c.BASE+rva), name=function.name))
        row['lifted'] = True
        stage = 'original-reference'
        expected, inputs, visited = [], bytearray(), set()
        for n in range(64):
            regs, pages = state(n)
            observed, seen = c.reference(nodes, code_pages, c.BASE+ROOT_RVA, regs, pages)
            c.require(observed == oracle(regs,pages,calls[-1][1]))
            visited |= seen; expected.append(dict(case=n, **observed))
            inputs.extend(struct.pack('<8I', *(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in c.PAGES))
        c.require(visited == set(nodes))
        row.update(x86_contract_matches=64, coverage=dict(visited=len(visited), total=len(nodes)))
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(bodies, calls))
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
                row['host_native_executed' if isa == 'host' else 'arm64_executed'] = True
        row['artifact_sha256'] = {n:c.digest(output/n) for n in ('2570.c','1a00.c','1a40.c','transport.cpp','reference.json','input.bin')}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        row.update(success=True, whole_function_verified=True, dependencies_newly_resolved=1,
                   original_behaviour_newly_executable=['0x2570'])
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try: run(a.index_dir, a.output)
    except Exception: p.exit(1, 'Opener initializer comparison failed; inspect private receipt.\n')
    print('2570 -> real 1A40/1A00: 64 cases per ISA; NOT Android or game startup.')


if __name__ == '__main__': main()
