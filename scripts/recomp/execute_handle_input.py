#!/usr/bin/env python3
"""Fresh 2790 -> 26B0 differential on owned buffers with sufficient capacity.

No allocator stand-in: reaching 1AF0 rejects. Private bodies/states stay in work/.
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

ROOT_RVA = 0x2790
UNITS = {
    0x2790: (56, 16, '71073bafa4914142a5666eebf130816c511017bbe3d10c8f32015535a519e4ba'),
    0x26b0: (60, 30, '98df3b377e24be341152f9004d2ad3fb8b29d44ef54a1d9bbc7f90af7459367c'),
}
MODES = ('valid', 'wrong-slot', 'wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random(0x279000+n)
    regs = {r:rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    pages = {p:bytearray(rng.randbytes(4096)) for p in c.PAGES}
    h = c.DATA_PAGES[1]+(128 if n % 2 else 1024)
    source, cursor = c.DATA_PAGES[2]+128, c.DATA_PAGES[2]+1024+(n % 4)*64
    # +8 is the end bound, +C/+10 begin at the same owned cursor.
    struct.pack_into('<III', pages[c.DATA_PAGES[1]], h-c.DATA_PAGES[1]+0x1d8,
                     cursor+64, cursor, cursor)
    sample = bytes(1+rng.randrange(255) for _ in range(n % 17))+b'\0'
    pages[c.DATA_PAGES[2]][128:128+len(sample)] = sample
    struct.pack_into('<III', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0],
                     c.RETURN, h, source)
    # Old input pointer is deliberately distinct; it must be replaced.
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], h-c.DATA_PAGES[1]+0xd0, source)
    return regs, pages


def contract(regs, pages, observed):
    """Independent non-stack post-state/result contract; x86 supplies scratch GPRs."""
    c.require(set(regs) == set(c.REGS) and set(pages) == set(c.PAGES))
    c.require(all(len(pages[p]) == 4096 for p in c.PAGES))
    sp = regs['esp']-c.DATA_PAGES[0]
    ret, h, source = struct.unpack_from('<III', pages[c.DATA_PAGES[0]], sp)
    c.require(ret == c.RETURN and c.DATA_PAGES[1] <= h <= c.DATA_PAGES[1]+4096-0x1e4)
    off = h-c.DATA_PAGES[1]
    end, cursor, start = struct.unpack_from('<III', pages[c.DATA_PAGES[1]], off+0x1d8)
    c.require(cursor == start and c.DATA_PAGES[2] <= source < cursor < end <= c.DATA_PAGES[2]+4096)
    data = bytes(pages[c.DATA_PAGES[2]])
    nul = data.find(b'\0', source-c.DATA_PAGES[2], cursor-c.DATA_PAGES[2])
    c.require(nul >= 0)
    sample = data[source-c.DATA_PAGES[2]:nul+1]
    c.require(len(sample) < end-cursor)  # No capacity-boundary/allocator claim.
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<I', after[c.DATA_PAGES[1]], off+0xd0, start)
    struct.pack_into('<II', after[c.DATA_PAGES[1]], off+0x1dc,
                     cursor+len(sample), cursor+len(sample))
    pos = cursor-c.DATA_PAGES[2]
    after[c.DATA_PAGES[2]][pos:pos+len(sample)] = sample
    c.require(len(observed['regs']) == 8 and observed['regs'][0] == 1)
    c.require(observed['regs'][7] == regs['esp']+4)
    for name in ('ebx', 'ebp', 'esi', 'edi'):
        c.require(observed['regs'][c.REGS.index(name)] == regs[name])
    raw = bytes.fromhex(observed['pages'])
    c.require(len(raw) == 6*4096)
    for index, page in enumerate(c.PAGES):
        if page != c.DATA_PAGES[0]:
            c.require(raw[index*4096:(index+1)*4096] == after[page])


def assemble(bodies, call_return):
    c.require(set(bodies) == set(UNITS) and all(b.strip() for b in bodies.values()))
    c.require(type(call_return) is int and c.BASE+ROOT_RVA < call_return < c.BASE+ROOT_RVA+56)
    replacements = {
        '@PROTOTYPES@': '\n'.join(f'static void input_{r:X}(void);' for r in UNITS)+
            '\nstatic constexpr unsigned address_sub_A00026B0=0xA00026B0u;\n'
            'static constexpr unsigned address_sub_A0001AF0=0xA0001AF0u;',
        '@SELECT@': ''.join(f'case 0x{c.BASE+r:08X}u:input_{r:X}();break;' for r in UNITS),
        '@ADAPTERS@': '\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}' for r in UNITS),
        '@CALLBACKS@': ''.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in UNITS),
        '@DIRECT_RETURNS@': f'if(caller==0xA0002790u && target==0xA00026B0u) return 0x{call_return:08X}u;',
        '@INDIRECT_RETURNS@': '', '@BODY@': '\n'.join(bodies.values()),
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA0002790u,in,adapter_2790)',
    }
    text = c.TEMPLATE.read_text()
    for old, new in replacements.items():
        c.require(text.count(old) == 1)
        text = text.replace(old, new)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = c.BRIDGE.read_text()
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    c.require(text.count(old) == 1)
    text = text.replace(old, 'constexpr std::array<uint32_t,2> targets{0xA0002790u,0xA00026B0u};')
    old = '    current(s.data());'
    c.require(text.count(old) == 1)
    if mode == 'wrong-cleanup':
        text = text.replace(old, old+'\n    s[7]+=8;')
    elif mode == 'wrong-slot':
        # Perturb only root publication through checked guest memory, not the lift.
        text = text.replace(old, old+'\n    if(depth==1) {auto h=memory->read32(s[7]);memory->write32(h+0xd0,0);}')
    return text


def run(index_dir, output, buffer_index=None):
    output = c.private_output(output)
    row = dict(schema='ts2-handle-input-native/1', success=False,
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)), helper_sha256=c.digest(Path(c.__file__)),
        template_sha256=c.digest(c.TEMPLATE), bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable, *sys.argv], functions={}, commands=[], runs={},
        lifted=False, host_native_executed=False, arm64_executed=False, android_executed=False,
        stub=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['ONLY nonnull input, disjoint owned buffers, sufficient capacity; no 1AF0 call allowed',
                'Eight final GPRs/six full pages vs x86; oracle checks result/nonvolatiles/SP/non-stack pages',
                'No flags/FP/PC/native transient-write comparison; no null/allocation/failure path claim',
                'No lifetime, whole 20D0/1460/1AB665, E3/E4, production binding or Android evidence'])
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
        nodes, bodies, code_pages = {}, {}, {c.BASE+0x2000:bytearray(4096)}
        call_return = None
        from capstone import CS_GRP_CALL
        for rva, (size, count, pin) in UNITS.items():
            code = pe.get_data(rva, size)
            c.require(hashlib.sha256(code).hexdigest() == pin)
            function, ns, _, flow = decode_flow(code, c.BASE+rva, LinearInstruction)
            c.require(len(ns) == count and flow['size_bytes'] == size)
            index = buffer_index if rva == 0x26b0 and buffer_index is not None else index_dir/f'{rva:x}.json.env.json'
            meta = dict(flow, instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)])
            check = crosscheck_index(json.loads(index.read_text()), meta, rva)
            deps = dependencies(ns, pe)
            c.require(deps['direct_calls'] == (['0x26b0'] if rva == ROOT_RVA else ['0x1af0']))
            c.require(deps['indirect_calls'] == 0)
            if rva == ROOT_RVA:
                calls = [i for i in ns.values() if i.group(CS_GRP_CALL)]
                c.require(len(calls) == 1); call_return = calls[0].address+calls[0].size
            function.name = f'input_{rva:X}'
            body = Lifter(precise_carry=True).lift_function(function)
            c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
            bodies[rva] = body; nodes.update(ns)
            (output/f'{rva:x}.c').write_text(body)
            code_pages[c.BASE+0x2000][rva-0x2000:rva-0x2000+size] = code
            row['functions'][hex(rva)] = dict(index=check, index_sha256=c.digest(index), function_sha256=pin,
                dependencies=deps, size=size, instructions=count,
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function', address=hex(c.BASE+rva), name=function.name))
        row['lifted'] = True
        stage = 'original-reference'
        expected, inputs, visited = [], bytearray(), set()
        for n in range(64):
            regs, pages = state(n)
            observed, seen = c.reference(nodes, code_pages, c.BASE+ROOT_RVA, regs, pages)
            contract(regs, pages, observed)
            c.require(c.BASE+0x26b0 in seen)
            visited |= seen; expected.append(dict(case=n, **observed))
            inputs.extend(struct.pack('<8I', *(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in c.PAGES))
        row.update(x86_contract_matches=64, coverage=dict(visited=len(visited), total=len(nodes), allocator_calls=0))
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(bodies, call_return))
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
        row['artifact_sha256'] = {n:c.digest(output/n) for n in ('2790.c', '26b0.c', 'transport.cpp', 'reference.json', 'input.bin')}
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
    p.add_argument('--index-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--buffer-index', type=Path, help='Existing persistent 26B0 envelope')
    a = p.parse_args()
    try: run(a.index_dir, a.output, a.buffer_index)
    except Exception: p.exit(1, 'Handle input comparison failed; inspect private receipt.\n')
    print('2790 -> 26B0 owned-capacity path: 64 cases per ISA; NOT allocation or Android.')


if __name__ == '__main__': main()
