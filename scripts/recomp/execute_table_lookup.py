#!/usr/bin/env python3
"""Verify bounded no-create 1820 lookup with original hash/compare callees.

Authored fixtures and transport only; original bodies/states remain private.
Synthetic table ownership is NOT a 3C50/3700 producer contract.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_mode_empty as m
from inspect_startup_dependency import crosscheck_index
c = m.c
UNITS = {0x1820: (414, 154), 0x1800: (25, 12), 0x17d0: (34, 18)}
PINS = {0x1820: '5f921dda06040f85fd8450ed74f7aa7bc2140c6eb4dfb89fa90a04ba34f6f8ad',
        0x1800: 'c2c768e197e87dd23d2a57495744ee8bfdd0db35af3af35442e34dae83a8d3e1',
        0x17d0: 'af6e287e110dc731323524b5db0eaf9421ffdf97b5f82a6fe6bf8fe792afd248'}
EXTERNAL = (0x83a371, 0x831a54)
TEXTS = (b'', b'a', b'abc', b'wb+', b'Aa09', b'\x80\xff', b'longer-key', b'z')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    regs, pages = c.state(n)
    h = c.DATA_PAGES[1]+(0, 128, 1024, 4080)[n % 4]
    key, other, node, slots = c.DATA_PAGES[2]+64, c.DATA_PAGES[2]+256, c.DATA_PAGES[3]+64, c.DATA_PAGES[3]+128
    domain = 0 if n < 8 else 1 if n < 16 else 2 if n < 48 else 3
    capacity = (0, 4, 4, 4)[domain]
    text = TEXTS[n % 8]+b'\0'
    pages[c.DATA_PAGES[2]][64:64+len(text)] = text
    pages[c.DATA_PAGES[2]][256:267] = b'!different\0'
    # capacity, node count and growth threshold are input state, not responses.
    struct.pack_into('<4I', pages[c.DATA_PAGES[1]], h-c.DATA_PAGES[1], slots, capacity, 3, 4)
    struct.pack_into('<I', pages[c.DATA_PAGES[3]], 64, key if domain == 2 else other)
    buckets = ([node]*4 if domain == 2 else [node, node, node, 0] if domain == 3 else [0]*4)
    struct.pack_into('<4I', pages[c.DATA_PAGES[3]], 128, *buckets)
    regs['edi'] = h
    sp = regs['esp']-c.DATA_PAGES[0]
    struct.pack_into('<3I', pages[c.DATA_PAGES[0]], sp, c.RETURN, key, 0)
    return regs, pages


def contract(n, regs, pages, observed):
    """Independent observable subset; full volatile registers come from x86 only."""
    c.require(type(n) is int and 0 <= n < 64)
    out = dict(zip(c.REGS, observed['regs']))
    c.require(out['eax'] == (c.DATA_PAGES[3]+64 if 16 <= n < 48 else 0))
    c.require(out['esp'] == regs['esp']+4)
    c.require(all(out[r] == regs[r] for r in ('ebx', 'ebp', 'esi', 'edi')))
    data = bytes.fromhex(observed['pages'])
    c.require(len(data) == len(c.PAGES)*4096)
    c.require(all(data[i*4096:(i+1)*4096] == bytes(pages[p])
                  for i,p in enumerate(c.PAGES) if p != c.DATA_PAGES[0]))
    # Only callee stack scratch below incoming ESP may change; caller arguments
    # and the return word must remain intact, not just the four-byte cleanup.
    sp = regs['esp']-c.DATA_PAGES[0]
    c.require(data[sp:4096] == bytes(pages[c.DATA_PAGES[0]][sp:]))


def assemble(bodies):
    c.require(set(bodies) == set(UNITS) and all(type(b) is str and b.strip() for b in bodies.values()))
    replacements = {
        '@PROTOTYPES@': ''.join(f'static void lookup_{r:X}(void);\n' for r in UNITS)+''.join(
            f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;\n' for r in (*UNITS, *EXTERNAL)),
        '@SELECT@': ''.join(f'case 0x{c.BASE+r:08X}u:lookup_{r:X}();break;' for r in UNITS),
        '@ADAPTERS@': ''.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}\n' for r in UNITS),
        '@CALLBACKS@': ''.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in UNITS),
        '@DIRECT_RETURNS@': ('if(caller==0xA0001820u && target==0xA0001800u) return 0xA0001879u;'
                             'if(caller==0xA0001820u && target==0xA00017D0u) return 0xA000189Eu;'),
        '@INDIRECT_RETURNS@': '', '@BODY@': '\n'.join(bodies.values()),
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA0001820u,in,adapter_1820)',
    }
    text = c.TEMPLATE.read_text()
    for old,new in replacements.items():
        c.require(text.count(old) == 1); text = text.replace(old,new)
    return text


def bridge_source(mode):
    text = m.bridge_source(mode)
    if mode != 'valid':
        mutation = 's[0]^=4;' if mode == 'wrong-result' else 's[7]+=8;'
        c.require(text.count(mutation) == 1)
        text = text.replace(mutation, 'if(depth==1) '+mutation)
    c.require(text.count('constexpr std::array<uint32_t,1> targets{0xA0003700u};') == 1)
    return text.replace('constexpr std::array<uint32_t,1> targets{0xA0003700u};',
                        'constexpr std::array<uint32_t,3> targets{0xA0001820u,0xA0001800u,0xA00017D0u};')


def run(indices, output):
    output = c.private_output(output)
    sources = [Path(__file__), Path(m.__file__), Path(c.__file__), Path(c.reference.__code__.co_filename),
               Path(c.assess.__code__.co_filename), Path(m.decode_flow.__code__.co_filename),
               Path(crosscheck_index.__code__.co_filename), Path(c.state.__code__.co_filename), c.TEMPLATE, c.BRIDGE,
               *[c.ROOT/'native/src'/n for n in ('guest_memory.cpp','guest_dispatch.cpp')]]
    row = dict(schema='ts2-table-lookup-native/1', success=False, stub=False,
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION, invocation=[sys.executable,*sys.argv],
        source_sha256={str(p):c.digest(p) for p in sources},
        index_sha256={hex(r):c.digest(p) for r,p in indices.items()}, commands=[], runs={}, units={},
        host_native_executed=False, arm64_executed=False, android_executed=False,
        dependencies_newly_resolved=0, whole_function_verified=False,
        limits=['No-create synthetic owned tables: zero-capacity, empty, hit, collision-miss',
                'No allocation/growth/free execution; no real 3C50/3700 ownership binding',
                'Direct return mappings limited to no-create call sites 1874 and 1899',
                'Eight final GPRs and six full pages diffed; no flags/FP/PC/transient writes',
                'Compiler -fwrapv gives generated signed IMUL explicit modulo-32 overflow semantics',
                'Independent subset oracle only; full volatile GPR/stack oracle is original x86',
                'Not Android, game startup, composed opener or whole 1AB665'])
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
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        c.require(all(sha == c.digest(pristine/n) for n,sha in row['upstream_files'].items()))
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        nodes, bodies, cp = {}, {}, bytearray(4096)
        for r,(size,count) in UNITS.items():
            stage = 'lift-'+hex(r)
            code = pe.get_data(r,size); pin = hashlib.sha256(code).hexdigest()
            if r in PINS: c.require(pin == PINS[r])
            fn, ns, _, flow = m.decode_flow(code,c.BASE+r,LinearInstruction)
            c.require(len(ns) == count and flow['size_bytes'] == size)
            index = crosscheck_index(json.loads(indices[r].read_text()),dict(flow,instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)]),r)
            fn.name = f'lookup_{r:X}'
            start = time.monotonic(); body = Lifter(precise_carry=True).lift_function(fn)
            c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
            row['units'][hex(r)] = dict(size_bytes=size,instructions=count,sha256=pin,index=index,
                lift_seconds=time.monotonic()-start,lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+r),name=fn.name),lifted=True)
            (output/(hex(r)+'.c')).write_text(body)
            c.require(not set(ns)&set(nodes)); nodes.update(ns); bodies[r]=body
            cp[r%4096:r%4096+size]=code
        stage = 'original-reference'
        expected, inputs, visited = [], bytearray(), set()
        entry_cases = {r: 0 for r in UNITS}
        for n in range(64):
            regs,pages = state(n)
            result,seen = c.reference(nodes,{c.BASE+0x1000:cp},c.BASE+0x1820,regs,pages,budget=2048,checked_integer_multiply=True)
            contract(n,regs,pages,result)
            expected.append(dict(case=n,**result)); visited |= seen
            for r in UNITS: entry_cases[r] += int(c.BASE+r in seen)
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in c.PAGES))
        c.require(all(count >= 32 for count in entry_cases.values()))
        row.update(entry_cases={hex(r):count for r,count in entry_cases.items()})
        row.update(x86_subset_matches=64,coverage={hex(r):dict(visited=sum(c.BASE+r <= a < c.BASE+r+size for a in visited),total=count) for r,(size,count) in UNITS.items()})
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport=output/'transport.cpp'; transport.write_text(assemble(bodies))
        for mode in m.MODES:
            bridge=output/(mode+'.cpp'); bridge.write_text(bridge_source(mode))
            for isa in ('host','arm64'):
                stage=mode+'-'+isa; binary=output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-fwrapv','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,
                    *[c.ROOT/'native/src'/n for n in ('guest_memory.cpp','guest_dispatch.cpp')],'-lm','-o',binary])
                header=binary.read_bytes()[:20]
                c.require(header[:6]==b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little')==(62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage]=dict(compiled=True,**c.assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                row['host_native_executed' if isa=='host' else 'arm64_executed']=True
        row['artifact_sha256']={p.name:c.digest(p) for p in output.iterdir() if p.is_file()}
        c.require(c.digest(image)==c.IMAGE_SHA)
        c.require(all(c.digest(Path(p))==sha for p,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indices[int(r,16)])==sha for r,sha in row['index_sha256'].items()))
        c.require(all(c.digest(upstream/n)==sha for n,sha in row['upstream_files'].items()))
        row.update(success=True,dependencies_newly_resolved=2,original_behaviour_newly_executable=['1800','17d0','1820 no-create lookup'])
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__); raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for r in UNITS: p.add_argument('--index-'+format(r,'x'),type=Path,required=True)
    p.add_argument('--output',type=Path,required=True); a=p.parse_args()
    try: run({r:getattr(a,'index_'+format(r,'x')) for r in UNITS},a.output)
    except Exception: p.exit(1,'Table lookup check rejected; inspect private receipt.\n')
    print('No-create lookup matched host/Linux-AArch64; NOT whole opener or Android.')


if __name__=='__main__': main()
