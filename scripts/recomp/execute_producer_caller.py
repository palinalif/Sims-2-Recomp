#!/usr/bin/env python3
"""Fresh 20D0 composition: both real producers; failure uses null-provider 1460.

No service responses are authored. Nonnull service and incoming ownership remain
unverified. Original-derived artifacts are written only to private ignored work/.
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
import execute_classifier_scan as scan
import execute_service_guard as guard
import probe_producer_input as caller
from measure_startup import decode_flow, dependencies
c = scan.c
RVA = caller.RVA
TARGETS = (RVA, scan.producer.RVA, scan.ALTERNATE, c.CLASSIFIER, c.MODULE_COMPARE, guard.RVA)
MODES = ('valid', 'wrong-result', 'wrong-cleanup', 'wrong-slot')


def state(n, images):
    c.require(type(n) is int and 0 <= n < 128)
    regs, pages, sample = scan.producer_state(n // 2, images)
    _, obj, link, pointer = struct.unpack_from('<4I', pages[scan.PAGES[0]], regs['esp']-scan.PAGES[0])
    handle = link-0x78
    regs['eax'] = handle
    # Every scan fixture is run through BOTH branches. These are receiver data,
    # not fabricated callee behavior or a claim about upstream object lifetime.
    for offset, value in ((0x74, 0), (0xd0, pointer), (0xd4, n % 2)):
        struct.pack_into('<I', pages[scan.PAGES[1]], handle-scan.PAGES[1]+offset, value)
    return regs, pages, sample


def contract(regs, pages, sample, result):
    """Independent non-stack/return/preserved-register contract, not full oracle."""
    sp, handle = regs['esp'], regs['eax']
    c.require(set(pages) == set(scan.PAGES) and all(len(b) == 4096 for b in pages.values()))
    c.require(scan.PAGES[1] <= handle <= scan.PAGES[1]+4096-0x210)
    objoff = handle-scan.PAGES[1]
    provider, = struct.unpack_from('<I', pages[scan.PAGES[1]], objoff+0x74)
    pointer, selector = struct.unpack_from('<2I', pages[scan.PAGES[1]], objoff+0xd0)
    c.require(provider == 0 and selector in (0, 1))
    names = scan.names_from_pages({p:pages[p] for p in scan.IMAGES})
    matches = [i for i, name in enumerate(names) if c.comparison_equal(name, sample)]
    value = 6 if pointer == 0 else matches[0] if matches else 0xffffffff
    success = value != 0xffffffff
    out = result['regs']
    c.require(len(out) == 8 and out[0] == (0 if success else 18) and out[7] == sp+4)
    for r in ('ebx', 'ebp', 'esi', 'edi'):
        c.require(out[c.REGS.index(r)] == regs[r])
    after = {p:bytearray(b) for p,b in pages.items()}
    if success:
        _, first, second = scan.producer_profile(scan.ALTERNATE if selector else scan.producer.RVA)
        obj, link = handle+0x7c, handle+0x78
        for offset, word in ((0, c.BASE+first), (4, c.BASE+second),
                             (0x34, c.BASE+0xfcf0), (0x4c, link)):
            struct.pack_into('<I', after[scan.PAGES[1]], obj-scan.PAGES[1]+offset, word)
        after[scan.PAGES[1]][obj-scan.PAGES[1]+0x49] = value
        struct.pack_into('<I', after[scan.PAGES[1]], link-scan.PAGES[1], obj)
    final = bytes.fromhex(result['pages'])
    c.require(len(final) == len(scan.PAGES)*4096)
    c.require(final[4096:] == b''.join(after[p] for p in scan.PAGES[1:]))
    if not success:
        # Retained argument proves 20D0 passed H+D0 to 1460; guard never writes it.
        c.require(struct.unpack_from('<I', final, sp-scan.PAGES[0]-8)[0] == pointer)
        c.require(out[c.REGS.index('edx')] == 0)
    return selector, value


def assemble(bodies):
    c.require(set(bodies) == set(TARGETS) and all(isinstance(b,str) and b.strip() for b in bodies.values()))
    name = lambda r: f'producer_caller_{r:X}'
    declarations = '\n'.join(f'static void {name(r)}(void);' for r in TARGETS)
    declarations += '\n'+'\n'.join(f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;'
                                  for r in (*TARGETS, 0x102d0, 0x831a6f))
    replacements = {
        '@PROTOTYPES@': declarations,
        '@SELECT@': '\n'.join(f'case 0x{c.BASE+r:08X}u: {name(r)}();break;' for r in TARGETS),
        '@ADAPTERS@': '\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}' for r in TARGETS),
        '@CALLBACKS@': '\n'.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in TARGETS),
        '@DIRECT_RETURNS@': '\n'.join(f'if(caller==0x{c.BASE+a:08X}u && target==0x{c.BASE+b:08X}u) return 0x{c.BASE+d:08X}u;'
                                    for a,b,d in ((RVA,guard.RVA,0x210f),(scan.producer.RVA,c.CLASSIFIER,0x109da),
                                                  (scan.ALTERNATE,c.CLASSIFIER,0x10b6a),(c.CLASSIFIER,c.MODULE_COMPARE,0x1071e))),
        '@INDIRECT_RETURNS@': 'if(caller==0xA00020D0u && (target==0xA00109D0u || target==0xA0010B60u)) return 0xA00020F8u;',
        '@BODY@': '\n'.join(bodies[r] for r in TARGETS),
        'for(unsigned n=0;n<64;++n)': 'for(unsigned n=0;n<128;++n)',
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA00020D0u,in,adapter_20D0)',
    }
    text = c.TEMPLATE.read_text()
    for old,new in replacements.items():
        c.require(text.count(old) == 1); text = text.replace(old,new)
    for body in bodies.values(): c.require(text.count(body) == 1)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = scan.bridge_source(c.BRIDGE.read_text(), 'valid')
    old = 'constexpr std::array<uint32_t,2> targets{0xA0010700u,0xA000FCB0u};'
    new = 'constexpr std::array<uint32_t,6> targets{'+','.join(f'0x{c.BASE+r:08X}u' for r in TARGETS)+'};'
    c.require(text.count(old) == 1); text = text.replace(old,new)
    if mode == 'wrong-slot':
        old = '    check(a,size,true);'
        new = old+'\n    if(size==4 && a>=0x72000000u && a<0x72001000u) a+=4;'
    elif mode != 'valid':
        old = '    current(s.data());'
        new = old+'\n    if(depth==1) '+('s[0]^=4;' if mode == 'wrong-result' else 's[7]+=8;')
    else: return text
    c.require(text.count(old) == 1)
    return text.replace(old,new)


def assess(text, expected, mode):
    """Strict complete transport; malformed output is never a behavioral kill."""
    c.require(mode in MODES and len(expected) == 128)
    rows = [json.loads(line) for line in text.splitlines()]
    c.require(len(rows) == 128)
    for n,row in enumerate(rows):
        c.require(type(row) is dict and set(row) == {'case','regs','pages'} and
                  type(row['case']) is int and row['case'] == n)
        c.require(type(row['regs']) is list and len(row['regs']) == 8 and
                  all(type(v) is int and 0 <= v <= 0xffffffff for v in row['regs']))
        c.require(type(row['pages']) is str and len(row['pages']) == 6*8192 and
                  all(ch in '0123456789abcdef' for ch in row['pages']))
    differences = [n for n,(a,b) in enumerate(zip(rows,expected)) if a != b]
    if mode == 'valid': c.require(not differences)
    elif mode == 'wrong-slot':
        publications = {n for n,b in enumerate(expected) if b['regs'][0] == 0}
        c.require(publications and publications <= set(differences))
    else: c.require(len(differences) == 128)
    return dict(cases=128,matched=128-len(differences),differences=len(differences),
                negative_control_rejected=mode != 'valid')


def run(indexes, output):
    output = c.private_output(output)
    row = dict(schema='ts2-producer-caller-native/1', success=False, rva=hex(RVA),
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        invocation=[sys.executable,*sys.argv], commands=[], functions={}, runs={},
        lifted=False, host_native_executed=False, arm64_executed=False, android_executed=False,
        stub=False, dependencies_newly_resolved=0, whole_function_verified=False,
        compared=['eight final GPRs', 'six complete pages including nested frames'],
        limits=['20D0 both producer selections; fallback restricted to null H+74',
                'synthetic bounded receiver data, not upstream field writers or lifetime',
                'partial independent semantic oracle; full state oracle is original x86',
                'no flags/FP/PC/native transient writes, nonnull service, allocator or Android',
                'diagnostic GuestMemory/exact-VA composition, not whole 1AB665/E3/E4'])
    stage = 'preflight'
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err, cwd=c.ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    try:
        c.require(set(indexes) == set(TARGETS))
        row['source_sha256'] = {str(p.relative_to(c.ROOT)):c.digest(p) for p in
            (Path(__file__).resolve(), Path(scan.__file__), Path(guard.__file__), Path(caller.__file__),
             Path(c.__file__), Path(scan.producer.__file__),
             c.ROOT/'scripts/recomp/execute_cache_dispatch.py',
             c.ROOT/'scripts/recomp/measure_startup.py',
             c.ROOT/'scripts/recomp/inspect_startup_dependency.py', c.TEMPLATE,c.BRIDGE)}
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        c.require(all(c.digest(upstream/n) == c.digest(pristine/n) for n in used))
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        bodies, nodes, code_pages = {}, {}, {}
        stage = 'fresh-lift'; start = time.monotonic()
        for r in TARGETS:
            if r == RVA: sha,size = caller.FUNCTION_SHA,caller.SIZE
            elif r == guard.RVA: sha,size = guard.FUNCTION_SHA,guard.SIZE
            elif r in (scan.producer.RVA,scan.ALTERNATE): sha,size = scan.producer_profile(r)[0],scan.producer.SIZE
            else: _,sha,size,_,_ = c.unit(r)
            code = pe.get_data(r,size); c.require(hashlib.sha256(code).hexdigest() == sha)
            function, decoded, _, flow = decode_flow(code,c.BASE+r,LinearInstruction)
            meta = dict(flow,instruction_rvas=[hex(a-c.BASE) for a in sorted(decoded)])
            context = guard.crosscheck_index(json.loads(indexes[r].read_text()),meta,r)
            function.name = f'producer_caller_{r:X}'
            body = Lifter(precise_carry=True).lift_function(function)
            c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
            bodies[r] = body; (output/f'{r:x}-lifted.c').write_text(body)
            row['functions'][hex(r)] = dict(function_sha256=sha,size=size,index=context,
                index_sha256=c.digest(indexes[r]),dependencies=dependencies(decoded,pe),
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+r),name=function.name,
                    blocks=[(a-c.BASE-r,b.instructions[-1].address+b.instructions[-1].size-c.BASE-r)
                            for a,b in sorted(function.blocks.items())]))
            c.require(not set(nodes) & set(decoded)); nodes.update(decoded)
            page = c.BASE+r//4096*4096
            code_pages.setdefault(page,bytearray(4096))[r%4096:r%4096+size] = code
        row.update(lifted=True,translation_seconds=time.monotonic()-start)
        stage = 'original-reference'
        images = {p:pe.get_data(p-c.BASE,4096) for p in scan.IMAGES}
        row['image_pages_sha256'] = {hex(p):hashlib.sha256(b).hexdigest() for p,b in images.items()}
        expected, inputs, visited, counts = [], bytearray(), set(), {}
        for n in range(128):
            regs,pages,sample = state(n,images)
            observed,seen = c.reference(nodes,code_pages,c.BASE+RVA,regs,pages,budget=4096,image_pages=scan.IMAGES)
            selector,value = contract(regs,pages,sample,observed)
            key = f'{selector}:{value}'; counts[key] = counts.get(key,0)+1
            if value == 0xffffffff:
                c.require({c.BASE+a for a in guard.GUARD_PATH} <= seen)
            else: c.require(c.BASE+guard.RVA not in seen)
            visited |= seen; expected.append(dict(case=n,**observed))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in scan.PAGES))
        c.require(set(counts) == {f'{s}:{v}' for s in (0,1) for v in (*range(7),0xffffffff)})
        caller_nodes = {a for a in nodes if c.BASE+RVA <= a < c.BASE+RVA+caller.SIZE}
        c.require(len(caller_nodes) == 26 and caller_nodes <= visited)
        row.update(x86_semantic_contract_matches=128,coverage=dict(visited=len(visited),total=len(nodes),
            caller_visited=len(visited & caller_nodes),caller_total=len(caller_nodes),outcome_counts=counts))
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(bodies))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(mode))
            for isa in ('host','arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,c.ROOT/'native/src/guest_memory.cpp',
                    c.ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
                h = binary.read_bytes()[:20]
                c.require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                text = (output/(stage+'-execute.stdout')).read_text()
                row['runs'][stage] = dict(compiled=True,**assess(text,expected,mode))
                if isa == 'host': row['host_native_executed'] = True
                else: row['arm64_executed'] = True
        row['artifact_sha256'] = {p.name:c.digest(p) for p in (output/'reference.json',output/'input.bin',transport,
            *(output/f'{r:x}-lifted.c' for r in TARGETS))}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        c.require(all(c.digest(c.ROOT/n) == sha for n,sha in row['source_sha256'].items()))
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__); raise
    finally: (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index',action='append',required=True,help='RVA=private query envelope')
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    indexes = {}
    for item in a.index:
        r,path = item.split('=',1); r = int(r,16)
        if r in indexes: p.error('duplicate index')
        indexes[r] = Path(path)
    try: run(indexes,a.output)
    except Exception: p.exit(1,'Producer caller failed; inspect private receipt.\n')
    print('20D0 bounded composition: 128 cases host + Linux/AArch64; NOT nonnull service or Android.')


if __name__ == '__main__': main()
