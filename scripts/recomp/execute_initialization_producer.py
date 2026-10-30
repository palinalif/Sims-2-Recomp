#!/usr/bin/env python3
"""E2 producer 109D0 + real 10700, third-argument-zero path only.

Authored infrastructure only; all original-derived artifacts stay private.
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
import execute_initialization_setter as common
from measure_startup import decode_flow, dependencies

ROOT, BASE, PAGES, REGS = common.ROOT, common.BASE, common.PAGES, common.REGS
RVA, SIZE, COUNT = 0x109d0, 61, 18
FUNCTION_SHA = 'c1fe91465d96cfc7b4a5485445ffb0320bd24e69640260e60f008603d0269fe7'
MODES = ('valid', 'wrong-slot', 'wrong-cleanup')
require = common.require


def state(n, layout='separate'):
    require(type(n) is int and 0 <= n < 64 and layout in ('separate', 'inline'))
    rng = random.Random((RVA << 8)+n)
    pages = {p:bytearray(rng.randbytes(4096)) for p in PAGES}
    regs = {r:rng.getrandbits(32) for r in REGS}
    regs['esp'] = common.DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    obj = common.DATA_PAGES[1]+(0x80 if n % 2 else 0xe00)
    link = common.DATA_PAGES[2]+(0xe00 if n % 2 else 0x80)
    if layout == 'inline':
        # Established opener storage: H is a bounded 0x210-byte handle,
        # publication slot H+78 and service object H+7C share one page.
        # This authors storage, not allocation, lifetime or service responses.
        handle = common.DATA_PAGES[1]+(0x40 if n % 2 else 0xc00)
        link, obj = handle+0x78, handle+0x7c
    # Incoming EDI varies: producer must save it, load zero for real callee,
    # and restore it. Object and link are separate aligned bounded storage.
    struct.pack_into('<4I', pages[PAGES[0]], regs['esp']-PAGES[0], common.RETURN, obj, link, 0)
    return regs, pages


def arguments(regs, pages, layout='separate'):
    require(layout in ('separate', 'inline'))
    ret, obj, link, kind = struct.unpack_from('<4I', pages[PAGES[0]], regs['esp']-PAGES[0])
    require(ret == common.RETURN and kind == 0)
    require(obj % 4 == link % 4 == 0 and PAGES[1] <= obj <= PAGES[1]+4096-0x50)
    if layout == 'separate':
        require(PAGES[2] <= link <= PAGES[2]+4092)
    else:
        require(obj == link+4 and PAGES[1] <= link-0x78 <= PAGES[1]+4096-0x210)
    return obj, link


def oracle(regs, pages, layout='separate'):
    """Independent final write/ABI contract, including retained nested frames."""
    obj, link = arguments(regs, pages, layout)
    after = {p:bytearray(b) for p,b in pages.items()}
    def put(page, address, value):
        struct.pack_into('<I', after[page], address-page, value)
    put(PAGES[0], regs['esp']-4, regs['edi'])
    put(PAGES[0], regs['esp']-8, BASE+0x109da)
    for offset, value in ((0, BASE+0x10970), (4, BASE+0x109a0),
                          (0x34, BASE+0xfcf0), (0x4c, link)):
        put(PAGES[1], obj+offset, value)
    after[PAGES[1]][obj-PAGES[1]+0x49] = 6
    put(PAGES[1] if layout == 'inline' else PAGES[2], link, obj)
    out = dict(regs, eax=1, ecx=obj, esp=regs['esp']+4)
    return dict(regs=[out[r] for r in REGS], pages=b''.join(after[p] for p in PAGES).hex())


def check_index(envelope):
    context = common.index_context(envelope, RVA)
    f = envelope['result']['function']; d = f['disassembly']
    require(f['resolution'] == 'function-at' and int(f['entryRva'],16) == RVA)
    require(d['instructionCount'] == COUNT and d['extentBytes'] == SIZE and
            int(d['extentEndVa'],16) == BASE+RVA+SIZE-1 and len(d['items']) == COUNT and
            int(d['items'][0]['va'],16) == BASE+RVA)
    require(not any(v for k,v in envelope['result']['truncation'].items() if k != 'counts'))
    context['reliable_boundaries'] = True
    return context


def assemble(bodies):
    require(set(bodies) == {RVA, common.CLASSIFIER} and all(type(b) is str and b.strip() for b in bodies.values()))
    names = {RVA:'initialization_producer_109D0', common.CLASSIFIER:common.body_name(common.CLASSIFIER)}
    text = common.TEMPLATE.read_text()
    replacements = {
        '@PROTOTYPES@':'\n'.join('static void '+names[r]+'(void);' for r in names)+
            '\nstatic constexpr unsigned address_sub_A0010700=0xA0010700u;\n'
            'static constexpr unsigned address_sub_A000FCB0=0xA000FCB0u;',
        '@SELECT@':'\n'.join(f'case 0x{BASE+r:08X}u: {names[r]}();break;' for r in names),
        '@ADAPTERS@':'\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{BASE+r:08X}u,s);}}' for r in names),
        '@CALLBACKS@':'\n'.join(f'case 0x{BASE+r:08X}u:callback=adapter_{r:X};break;' for r in names),
        '@DIRECT_RETURNS@':'if(caller==0xA00109D0u && target==0xA0010700u) return 0xA00109DAu;',
        '@INDIRECT_RETURNS@':'', '@BODY@':'\n'.join(bodies.values()),
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)':'cache_invoke(0xA00109D0u,in,adapter_109D0)',
    }
    for old,new in replacements.items():
        require(text.count(old) == 1)
        text = text.replace(old,new)
    for body in bodies.values(): require(text.count(body) == 1)
    return text


def bridge_source(text, mode):
    require(mode in MODES)
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    require(text.count(old) == 1)
    text = text.replace(old,'constexpr std::array<uint32_t,2> targets{0xA00109D0u,0xA0010700u};')
    if mode == 'wrong-slot':
        old = '    check(a,size,true);'
        # Perturb producer object stores only; preserve genuine nested frames.
        new = old+'\n    if(size==4 && a>=0x72000000u && a<0x72001000u) a+=4;'
    elif mode == 'wrong-cleanup':
        old = '    current(s.data());'
        new = old+'\n    if(depth==1) s[7]+=8;'
    else: return text
    require(text.count(old) == 1)
    return text.replace(old,new)


def run(output, index, classifier_index, layout='separate'):
    require(layout in ('separate', 'inline'))
    output = common.private_output(output)
    row = dict(schema='ts2-initialization-producer-zero-native/1', success=False,
        rva=hex(RVA), size=SIZE, selected=1, attempted=False, lifted=False,
        image_sha256=common.IMAGE_SHA, pcrecomp_revision=common.REVISION,
        harness_sha256=common.digest(Path(__file__)), helper_sha256=common.digest(Path(common.__file__)),
        template_sha256=common.digest(common.TEMPLATE), bridge_sha256=common.digest(common.BRIDGE),
        invocation=[sys.executable,*sys.argv], commands=[], timings={}, runs={}, functions={},
        arm64_executed=False, android_executed=False, stub=False,
        path_contract=dict(storage_layout=layout, third_argument=0, real_callee='0x10700', external_target_executed=False,
                           whole_function_verified=False),
        compared=['eight final GPRs including ESP', 'six complete 4096-byte pages including nested frames'],
        limits=['zero third argument only; classifier scan and producer failure path unverified',
                'separate storage or fixed inline H+78/H+7C layout only; no arbitrary alias, lifetime or opener execution proof',
                'callback addresses stored as data, never invoked',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no E3/E4 or Android execution'])
    stage = 'preflight'
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err, cwd=ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        require(child.returncode == 0)
    try:
        start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(common.digest(image) == common.IMAGE_SHA)
        row['indexes'] = {'producer':check_index(json.loads(index.read_text())),
                          'classifier':common.check_index(json.loads(classifier_index.read_text()),common.CLASSIFIER)}
        row['index_sha256'] = [common.digest(index),common.digest(classifier_index)]
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        common.verify(pristine)
        locked = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        require(all(common.digest(upstream/n) == common.digest(pristine/n) for n in used))
        row['upstream_files'] = {n:common.digest(upstream/n) for n in used}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'fresh-lift'; start = time.monotonic(); row['attempted'] = True
        bodies, nodes, code_pages = {}, {}, {}
        for rva,size,sha,name,index_path,callees in (
            (RVA,SIZE,FUNCTION_SHA,'initialization_producer_109D0',index,['0x10700']),
            (common.CLASSIFIER,49,common.CLASSIFIER_SHA,common.body_name(common.CLASSIFIER),classifier_index,['0xfcb0'])):
            code = pe.get_data(rva,size)
            require(hashlib.sha256(code).hexdigest() == sha)
            function, decoded, _, _ = decode_flow(code,BASE+rva,LinearInstruction)
            deps = dependencies(decoded,pe)
            require(deps['direct_calls'] == callees and deps['indirect_calls'] == 0 and
                    not deps['absolute_memory_va'] and not deps['segmented_memory_operands'])
            function.name = name
            blocks = tuple((a-BASE-rva,b.instructions[-1].address+b.instructions[-1].size-BASE-rva)
                           for a,b in sorted(function.blocks.items()))
            body = Lifter(precise_carry=True).lift_function(function)
            require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
            bodies[rva] = body; (output/f'{rva:x}-lifted.c').write_text(body)
            row['functions'][hex(rva)] = dict(function_sha256=sha, size=size, dependencies=deps,
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(BASE+rva),blocks=blocks,name=name))
            require(not set(nodes) & set(decoded)); nodes.update(decoded)
            indexed = json.loads(index_path.read_text())['result']['function']['disassembly']['items']
            require([int(i['va'],16) for i in indexed] == sorted(decoded))
            page = BASE+(rva//4096)*4096
            code_pages.setdefault(page,bytearray(4096))[rva%4096:rva%4096+size] = code
        row['lifted'] = True; row['timings']['translation'] = time.monotonic()-start
        stage = 'original-reference'; start = time.monotonic()
        expected, inputs, visited = [], bytearray(), set()
        for n in range(64):
            regs,pages = state(n,layout)
            result,seen = common.reference(nodes,code_pages,BASE+RVA,regs,pages,budget=64)
            require(result == oracle(regs,pages,layout))
            require(seen & {BASE+a for a in range(common.CLASSIFIER,common.CLASSIFIER+49)} ==
                    {BASE+a for a in common.CLASSIFIER_PATH})
            require(BASE+0xfcb0 not in seen)
            require(sum(BASE+RVA <= a < BASE+RVA+SIZE for a in seen) == 16 and len(seen) == 20)
            expected.append(dict(case=n,**result)); visited.update(seen)
            inputs.extend(struct.pack('<8I',*(regs[r] for r in REGS)))
            inputs.extend(b''.join(pages[p] for p in PAGES))
        row['coverage'] = dict(visited=len(visited),total=len(nodes),
            producer_visited=sum(BASE+RVA <= a < BASE+RVA+SIZE for a in visited),producer_total=COUNT,
            classifier_visited=4,classifier_total=21)
        row['x86_oracle_matches'] = 64
        row['timings']['x86_reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(bodies))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(common.BRIDGE.read_text(),mode))
            for isa in ('host','arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(ROOT/'native/include'),transport,bridge,ROOT/'native/src/guest_memory.cpp',
                    ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
                h = binary.read_bytes()[:20]
                require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage] = dict(compiled=True,**common.assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                if isa == 'arm64': row['arm64_executed'] = True
        row['artifact_sha256'] = {n:common.digest(output/n) for n in
            ('109d0-lifted.c','10700-lifted.c','transport.cpp','reference.json','input.bin')}
        require(common.digest(image) == common.IMAGE_SHA)
        require(all(common.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__)
        raise
    finally: (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--index',type=Path,required=True)
    p.add_argument('--classifier-index',type=Path,required=True)
    p.add_argument('--layout',choices=('separate','inline'),default='separate')
    a = p.parse_args()
    try: run(a.output,a.index,a.classifier_index,a.layout)
    except Exception: p.exit(1,'Producer failed; inspect private receipt.\n')
    print('109D0 zero path: 64/64 host + Linux/AArch64; two controls reject. NOT Android.')


if __name__ == '__main__': main()
