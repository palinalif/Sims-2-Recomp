#!/usr/bin/env python3
"""F2: whole pinned lift, ONLY the populated +34 early-return E3 fragment.

No opener, service, callback or other callee is registered. Private artifacts only.
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
import inspect_classifier_paths as probe
from inspect_initialization_graph import seed_receipt
from measure_startup import decode_flow, dependencies
c = probe.c
RVA, SIZE = 0x1ab665, 267
FUNCTION_SHA = '6c35c08430e158c83c52e190dacc59e507d1683e57f0b10cc735a620eb8ff4fe'
GUARD_PATH = (0x1ab665,0x1ab666,0x1ab668,0x1ab669,0x1ab66b,0x1ab66e,
              0x1ab766,0x1ab769,0x1ab76a,0x1ab76b)
MODES = ('valid','wrong-result','wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random((RVA<<8)+n)
    regs = {r:rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0]+(0x800 if n%2 else 0xc00)
    regs['ecx'] = c.DATA_PAGES[1]+(0x80 if n%2 else 0xe00)
    pages = {p:bytearray(rng.randbytes(4096)) for p in probe.PAGES}
    struct.pack_into('<I',pages[c.DATA_PAGES[0]],regs['esp']-c.DATA_PAGES[0],c.RETURN)
    off = regs['ecx']-c.DATA_PAGES[1]
    # Populated handle values are opaque data: include unmapped/high-bit values.
    value = (1,0xffffffff,0x80000000,0x12345678)[n%4] if n<32 else rng.getrandbits(32) or 1
    struct.pack_into('<I',pages[c.DATA_PAGES[1]],off+0x34,value)
    struct.pack_into('<I',pages[c.DATA_PAGES[1]],off+0x1c,0 if n%2 else 0xffffffff)
    # Retain nontrivial upper EAX and guarantee a visible AL write.
    regs['eax'] = (regs['eax'] & 0xffffff00) | (0 if n%2 else 0xff)
    return regs,pages


def oracle(regs,pages):
    obj = regs['ecx']; sp = regs['esp']
    c.require(set(regs) == set(c.REGS) and set(pages) == set(probe.PAGES))
    c.require(c.DATA_PAGES[1] <= obj <= c.DATA_PAGES[1]+4096-0x38 and obj%4==0)
    c.require(sp in (c.DATA_PAGES[0]+0x800,c.DATA_PAGES[0]+0xc00))
    c.require(struct.unpack_from('<I',pages[c.DATA_PAGES[0]],sp-c.DATA_PAGES[0])[0] == c.RETURN)
    c.require(struct.unpack_from('<I',pages[c.DATA_PAGES[1]],obj-c.DATA_PAGES[1]+0x34)[0] != 0)
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<II',after[c.DATA_PAGES[0]],sp-c.DATA_PAGES[0]-8,regs['edi'],regs['esi'])
    out = dict(regs,eax=(regs['eax'] & 0xffffff00)|1,esp=sp+4)
    return dict(regs=[out[r] for r in c.REGS],pages=b''.join(after[p] for p in probe.PAGES).hex())


def check_dependencies(deps, seed):
    c.require(not deps['indirect_calls'] and not deps['absolute_memory_va'] and not deps['segmented_memory_operands'])
    # Decoder preserves encounter order; the settled inventory is RVA-sorted.
    c.require(len(deps['direct_calls']) == len(seed['direct']) and
              set(deps['direct_calls']) == set(seed['direct']))


def assemble(body,callees):
    c.require(type(body) is str and body.strip())
    # Addresses only, not responses, bodies, callback registrations or return edges.
    expected = {'0x1030','0x1070','0x1090','0x10a0','0x10b0','0x10c0','0x10e0',
                '0x1100','0x1110','0x1120','0x1130','0x1140','0x3a50','0x3c50'}
    c.require(set(callees) == expected and len(callees) == len(expected))
    declarations = '\n'.join(f'static constexpr unsigned address_sub_{c.BASE+int(r,16):08X}=0x{c.BASE+int(r,16):08X}u;' for r in callees)
    replacements = {
        '@PROTOTYPES@':'static void initialization_guard_1AB665(void);\n'+declarations,
        '@SELECT@':'case 0xA01AB665u: initialization_guard_1AB665();break;',
        '@ADAPTERS@':'static void adapter_1AB665(uint32_t* s) {select_body(0xA01AB665u,s);}',
        '@CALLBACKS@':'case 0xA01AB665u:callback=adapter_1AB665;break;',
        '@DIRECT_RETURNS@':'','@INDIRECT_RETURNS@':'','@BODY@':body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)':'cache_invoke(0xA01AB665u,in,adapter_1AB665)',
    }
    text = c.TEMPLATE.read_text()
    for old,new in replacements.items():
        c.require(text.count(old)==1); text=text.replace(old,new)
    c.require(text.count(body)==1)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = c.BRIDGE.read_text()
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    c.require(text.count(old)==1)
    text = text.replace(old,'constexpr std::array<uint32_t,1> targets{0xA01AB665u};')
    c.require(text.count('0xA0009000u')==1)
    text = text.replace('0xA0009000u','0xA1050000u')
    if mode != 'valid':
        old = '    current(s.data());'
        c.require(text.count(old)==1)
        text = text.replace(old,old+ ('\n    s[0]=1;' if mode=='wrong-result' else '\n    s[7]+=8;'))
    return text


def run(output):
    output = c.private_output(output)
    row = dict(schema='ts2-initialization-populated-guard-native/1',success=False,
        rva=hex(RVA),size=SIZE,image_sha256=c.IMAGE_SHA,pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)),probe_sha256=c.digest(Path(probe.__file__)),
        helper_sha256=c.digest(Path(c.__file__)),template_sha256=c.digest(c.TEMPLATE),bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable,*sys.argv],commands=[],runs={},timings={},
        lifted=False,arm64_executed=False,android_executed=False,stub=False,
        whole_function_verified=False,e3_fragment=True,e3_complete=False,e4_complete=False,
        compared=['eight final GPRs including ESP','six complete 4096-byte pages including retained saved-register words'],
        limits=['ONLY populated receiver+34 early-return path; no opener or other callee execution',
                'Authored bounded receiver, not producer/input/lifetime/callback ownership proof',
                'No flags/FP/PC/native transient-write comparison',
                'Diagnostic GuestMemory/exact-VA bridge, not production integration or Android'])
    def command(name,argv,data=None):
        rec=dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec)
        start=time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            child=subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=c.ROOT,timeout=180)
        rec.update(exit_code=child.returncode,seconds=time.monotonic()-start)
        c.require(child.returncode==0)
    stage='preflight'
    try:
        image=c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image)==c.IMAGE_SHA)
        row['seed']=seed_receipt(c.ROOT/'work/recomp-bench/frontier-d3-sibling-final/result.json')
        upstream=c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine=c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked=json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used=[n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        c.require(all(c.digest(upstream/n)==c.digest(pristine/n) for n in used))
        row['upstream_files']={n:c.digest(upstream/n) for n in used}
        import pefile
        pe=pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase==c.BASE and pe.FILE_HEADER.Machine==0x14c)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve()==(upstream/'tools/lift/lift32.py').resolve())
        stage='fresh-lift';start=time.monotonic()
        code=pe.get_data(RVA,SIZE);c.require(hashlib.sha256(code).hexdigest()==FUNCTION_SHA)
        function,nodes,_,_=decode_flow(code,c.BASE+RVA,LinearInstruction)
        c.require(len(nodes)==83)
        deps=dependencies(nodes,pe)
        check_dependencies(deps,row['seed'])
        function.name='initialization_guard_1AB665'
        body=Lifter(precise_carry=True).lift_function(function)
        c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
        (output/'lifted.c').write_text(body)
        row.update(lifted=True,function_sha256=FUNCTION_SHA,dependencies=deps,
            lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+RVA),name=function.name))
        row['timings']['translation']=time.monotonic()-start
        stage='original-reference';start=time.monotonic()
        code_pages={c.BASE+0x1ab000:bytearray(4096)}
        code_pages[c.BASE+0x1ab000][0x665:0x665+SIZE]=code
        expected,inputs=[],bytearray()
        for n in range(64):
            regs,pages=state(n)
            result=probe.trace(nodes,code_pages,c.BASE+RVA,regs,pages)
            c.require(result['outcome']=='returned' and result['visited']==[c.BASE+a for a in GUARD_PATH])
            observed={k:result[k] for k in ('regs','pages')}
            c.require(observed==oracle(regs,pages))
            expected.append(dict(case=n,**observed))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in probe.PAGES))
        row.update(x86_oracle_matches=64,coverage=dict(visited=10,total=83,callee_calls=0))
        row['timings']['reference_and_oracle']=time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected));(output/'input.bin').write_bytes(inputs)
        transport=output/'transport.cpp';transport.write_text(assemble(body,deps['direct_calls']))
        for mode in MODES:
            bridge=output/(mode+'.cpp');bridge.write_text(bridge_source(mode))
            for isa in ('host','arm64'):
                stage=mode+'-'+isa;binary=output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,c.ROOT/'native/src/guest_memory.cpp',
                    c.ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
                header=binary.read_bytes()[:20]
                c.require(header[:6]==b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little')==(62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage]=dict(compiled=True,**c.assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                if isa=='arm64':row['arm64_executed']=True
        row['artifact_sha256']={n:c.digest(output/n) for n in ('lifted.c','transport.cpp','reference.json','input.bin')}
        c.require(c.digest(image)==c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n)==sha for n,sha in row['upstream_files'].items()))
        row['success']=True
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__)
        raise
    finally:(output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:run(a.output)
    except Exception:p.exit(1,'Guard fragment failed; inspect private receipt.\n')
    print('Populated +34 guard: 64/64 host + Linux/AArch64; two controls reject. Fragment ONLY; NOT Android.')

if __name__=='__main__':main()
