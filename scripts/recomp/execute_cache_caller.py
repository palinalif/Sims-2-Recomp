#!/usr/bin/env python3
"""Authorized whole cache caller: fresh lifts, original x86 vs GuestMemory on two ISAs.

All proprietary outputs stay private. Whole-sample synthetic owned ranges only;
not proof of range writers, lifetime, arbitrary text, Android or game startup.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from execute_cache_dispatch import (BASE, PAGES, IMAGE_PAGES, DATA_PAGES, REGS,
    RETURN, reference, entry_state, compare, thunk_function)
from execute_cache_skip import CLOSURE, private_output, require
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify
from measure_startup import decode_flow, supported
from measure_local_switch import decode_switch
from inspect_startup_dependency import crosscheck_index

RVA=0x1abd40
TEMPLATE=Path(__file__).with_name('cache_caller_transport.cpp.in')
BRIDGE=Path(__file__).with_name('cache_caller_memory.cpp')


def caller_state(n,rng,image_pages):
    regs,pages=entry_state(n,0x1290,rng,image_pages,complete_units=True)
    receiver=DATA_PAGES[3]+128
    handle=DATA_PAGES[1]+128
    regs['ecx']=receiver
    struct.pack_into('<I',pages[DATA_PAGES[3]],128+0x34,handle)
    # Deterministic independent payload fields for the three earlier callees.
    for off,value in ((0xfc,(0,1,0xffffffff,0x80000000)[n%4]),
                      (0x18,rng.getrandbits(32)),(0x1c,rng.getrandbits(32)),
                      (0x104,0 if n%3==0 else DATA_PAGES[2]+192)):
        struct.pack_into('<I',pages[DATA_PAGES[1]],128+off,value)
    return regs,pages


def assert_poststate(regs,pages,state):
    """Independent documented cache/cleanup contract, not a callee response.

    Counter values are observed, not inferred encoding semantics. The cache must
    agree with those live counter words after real callees run.
    """
    final=bytes.fromhex(state['pages'])
    require(len(final)==len(PAGES)*4096)
    def before(p,off):return struct.unpack_from('<I',pages[p],128+off)[0]
    def after(p,off):return struct.unpack_from('<I',final,PAGES.index(p)*4096+128+off)[0]
    h,r=DATA_PAGES[1],DATA_PAGES[3]
    end=before(h,0x100)
    expected={0x80:before(h,0xfc),0x84:(after(h,0x1c8)+1)&0xffffffff,
              0x88:after(h,0x1cc),
              0x8c:((before(h,0x18)-before(h,0x1c)+end)&0xffffffff) if end else 0xffffffff,
              0x90:((before(h,0x104)-end)&0xffffffff) if end and before(h,0x104) else 0}
    require(all(after(r,off)==v for off,v in expected.items()))
    require(after(h,0x108)==(end if end else before(h,0x108)))
    require(after(r,0x34)==before(r,0x34))
    require(state['regs'][-1]==regs['esp']+4)
    require(state['regs'][0]==((expected[0x90]&0xffffff00)|int(expected[0x80]!=0)))


def assemble(bodies,direct,indirect):
    require(set(bodies)==set(CLOSURE) and all(supported(b) and b.strip() for b in bodies.values()))
    require(set(direct)==set(CLOSURE[1:6]) and set(indirect)=={0x1290,0x12d0})
    replacements={
        '@PROTOTYPES@':'\n'.join(f'static void startup_{r:06X}(void);\nstatic const uint32_t address_startup_{r:06X}=0x{BASE+r:08X}u;\nstatic const uint32_t address_sub_{BASE+r:08X}=0x{BASE+r:08X}u;' for r in CLOSURE),
        '@SELECT@':'\n'.join(f'case 0x{BASE+r:08X}u: startup_{r:06X}();break;' for r in CLOSURE),
        '@ADAPTERS@':'\n'.join(f'static void adapter_{r:06X}(uint32_t* s) {{select_body(0x{BASE+r:08X}u,s);}}' for r in CLOSURE),
        '@CALLBACKS@':'\n'.join(f'case 0x{BASE+r:08X}u:callback=adapter_{r:06X};break;' for r in CLOSURE),
        '@DIRECT_RETURNS@':'\n'.join(f'if(caller==0x{BASE+RVA:08X}u && target==0x{BASE+r:08X}u) return 0x{ret:08X}u;' for r,ret in direct.items()),
        '@INDIRECT_RETURNS@':'\n'.join(f'if(caller==0x{BASE+r:08X}u && target==0x{BASE+0xfcf0:08X}u) return 0x{ret:08X}u;' for r,ret in indirect.items()),
        '@BODY@':'\n'.join(bodies[r] for r in reversed(CLOSURE))}
    text=TEMPLATE.read_text()
    for key,value in replacements.items():
        require(text.count(key)==1)
        text=text.replace(key,value)
    return text


def run(output,caller_index):
    output=private_output(output)
    row=dict(schema='ts2-cache-caller-native/1',success=False,rva=hex(RVA),
        caller_closure=[hex(r) for r in CLOSURE],survey_expanded=False,
        invocation=[sys.executable,*sys.argv],harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE),bridge_sha256=digest(BRIDGE),image_sha256=IMAGE_SHA,
        pcrecomp_revision=REVISION,commands=[],functions={},runs={},
        range_corpus='whole-samples',arm64_executed=False,android_executed=False,
        compared=['eight GPRs','six entire 4096-byte pages including receiver/handle/stack and image tables'],
        limits=['synthetic owned range and receiver; service fields from verified producer writes, no behavior responses',
                'no flags/FP/native PC/transient-write comparison; unknown actual text writer/lifetime',
                'diagnostic-only real GuestMemory/GuestDispatch adapter; no Android binding or game execution'])
    def command(name,argv,data=None):
        rec=dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec)
        t=time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            p=subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=ROOT,timeout=180)
        rec.update(exit_code=p.returncode,seconds=time.monotonic()-t)
        require(p.returncode==0)
    stage='fresh-lift'
    try:
        image=ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image)==IMAGE_SHA)
        upstream=ROOT/'work/interop-legacy-002/pcrecomp'
        pristine=ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        lock=json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
        used=[n for n in lock['files'] if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        require(all(digest(upstream/n)==digest(pristine/n) for n in used))
        row['upstream_files']={n:digest(upstream/n) for n in used}
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve()==(upstream/'tools/lift/lift32.py').resolve())
        import pefile
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_CALL
        from capstone.x86 import X86_OP_IMM
        pe=pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase==BASE and pe.FILE_HEADER.Machine==0x14c)
        nodes,bodies,functions,direct,indirect={},{},{},{},{}
        targets=struct.unpack('<6I',pe.get_data(0x95c8,24))
        for r in CLOSURE:
            t=time.monotonic()
            if r==0x9550:
                f,ns,_=decode_switch(pe.get_data(r,0x78),BASE+r,BASE+0x95c8,targets,LinearInstruction)
            elif r==0xfcf0:
                raw=pe.get_data(r,32)
                span=sum(i.size for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(raw,BASE+r,count=2))
                f,ns=thunk_function(raw[:span],LinearInstruction)
            else:
                f,ns,_,flow=decode_flow(pe.get_data(r,128 if r==RVA else 64),BASE+r,LinearInstruction)
                if r==RVA:
                    row['caller_index']=crosscheck_index(json.loads(caller_index.read_text()),
                        dict(flow,instruction_rvas=[hex(a-BASE) for a in sorted(ns)]),r)
                    row['caller_index_sha256']=digest(caller_index)
                    for i in ns.values():
                        if i.group(CS_GRP_CALL):
                            require(i.operands[0].type==X86_OP_IMM)
                            target=(i.operands[0].imm&0xffffffff)-BASE
                            require(target in CLOSURE[1:6] and target not in direct)
                            direct[target]=i.address+i.size
                elif r in (0x1290,0x12d0):
                    calls=[i for i in ns.values() if i.group(CS_GRP_CALL)]
                    require(len(calls)==1)
                    indirect[r]=calls[0].address+calls[0].size
            require(not set(nodes)&set(ns))
            nodes.update(ns);functions[r]=f
            row['functions'][hex(r)]=dict(analysis_seconds=time.monotonic()-t,instructions=len(ns))
        for r,f in functions.items():
            t=time.monotonic()
            body=Lifter(precise_carry=True,lifted={BASE+r for r in CLOSURE}).lift_function(f)
            require(supported(body))
            path=output/f'lift-{r:x}.c';path.write_text(body);bodies[r]=body
            row['functions'][hex(r)].update(lifted=True,sha256=digest(path),translation_seconds=time.monotonic()-t,
                api='Lifter(precise_carry=True,lifted=authorized_closure_vas).lift_function(bounded_function)')
        require(set(direct)==set(CLOSURE[1:6]))
        stage='composed-reference'
        code_pages={p:pe.get_data(p-BASE,4096) for p in (BASE+0x1000,BASE+0xf000,BASE+0x9000,BASE+(RVA&~4095))}
        image_pages={p:pe.get_data(p-BASE,4096) for p in IMAGE_PAGES}
        rng=random.Random(118187+RVA)
        inputs,expected,visited=bytearray(),[],set()
        for n in range(64):
            row['current_reference_case']=n
            regs,pages=caller_state(n,rng,image_pages)
            state,seen=reference(nodes,code_pages,BASE+RVA,regs,pages)
            assert_poststate(regs,pages,state)
            visited.update(seen);expected.append(dict(case=n,**state))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in REGS)))
            inputs.extend(b''.join(bytes(pages[p]) for p in PAGES))
        row.pop('current_reference_case')
        require(all(BASE+r in visited for r in CLOSURE))
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        row['reference_sha256']=digest(output/'reference.json')
        row['independent_poststate_contract_cases']=64
        row['coverage']=dict(visited=len(visited),total=len(nodes),switch_arms=len(set(targets)&visited),
            uncovered_rvas=[hex(a-BASE) for a in sorted(set(nodes)-visited)])
        transport=output/'transport.cpp';transport.write_text(assemble(bodies,direct,indirect))
        row['transport_sha256']=digest(transport)
        row['verbatim_bodies_audited']=all(transport.read_text().count(body)==1 for body in bodies.values())
        require(row['verbatim_bodies_audited'])
        for isa in ('host','arm64'):
            stage=isa+'-compile';binary=output/isa
            command(stage,['zig-cxx',* ([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                '-I'+str(ROOT/'native/include'),transport,BRIDGE,ROOT/'native/src/guest_memory.cpp',
                ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
            h=binary.read_bytes()[:20]
            require(h[:6]==b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little')==(62 if isa=='host' else 183))
            stage=isa+'-execute'
            command(stage,[binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
            row['runs'][isa]=compare((output/(stage+'.stdout')).read_text(),expected)
            if isa=='arm64':row['arm64_executed']=True
        require(digest(image)==IMAGE_SHA)
        row['success']=True
    except Exception as exc:
        import traceback
        row.update(failed_stage=stage,error_type=type(exc).__name__,
            harness_failure_lines=[f.lineno for f in traceback.extract_tb(exc.__traceback__) if Path(f.filename).resolve()==Path(__file__).resolve()])
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--caller-index',type=Path,required=True)
    a=p.parse_args()
    try:run(a.output,a.caller_index)
    except Exception:p.exit(1,'Whole caller failed; inspect private outputs.\n')
    print('Whole caller GuestMemory: 64/64 host and AArch64; NOT Android/gameplay')


if __name__=='__main__':main()
