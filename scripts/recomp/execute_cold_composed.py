#!/usr/bin/env python3
"""Execute two whole cold lifts; export/encoder remain authored, development only."""
import argparse
import itertools
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from measure_module_acquisition import ROOT, IMAGE_SHA, digest, require
from execute_storage_selector import strict_object
sys.path.insert(0,str(ROOT/'tools'))
import encoded_resolver_composed_probe as oracle

TEMPLATE=Path(__file__).with_name('cold_composed_transport.c.in')
COUNT=1336
RECORD=108+4096


def assemble(module,resolver):
    source=TEMPLATE.read_text()
    for marker,body in (('@MODULE@',module),('@RESOLVER@',resolver)):
        require(type(body) is str and bool(body.strip()) and marker not in body)
        require(source.count('\n'+marker+'\n')==1)
        source=source.replace('\n'+marker+'\n','\n'+body+'\n')
    require(source.count(module)==source.count(resolver)==1)
    return source


def cases():
    r=oracle.r
    scenarios=((r.H1,0,0,0,0),(0,5,1,1,r.H2),(0,87,0,1,r.H2),
               (0,87,1,0,r.H2),(0,87,1,1,r.H2),(0,87,1,1,0))
    for modules,a,b,export,length in itertools.product(
            ((0,0),(r.NEG,0),(r.H1,0),(0,r.H2),(r.NEG,r.NEG)),
            scenarios,scenarios,(0,0x80000000),range(3)):
        yield 0x12345678,modules,(a,b),export,length,33,0
    for count,index,salt,export in itertools.product(range(32),(0,63),(0,7),(0,0x80000001)):
        yield 0x12345660|count,(0,0),((0,87,1,1,r.H1),(r.H2,0,0,0,0)),export,2,index,salt


def reference(codes=None):
    data,expected=bytearray(),[]
    r=oracle.r
    for n,(cookie,modules,responses,export,length,index,salt) in enumerate(cases()):
        wanted=oracle.oracle(cookie,modules,responses,export,length)
        if codes is not None:
            r.verify(oracle.exercise(*codes,cookie,modules,responses,export,length,index,salt),wanted)
        regs,stack=oracle.c.inputs(index,salt)
        struct.pack_into('<I',stack,r.SP-r.STACK+16,r.ARRAY+4*length)
        data.extend(struct.pack('<27I',*regs,*modules,*responses[0],*responses[1],length,
                                r.TRAPS,cookie,export,index,r.TRAPS+32,0))
        data.extend(stack)
        hot=oracle.c.oracle(wanted['eax'] or r.NEG,cookie,index,salt)
        hot_stack=bytearray(hot['stack'])
        struct.pack_into('<I',hot_stack,r.SP-r.STACK+16,r.ARRAY+4*length)
        expected.append(dict(case=n,eax=wanted['eax'],esp=wanted['esp'],modules=wanted['modules'],
                             cache=wanted['cache'],events=[list(e) for e in wanted['events']],
                             hot=dict(registers=hot['registers'],stack=hot_stack.hex())))
    require(len(expected)==COUNT)
    return bytes(data),expected


def compare(text,expected):
    rows=[json.loads(line,object_pairs_hook=strict_object) for line in text.splitlines()]
    require(len(rows)==len(expected)==COUNT)
    def word(v):return type(v) is int and 0<=v<=0xFFFFFFFF
    for n,(actual,wanted) in enumerate(zip(rows,expected)):
        require(type(actual) is dict and set(actual)=={'case','eax','esp','modules','cache','events','hot'})
        require(type(actual['case']) is int and actual['case']==n)
        require(all(word(actual[k]) for k in ('eax','esp','cache')))
        require(type(actual['modules']) is list and len(actual['modules'])==2 and all(map(word,actual['modules'])))
        require(type(actual['events']) is list and len(actual['events'])<=11)
        for e in actual['events']:
            require(type(e) is list and len(e)==4 and e[0] in ('load','error','compare','export') and
                    type(e[1]) is list and len(e[1])==dict(load=3,error=0,compare=3,export=2)[e[0]] and all(map(word,e[1]+e[2:])))
        hot=actual['hot']
        require(type(hot) is dict and set(hot)=={'registers','stack'})
        require(type(hot['registers']) is list and len(hot['registers'])==8 and all(map(word,hot['registers'])))
        require(type(hot['stack']) is str and len(hot['stack'])==8192 and
                all(c in '0123456789abcdef' for c in hot['stack']))
        require(actual==wanted)
    return dict(cases=COUNT,matched=COUNT,same_memory_hot_matches=COUNT)


def run(output,module_index,resolver_index):
    output=output.resolve();require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    row=dict(schema='ts2-cold-composed-native/2',success=False,rvas=['0x847da1','0x847e6c'],
        original_bodies=2,lifted=False,compiled_for_aarch64=False,matched_x86_reference=False,
        executed_under_qemu=False,android_executed=False,commands=[],runs={},timings={},lifts={},
        invocation=[sys.executable,*sys.argv],harness_sha256=digest(Path(__file__)),template_sha256=digest(TEMPLATE),
        compared=['EAX/ESP/nonvolatiles','ordered endpoint args/return RVA/SP','module/cache page',
                  'immutable pages/stack outside64B scratch',
                  'same-memory hot reentry: all eight GPRs/full4096 stack/unchanged pages; cold data/endpoints disabled'],
        limits=['two unchanged whole lifts; export/encoder/load/error/comparison endpoints authored NOT Windows',
                'encoder original executed ONLY in existing x86 reference, NOT lifted/native translated',
                'no cold volatile registers/flags/scratch/transient writes/native PC/RET target/FP/SEH/race/ownership',
                'no native hot flags/transient writes/GuestMemory/image/runtime binding/Android/startup'])
    def command(name,argv,data=None,expected=0):
        rec=dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec);start=time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            p=subprocess.run(rec['argv'],input=data,cwd=ROOT,stdout=out,stderr=err,timeout=180)
        rec.update(exit_code=p.returncode,seconds=time.monotonic()-start);require(p.returncode==expected)
    stage='lift'
    try:
        bodies={}
        for name,script,index in (('module','measure_module_acquisition.py',module_index),('resolver','measure_encoded_resolver.py',resolver_index)):
            command(name+'-lift',[sys.executable,ROOT/'scripts/recomp'/script,'--index',index,'--output',output/name],expected=2)
            lift=json.loads((output/name/'metrics.jsonl').read_text());row['lifts'][name]=lift
            require(lift['lifted'] and lift['compiled_for_aarch64'])
            body=output/name/'lifted.c';require(digest(body)==lift['lifted_sha256']);bodies[name]=body.read_text()
        row['lifted']=True;(output/'transport.c').write_text(assemble(bodies['module'],bodies['resolver']))
        stage='reference';start=time.monotonic();image=ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image)==IMAGE_SHA);pe=oracle.r.load_image()
        try:
            codes=(pe.get_data(oracle.c.RVA,oracle.c.SIZE),pe.get_data(oracle.m.RVA,oracle.m.SIZE),pe.get_data(oracle.ENCODER-oracle.r.BASE,oracle.ENCODER_SIZE))
            require(tuple(map(len,codes))==(oracle.c.SIZE,oracle.m.SIZE,oracle.ENCODER_SIZE))
            inputs,expected=reference(codes)
        finally:pe.close()
        row['timings']['reference']=time.monotonic()-start
        (output/'input.bin').write_bytes(inputs);(output/'reference.json').write_text(json.dumps(expected));row['reference_sha256']=digest(output/'reference.json')
        upstream=ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'
        cold=next(n for n,e in enumerate(expected) if any(ev[0]=='load' for ev in e['events']))
        exported=next(n for n,e in enumerate(expected) if any(ev[0]=='export' for ev in e['events']))
        for isa in ('host','arm64'):
            stage=isa+'-compile';binary=output/isa
            command(stage,['zig-cc',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration','-I'+str(upstream),output/'transport.c','-o',binary])
            h=binary.read_bytes()[:20];require(h[:6]==b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little')==(62 if isa=='host' else 183))
            if isa=='arm64':row['compiled_for_aarch64']=True
            row.setdefault('binary_sha256',{})[isa]=digest(binary)
            argv=[binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary]
            stage=isa+'-execute';command(stage,argv,inputs)
            if isa=='arm64':row['executed_under_qemu']=True
            stage=isa+'-compare';row['runs'][isa]=compare((output/(isa+'-execute.stdout')).read_text(),expected)
            row['runs'][isa]['rejection_controls']=0
            for label,case,word,value in (('stack',0,7,oracle.r.SP-1),('range',0,20,3),('load',cold,21,oracle.r.TRAPS+4),
                    ('export',exported,25,oracle.r.TRAPS+36),('reserved',0,23,oracle.r.NEG),('index',0,24,64),('unpublished-hot',0,26,1)):
                bad=bytearray(inputs);struct.pack_into('<I',bad,case*RECORD+word*4,value)
                stage=isa+'-reject-'+label;command(stage,argv,bytes(bad))
                lines=(output/(stage+'.stdout')).read_text().splitlines();require(len(lines)==COUNT and json.loads(lines[case])==dict(case=case,rejected=True))
                lines[case]=json.dumps(expected[case]);compare('\n'.join(lines),expected);row['runs'][isa]['rejection_controls']+=1
        stage='audit';require((output/'host-execute.stdout').read_bytes()==(output/'arm64-execute.stdout').read_bytes())
        audit=dict(image_unchanged=digest(image)==IMAGE_SHA,source_exact=(output/'transport.c').read_text()==assemble(bodies['module'],bodies['resolver']),template_unchanged=digest(TEMPLATE)==row['template_sha256'])
        for name,body in bodies.items():
            audit[name+'_unchanged']=(output/name/'lifted.c').read_text()==body
            audit[name+'_inserted_once']=(output/'transport.c').read_text().count(body)==1
        (output/'source-audit.json').write_text(json.dumps(audit));require(all(audit.values()))
        row.update(success=True,matched_x86_reference=True)
    except Exception as exc:row.update(failed_stage=stage,error_type=type(exc).__name__);raise
    finally:(output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--module-index',type=Path,required=True);ap.add_argument('--resolver-index',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    try:run(args.output,args.module_index,args.resolver_index)
    except Exception:
        print('Cold composed comparison failed; inspect private metrics',file=sys.stderr);return 1
    print('Two cold whole lifts and same-memory hot GPR/stack reentry matched on host/Linux AArch64 QEMU; NOT Windows/Android/startup');return 0


if __name__=='__main__':raise SystemExit(main())
