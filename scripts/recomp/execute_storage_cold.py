#!/usr/bin/env python3
"""Compare three whole lifts in a cold selector frame; private development only."""
import argparse
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
import storage_cold_composed_probe as oracle
import storage_hot_composed_probe as hot

TEMPLATE=Path(__file__).with_name('storage_cold_transport.c.in')
COUNT=2528
RECORD=112+4096


def cases():
    """Retain the cold scenario matrix, then cross hot storage ABI edges."""
    for case in oracle.cases():
        yield case,False
    for count in range(32):
        for export in (0,oracle.query.FLS):
            for result in (0,1,0x80000000,oracle.r.NEG):
                for index in (0,oracle.r.NEG):
                    for clobber in (False,True):
                        yield (0x12345660|count,(0,0),
                            ((0,87,1,1,oracle.r.H1),(oracle.r.H2,0,0,0,0)),
                            export,result,index,7),clobber


def assemble(module,resolver,selector):
    source=TEMPLATE.read_text()
    bodies=(module,resolver,selector)
    for marker,body in zip(('@MODULE@','@RESOLVER@','@SELECTOR@'),bodies):
        require(type(body) is str and bool(body.strip()) and not any(m in body for m in ('@MODULE@','@RESOLVER@','@SELECTOR@')))
        require(source.count('\n'+marker+'\n')==1)
        source=source.replace('\n'+marker+'\n','\n'+body+'\n')
    require(all(source.count(body)==1 for body in bodies))
    return source


def reference(codes=None):
    data,expected=bytearray(),[]
    for n,(case,clobber) in enumerate(cases()):
        cookie,modules,responses,export,result,index,salt=case
        wanted=oracle.oracle(cookie,modules,responses,export,result,index)
        if codes is not None:
            oracle.r.verify(oracle.exercise(codes,cookie,modules,responses,export,result,index,salt),wanted)
        regs,stack=oracle.query.free.inputs(index,salt)
        data.extend(struct.pack('<28I',*regs,*modules,*responses[0],*responses[1],result,
                                oracle.LOAD,cookie,export,0,oracle.EXPORT,4,int(clobber)))
        data.extend(stack)
        # Independent full hot oracle, not a snapshot stitched from cold results.
        value=hot.hot.rotate(wanted['cache']^cookie,cookie&31)
        warmed=hot.oracle(value,cookie,result,index,salt,clobber=clobber)
        if codes is not None:
            oracle.r.verify(hot.exercise({p.ENTRY:codes[p.ENTRY] for p in hot.BODIES},
                            cookie,wanted['cache'],result,index,salt,clobber=clobber),warmed)
        expected.append(dict(case=n,**{k:([list(e) for e in v] if k=='events' else v) for k,v in wanted.items()},
            hot=dict(registers=warmed['registers'],stack=warmed['stack'].hex(),
                     events=[{k:v for k,v in e.items() if k!='flags'} for e in warmed['events']])))
    require(len(expected)==COUNT)
    return bytes(data),expected


def compare(text,expected):
    rows=[json.loads(line,object_pairs_hook=strict_object) for line in text.splitlines()]
    require(len(rows)==len(expected)==COUNT)
    def word(v):return type(v) is int and 0<=v<=0xFFFFFFFF
    counts=dict(resolve=4,load=3,error=0,compare=3,export=2,guard=0,fls=1,tls=1)
    for n,(actual,wanted) in enumerate(zip(rows,expected)):
        require(type(actual) is dict and set(actual)=={'case','eax','esp','modules','cache','events','hot'})
        require(type(actual['case']) is int and actual['case']==n)
        require(all(word(actual[k]) for k in ('eax','esp','cache')))
        require(type(actual['modules']) is list and len(actual['modules'])==2 and all(map(word,actual['modules'])))
        require(type(actual['events']) is list and 2<=len(actual['events'])<=15)
        for e in actual['events']:
            require(type(e) is list and len(e)==4 and type(e[0]) is str and e[0] in counts and
                    type(e[1]) is list and len(e[1])==counts[e[0]] and all(map(word,e[1]+e[2:])))
        warmed=actual['hot']
        require(type(warmed) is dict and set(warmed)=={'registers','stack','events'})
        require(type(warmed['registers']) is list and len(warmed['registers'])==8 and all(map(word,warmed['registers'])))
        require(type(warmed['stack']) is str and len(warmed['stack'])==8192 and all(c in '0123456789abcdef' for c in warmed['stack']))
        require(type(warmed['events']) is list and 2<=len(warmed['events'])<=3)
        for e in warmed['events']:
            require(type(e) is dict and set(e)=={'kind','args','returnRva','registers'})
            require(type(e['kind']) is str and e['kind'] in ('resolve','guard','fls','tls'))
            require(type(e['args']) is list and len(e['args'])==counts[e['kind']] and all(map(word,e['args'])))
            require(word(e['returnRva']) and type(e['registers']) is list and len(e['registers'])==8 and all(map(word,e['registers'])))
        require(actual==wanted)
    return dict(cases=COUNT,matched=COUNT,same_memory_hot_matches=COUNT)


def run(output,module_index,resolver_index,selector_index):
    output=output.resolve();require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    row=dict(schema='ts2-storage-cold-native/3',success=False,rvas=['0x847da1','0x847e6c','0x8480bf'],
        original_bodies=3,lifted=False,compiled_for_aarch64=False,matched_x86_reference=False,
        executed_under_qemu=False,android_executed=False,commands=[],runs={},timings={},lifts={},
        invocation=[sys.executable,*sys.argv],harness_sha256=digest(Path(__file__)),template_sha256=digest(TEMPLATE),
        compared=['EAX/ESP/nonvolatiles','ordered endpoint args/return RVA/SP','module/cache page',
                  'immutable pages/stack outside92B scratch','guard/FLS target ECX checked',
                  'same-memory hot: all caller GPRs/full4096 stack/all endpoint GPRs and frames/unchanged pages; cold dependencies disabled',
                  'both storage branches/all32 cookie counts/four results/two indices/hot ECX EDX preserve or clobber'],
        limits=['three unchanged whole lifts; encoder/API/guard/storage endpoints authored NOT Windows',
                'encoder original reference-only where called, NOT lifted/native translated',
                'no cold volatile/flags/scratch/transient writes/native PC/RET/FP/SEH/race/ownership',
                'no native hot flags/transient writes/GuestMemory/image/runtime binding/Android/startup',
                'fresh x86 cold and hot checked separately; native alone tests same-memory selector sequence'])
    def command(name,argv,data=None,expected=0):
        rec=dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec);start=time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            p=subprocess.run(rec['argv'],input=data,cwd=ROOT,stdout=out,stderr=err,timeout=180)
        rec.update(exit_code=p.returncode,seconds=time.monotonic()-start);require(p.returncode==expected)
    stage='lift'
    try:
        bodies={}
        for name,script,index in (('module','measure_module_acquisition.py',module_index),('resolver','measure_encoded_resolver.py',resolver_index),('selector','measure_storage_selector.py',selector_index)):
            # Validate and reuse the persistent read-only index, never re-import.
            oracle.load_index(index)
            command(name+'-lift',[sys.executable,ROOT/'scripts/recomp'/script,'--index',index,'--output',output/name],expected=2)
            lift=json.loads((output/name/'metrics.jsonl').read_text());row['lifts'][name]=lift
            require(lift['lifted'] and lift['compiled_for_aarch64'])
            body=output/name/'lifted.c';require(digest(body)==lift['lifted_sha256']);bodies[name]=body.read_text()
        row['lifted']=True;(output/'transport.c').write_text(assemble(**bodies))
        stage='reference';start=time.monotonic();image=ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image)==IMAGE_SHA);pe=oracle.r.load_image()
        try:
            codes={a:pe.get_data(a-oracle.r.BASE,size) for a,size in oracle.BODIES}
            require(all(len(codes[a])==size for a,size in oracle.BODIES))
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
            for label,case,word,value in (('stack',0,7,oracle.r.SP-1),('load',cold,21,oracle.LOAD+4),
                    ('export',exported,25,oracle.EXPORT+4),('target',0,23,oracle.query.FLS+4),
                    ('cleanup',0,26,0),('unpublished-hot',0,24,1),('clobber-mode',0,27,2)):
                bad=bytearray(inputs);struct.pack_into('<I',bad,case*RECORD+word*4,value)
                stage=isa+'-reject-'+label;command(stage,argv,bytes(bad))
                lines=(output/(stage+'.stdout')).read_text().splitlines();require(len(lines)==COUNT and json.loads(lines[case])==dict(case=case,rejected=True))
                lines[case]=json.dumps(expected[case]);compare('\n'.join(lines),expected);row['runs'][isa]['rejection_controls']+=1
        stage='audit';require((output/'host-execute.stdout').read_bytes()==(output/'arm64-execute.stdout').read_bytes())
        audit=dict(image_unchanged=digest(image)==IMAGE_SHA,source_exact=(output/'transport.c').read_text()==assemble(**bodies),template_unchanged=digest(TEMPLATE)==row['template_sha256'])
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
    for name in ('module','resolver','selector'):ap.add_argument('--'+name+'-index',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    try:run(args.output,args.module_index,args.resolver_index,args.selector_index)
    except Exception:
        print('Cold selector comparison failed; inspect private metrics',file=sys.stderr);return 1
    print('Three whole lifts matched partial cold state and same-memory hot GPR/stack/endpoint reentry on host/Linux AArch64 QEMU; NOT Windows/Android/startup');return 0


if __name__=='__main__':raise SystemExit(main())
