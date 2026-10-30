#!/usr/bin/env python3
"""Execute one unchanged whole module lift against the existing partial-state oracle."""
import argparse
import itertools
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_module_acquisition import ROOT, IMAGE_SHA, digest, require
from execute_storage_selector import strict_object
sys.path.insert(0, str(ROOT/'tools'))
import module_acquisition_probe as oracle

TEMPLATE = Path(__file__).with_name('module_transport.c.in')
COUNT = 1944


def assemble(body):
    require(type(body) is str and bool(body.strip()) and '@BODY@' not in body)
    source = TEMPLATE.read_text()
    require(source.count('\n@BODY@\n') == 1)
    source = source.replace('\n@BODY@\n', '\n'+body+'\n')
    require(source.count(body) == 1)
    return source


def reference(code=None):
    r = oracle.r
    scenarios = ((r.H1,0,0,0,0), (0,5,1,1,r.H2), (0,87,0,1,r.H2),
                 (0,87,1,0,r.H2), (0,87,1,1,0), (0,87,r.NEG,1,r.H2))
    data, expected = bytearray(), []
    for n, (modules, first, second, length, salt) in enumerate(itertools.product(
            itertools.product((0,r.NEG,r.H1),(0,r.NEG,r.H2)), scenarios,scenarios,range(3),(0,7))):
        responses = (first,second)
        wanted = oracle.oracle(modules,responses,length)
        if code is not None:
            r.verify(oracle.exercise(code,modules,responses,length,salt),wanted)
        regs = [(0x12345678+salt*0x1020304+k*0x112233)&r.NEG for k in range(8)]
        regs[7] = r.SP
        data.extend(struct.pack('<23I', *regs,*modules,*first,*second,length,r.TRAPS,0))
        expected.append(dict(case=n,eax=wanted['eax'],esp=wanted['esp'],modules=wanted['modules'],
                             events=[list(e[:1])+[e[1],e[2],e[3]] for e in wanted['events']]))
    require(len(expected) == COUNT)
    return bytes(data), expected


def compare(text, expected):
    rows = [json.loads(line,object_pairs_hook=strict_object) for line in text.splitlines()]
    require(len(rows) == len(expected) == COUNT)
    def word(v): return type(v) is int and 0 <= v <= 0xFFFFFFFF
    for n,(actual,wanted) in enumerate(zip(rows,expected)):
        require(type(actual) is dict and set(actual)=={'case','eax','esp','modules','events'})
        require(type(actual['case']) is int and actual['case']==n)
        require(word(actual['eax']) and word(actual['esp']))
        require(type(actual['modules']) is list and len(actual['modules'])==2 and all(map(word,actual['modules'])))
        require(type(actual['events']) is list and len(actual['events'])<=10)
        for e in actual['events']:
            require(type(e) is list and len(e)==4 and e[0] in ('load','error','compare') and
                    type(e[1]) is list and len(e[1])==(0 if e[0]=='error' else 3) and all(map(word,e[1]+e[2:])))
        require(actual==wanted)
    return dict(cases=COUNT,matched=COUNT)


def run(output,index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    row = dict(schema='ts2-module-acquisition-native/1',success=False,rva='0x847da1',size_bytes=203,
        lifted=False,compiled_for_aarch64=False,matched_x86_reference=False,executed_under_qemu=False,
        android_executed=False,commands=[],runs={},timings={},invocation=[sys.executable,*sys.argv],
        harness_sha256=digest(Path(__file__)),template_sha256=digest(TEMPLATE),
        compared=['EAX/ESP','ordered endpoint args/return RVA/SP','module words',
                  'checked nonvolatiles/module-page neighbors/immutable pages/stack outside36B scratch'],
        limits=['one whole unchanged pcrecomp body; endpoints authored NOT Windows/comparators',
                'no native PC/RET-target/volatile ECX/EDX/flags/scratch/transient writes/FP/SEH/race correctness or ownership',
                'race/unknown calls reject; no GuestMemory/image/runtime binding or Android/startup'])
    def command(name,argv,data=None,expected=0):
        record=dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(record)
        start=time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            p=subprocess.run(record['argv'],input=data,cwd=ROOT,stdout=out,stderr=err,timeout=180)
        record.update(exit_code=p.returncode,seconds=time.monotonic()-start)
        require(p.returncode==expected)
    stage='lift'
    try:
        command('lift',[sys.executable,ROOT/'scripts/recomp/measure_module_acquisition.py',
            '--index',index,'--output',output/'lift'],expected=2)
        lift=json.loads((output/'lift/metrics.jsonl').read_text());row['lift']=lift
        require(lift['lifted'] and lift['compiled_for_aarch64'])
        bodypath=output/'lift/lifted.c';require(digest(bodypath)==lift['lifted_sha256'])
        body=bodypath.read_text();row['lifted']=True
        (output/'transport.c').write_text(assemble(body))
        stage='reference';start=time.monotonic()
        image=ROOT/'work/interop-legacy-002/analysis-image.bin';require(digest(image)==IMAGE_SHA)
        pe=oracle.r.load_image()
        try:
            code=pe.get_data(oracle.RVA,oracle.SIZE);require(len(code)==oracle.SIZE)
            inputs,expected=reference(code)
        finally: pe.close()
        row['timings']['reference']=time.monotonic()-start
        (output/'input.bin').write_bytes(inputs);(output/'reference.json').write_text(json.dumps(expected))
        row['reference_sha256']=digest(output/'reference.json')
        upstream=ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32'
        # Mutate the first exercised load, preserving the rest of the stream.
        cold=next(i for i,e in enumerate(expected) if e['events'] and e['events'][0][0]=='load')
        for isa in ('host','arm64'):
            stage=isa+'-compile';binary=output/isa
            command(stage,['zig-cc',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream),output/'transport.c','-o',binary])
            h=binary.read_bytes()[:20]
            require(h[:6]==b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little')==(62 if isa=='host' else 183))
            if isa=='arm64':row['compiled_for_aarch64']=True
            row.setdefault('binary_sha256',{})[isa]=digest(binary)
            argv=[binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary]
            stage=isa+'-execute';command(stage,argv,inputs)
            if isa=='arm64':row['executed_under_qemu']=True
            stage=isa+'-compare';row['runs'][isa]=compare((output/(isa+'-execute.stdout')).read_text(),expected)
            row['runs'][isa]['rejection_controls']=0
            for label,word,value in (('stack',7,oracle.r.SP-1),('length',20,3),
                                      ('target',21,oracle.r.TRAPS+4),('race',22,1)):
                bad=bytearray(inputs);struct.pack_into('<I',bad,cold*92+word*4,value)
                stage=isa+'-reject-'+label;command(stage,argv,bytes(bad))
                lines=(output/(stage+'.stdout')).read_text().splitlines()
                require(len(lines)==COUNT and json.loads(lines[cold])==dict(case=cold,rejected=True))
                lines[cold]=json.dumps(expected[cold]);compare('\n'.join(lines),expected)
                row['runs'][isa]['rejection_controls']+=1
        stage='audit'
        require((output/'host-execute.stdout').read_bytes()==(output/'arm64-execute.stdout').read_bytes())
        audit=dict(image_unchanged=digest(image)==IMAGE_SHA,body_unchanged=bodypath.read_text()==body,
                   inserted_once=(output/'transport.c').read_text().count(body)==1,
                   source_exact=(output/'transport.c').read_text()==assemble(body),
                   template_unchanged=digest(TEMPLATE)==row['template_sha256'])
        (output/'source-audit.json').write_text(json.dumps(audit));require(all(audit.values()))
        row.update(success=True,matched_x86_reference=True)
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__);raise
    finally:(output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    try:run(args.output,args.index)
    except Exception:
        print('Module comparison failed; inspect private metrics',file=sys.stderr);return 1
    print('Whole module lift matched partial oracle on host/Linux AArch64 QEMU; NOT Windows/Android/startup')
    return 0


if __name__=='__main__':raise SystemExit(main())
