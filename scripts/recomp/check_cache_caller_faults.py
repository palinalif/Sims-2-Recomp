#!/usr/bin/env python3
"""Execute existing unchanged private lifts with two faulty diagnostic bridges.

Not new translations or matches: sensitivity evidence for the live-state oracle.
No proprietary bodies/states in this source; all outputs stay under ignored work/.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import execute_cache_caller as caller
from execute_cache_skip import private_output, require
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest

REFERENCE_SHA='75f7b957c04e05da42134fde2c39164c5e9eab58021d58b1d12b4e9d969bda95'
INPUT_SHA='b3634070384f67f28a40211bfa1e98f86e6ec4a47f6e9f561885c1d0993ea4d7'
MODES=('valid','slot-order','cleanup')


def bridge_source(text,mode):
    require(mode in MODES)
    if mode=='valid':return text
    if mode=='slot-order':
        old='    check(a,size,true);'
        # Swap stores only, not reads: faulty guest address marshalling.
        new=old+'\n    if (size==4 && (a==0xA10DF100u || a==0xA10DF104u)) a^=4;'
    else:
        old='    current(s.data());'
        # Corrupt only the root return frame, after the unchanged caller ran.
        # Models a runtime boundary consuming four too few caller-owned bytes;
        # NOT a mutation of the original caller ADD instruction.
        new=old+'\n    if (depth==1) s[7]-=4;'
    require(text.count(old)==1)
    return text.replace(old,new)


def assess(text,expected,inputs,mode):
    require(mode in MODES)
    # Validate transport independently first: a rejected frame is not a kill.
    rows=[json.loads(line) for line in text.splitlines()]
    caller.compare(text,rows)
    # Exact comparator remains authoritative, including strict row parsing.
    try:
        caller.compare(text,expected)
        matched=True
    except ValueError:
        matched=False
    if mode=='valid':require(matched)
    else:require(not matched)
    require(len(rows)==len(expected)==64)
    stride=32+len(caller.PAGES)*4096
    require(len(inputs)==64*stride)
    differences=contracts=0
    for n,(row,wanted) in enumerate(zip(rows,expected)):
        # A crash, rejected dispatch or malformed stream is NOT a killed mutant.
        require(set(row)=={'case','regs','pages'} and row['case']==n)
        differences+=row!=wanted
        raw=inputs[n*stride:(n+1)*stride]
        regs=dict(zip(caller.REGS,struct.unpack('<8I',raw[:32])))
        pages={p:raw[32+i*4096:32+(i+1)*4096] for i,p in enumerate(caller.PAGES)}
        try:caller.assert_poststate(regs,pages,row)
        except ValueError:contracts+=1
    if mode=='valid':require(differences==contracts==0)
    else:require(differences>0 and contracts>0)
    return dict(executed_cases=64,differing_cases=differences,poststate_rejections=contracts,
                strict_reference_match=matched,negative_control=mode!='valid')


def run(source,output):
    output=private_output(output)
    row=dict(schema='ts2-cache-caller-faults/1',success=False,arm64_executed=False,android_executed=False,
             new_translations=0,newly_executable_behaviors=0,commands=[],runs={},
             harness_sha256=digest(Path(__file__)),reference_sha256=REFERENCE_SHA,input_sha256=INPUT_SHA,
             limits=['saved bounded x86 reference; not a fresh original execution',
                     'unchanged original lifts; faults in authored bridge only',
                     'cleanup fault is root SP boundary corruption, not caller instruction mutation',
                     'not production binding, Android, ownership or arbitrary-range validation'])
    try:
        require(source.resolve().is_relative_to((ROOT/'work/recomp-bench').resolve()))
        receipt=json.loads((source/'result.json').read_text())
        require(receipt['success'] and receipt['arm64_executed'] and not receipt['android_executed'])
        require(receipt['image_sha256']==IMAGE_SHA and receipt['pcrecomp_revision']==REVISION)
        require(receipt['caller_closure']==[hex(r) for r in caller.CLOSURE])
        require(digest(source/'reference.json')==REFERENCE_SHA and digest(source/'input.bin')==INPUT_SHA)
        require(digest(caller.BRIDGE)==receipt['bridge_sha256'])
        require(digest(caller.TEMPLATE)==receipt['template_sha256'])
        require(digest(source/'transport.cpp')==receipt['transport_sha256'])
        upstream=ROOT/'work/interop-legacy-002/pcrecomp'
        require(all(digest(upstream/n)==sha for n,sha in receipt['upstream_files'].items()))
        require(digest(ROOT/'work/interop-legacy-002/analysis-image.bin')==IMAGE_SHA)
        transport=(source/'transport.cpp').read_text()
        for r in caller.CLOSURE:
            body=source/f'lift-{r:x}.c'
            require(digest(body)==receipt['functions'][hex(r)]['sha256'])
            require(transport.count(body.read_text())==1)
        row['source_receipt_sha256']=digest(source/'result.json')
        row['transport_sha256']=digest(source/'transport.cpp')
        row['verbatim_bodies_audited']=True
        expected=json.loads((source/'reference.json').read_text());inputs=(source/'input.bin').read_bytes()
        def command(name,argv,data=None):
            rec=dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec)
            t=time.monotonic()
            with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
                p=subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=ROOT,timeout=180)
            rec.update(exit_code=p.returncode,seconds=time.monotonic()-t)
            require(p.returncode==0)
        for mode in MODES:
            bridge=output/(mode+'.cpp');bridge.write_text(bridge_source(caller.BRIDGE.read_text(),mode))
            for isa in ('host','arm64'):
                name=mode+'-'+isa;binary=output/name
                command(name+'-compile',['zig-cxx',* ([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(ROOT/'native/include'),source/'transport.cpp',bridge,
                    ROOT/'native/src/guest_memory.cpp',ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
                h=binary.read_bytes()[:20]
                require(h[:6]==b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little')==(62 if isa=='host' else 183))
                command(name+'-execute',[binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary],inputs)
                row['runs'][name]=assess((output/(name+'-execute.stdout')).read_text(),expected,inputs,mode)
                if isa=='arm64':row['arm64_executed']=True
        row['success']=True
    except Exception as exc:
        row['error_type']=type(exc).__name__
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:run(a.source,a.output)
    except Exception:p.exit(1,'Fault experiment failed; inspect private outputs.\n')
    print('Unchanged lifts: valid baseline matched; both bridge faults rejected on both ISAs. NOT Android.')


if __name__=='__main__':main()
