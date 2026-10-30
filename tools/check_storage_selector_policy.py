#!/usr/bin/env python3
"""Value/request comparison for native encoded resolution + storage selection.

Optional private reference executes resolver composition and selector SEPARATELY;
not one composed x86 frame, CPU-ABI translation, Windows storage or startup.
"""
import argparse
import itertools
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import encoded_resolver_composed_probe as x
import ptd_query_probe as q
r = x.r


def cases():
    for case in itertools.product((0,1,31,0x12345678,r.NEG),range(3),
            (0,r.NEG,r.H1),(0,r.H2),(0,q.FLS),
            (0,1,0x80000000,r.NEG),(0,1,0x80000000,r.NEG)):
        if case[1] != 1 or case[4]: yield case
    for rotation in range(32):
        for target in (0,q.FLS):
            yield (0x12345660|rotation,0,0,r.H1,target,r.NEG,0)


def expected(case, bodies=None):
    cookie,state,module,loaded,target,index,result = case
    events=[]
    if state==0:
        responses=((loaded,5,0,0,0),(0,5,0,0,0))
        model=x.oracle(cookie,(module,0),responses,target,1)
        if bodies is not None:
            observed=x.exercise(*bodies[:3],cookie,(module,0),responses,target,1)
            r.verify(observed,model)
            model=observed
        target,cache,module=model['eax'],model['cache'],model['modules'][0]
        for kind,args,_,_ in model['events']:
            events.extend([{'load':1,'error':2,'export':3}[kind],*(args+[0]*(3-len(args)))])
    else:
        target=target if state==1 else 0
        cache=x.c.encode(target or r.NEG,cookie)
    for _ in range(2):
        selector=q.oracle(target,result,index)
        if bodies is not None:
            r.verify(q.exercise(bodies[3],target,result,index),selector)
        # Selector oracle supplies endpoint order/index, not resolver request values.
        for kind,args,_,_,_ in selector['events'][1:]:
            events.extend({'guard':[5,target,0,0],
                           'fls':[6,target,index,0], 'tls':[7,index,0,0]}[kind])
            r.require(args==([] if kind=='guard' else [index]))
    return [result,result,cache,module,len(events)//4,*events]


def parse(text,count):
    lines=text.splitlines(); r.require(len(lines)==count)
    rows=[]
    for line in lines:
        words=line.split(); r.require(all(w.isascii() and w.isdecimal() for w in words))
        row=list(map(int,words))
        r.require(len(row)>=5 and all(0<=v<=r.NEG for v in row))
        r.require(row[4]<=7 and len(row)==5+4*row[4]); rows.append(row)
    return rows


def compare(observed,wanted): r.require(observed==wanted)


def check(command,inputs,bodies=None):
    data='\n'.join(' '.join(map(str,case)) for case in inputs)+'\n'
    run=subprocess.run(command,input=data,text=True,capture_output=True,timeout=120)
    r.require(run.returncode==0 and not run.stderr)
    rows=parse(run.stdout,len(inputs))
    for row,case in zip(rows,inputs): compare(row,expected(case,bodies))
    return len(inputs)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,default=Path(os.environ.get(
        'TS2_GUEST_STORAGE_SELECTOR_PROBE','build/host/ts2_guest_storage_selector_probe')))
    parser.add_argument('--runner',default=os.environ.get('TS2_GUEST_STORAGE_SELECTOR_RUNNER',''))
    parser.add_argument('--private-x86',action='store_true')
    args=parser.parse_args(argv); pe=None
    try:
        bodies=None
        if args.private_x86:
            pe=r.load_image()
            spans=((x.c.RVA,x.c.SIZE),(x.m.RVA,x.m.SIZE),
                   (x.ENCODER-r.BASE,x.ENCODER_SIZE),(q.RVA,q.SIZE))
            bodies=tuple(pe.get_data(a,n) for a,n in spans)
            r.require(all(len(body)==span[1] for body,span in zip(bodies,spans)))
        count=check([*shlex.split(args.runner),str(args.native.resolve())],list(cases()),bodies)
        print(json.dumps(dict(cases=count,privateSeparateX86References=bodies is not None,
            composedX86Frame=False,cpuAbiCompared=False,windowsStorageExecuted=False,
            startupExecuted=False),sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,x.struct.error,
            x.UcError,x.pefile.PEFormatError,subprocess.SubprocessError):
        print('Storage selector comparison failed; private details suppressed.',file=sys.stderr); return 2
    finally:
        if pe is not None: pe.close()


if __name__=='__main__': raise SystemExit(main())
