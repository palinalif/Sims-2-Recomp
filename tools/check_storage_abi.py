#!/usr/bin/env python3
"""Bounded native selector ABI vs independent oracle, optionally pinned x86.

No original bytes/states emitted. Resolver/guard/storage remain authored APIs.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import ptd_query_probe as q
r=q.r


def cases():
    return [(target,result,index,salt,clobber)
            for target in (0,q.FLS) for result in (0,1,0x80000000,r.NEG)
            for index in (0,1,0x80000000,r.NEG) for salt in range(4)
            for clobber in (False,True)]


def request(case, wrong=0, sp=None):
    target,result,index,salt,clobber=case
    regs,stack=q.free.inputs(index,salt)
    if sp is not None: regs[7]=sp
    return ' '.join(map(str,[target,result,int(clobber),wrong,*regs,0xCD7,
                            *struct.unpack('<1024I',stack)]))+'\n'


def parse(text,count):
    lines=text.splitlines()
    r.require(len(lines)==count)
    states=[]
    for line in lines:
        tokens=line.split()
        r.require(all(t.isascii() and t.isdecimal() and len(t)<=10 for t in tokens))
        v=list(map(int,tokens)); r.require(all(n<=r.NEG for n in v))
        r.require(len(v)>=1035 and v[0] in (0,1))
        registers=v[1:9]; flags=v[9]&0xCC5
        stack=struct.pack('<1024I',*v[10:1034])
        n=v[1034]; r.require(n<=3); pos=1035; events=[]
        for _ in range(n):
            r.require(pos<len(v)); size=v[pos]; pos+=1
            r.require(size in (4,5,8) and pos+size<=len(v))
            kind,ret,sp,ecx,*args=v[pos:pos+size]; pos+=size
            r.require(kind in (1,2,3,4) and size=={1:8,2:4,3:5,4:5}[kind])
            events.append(({1:'resolve',2:'guard',3:'fls',4:'tls'}[kind],args,ret,sp,ecx))
        r.require(pos==len(v))
        states.append((v[0],dict(registers=registers,flags=flags,stack=stack,events=events)))
    return states


def run(cases_,native,runner=None,wrong=0,sp=None):
    command=([str(runner)] if runner else [])+[str(Path(native).resolve())]
    done=subprocess.run(command,input=''.join(request(c,wrong,sp) for c in cases_),
                        capture_output=True,text=True,timeout=60)
    r.require(done.returncode==0 and not done.stderr and len(done.stdout)<=32*1024*1024)
    return parse(done.stdout,len(cases_))


def verify(state,case):
    failure,actual=state; r.require(failure==0)
    target,result,index,salt,clobber=case
    r.verify(actual,q.oracle(target,result,index,salt,clobber=clobber))


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native',default=os.environ.get('TS2_GUEST_STORAGE_ABI_PROBE','build/host/ts2_guest_storage_abi_probe'))
    p.add_argument('--runner',default=os.environ.get('TS2_GUEST_STORAGE_ABI_RUNNER'))
    p.add_argument('--private-x86',action='store_true'); a=p.parse_args(argv)
    pe=None
    try:
        sweep=cases(); states=run(sweep,a.native,a.runner)
        if a.private_x86: pe=r.load_image()
        for case,state in zip(sweep,states):
            verify(state,case)
            if pe is not None:
                target,result,index,salt,clobber=case
                r.verify(q.exercise(pe.get_data(q.RVA,q.SIZE),target,result,index,salt,
                                    clobber=clobber),state[1])
        print(json.dumps(dict(cases=len(sweep),privateX86Compared=pe is not None,
            originalBodyLifted=False,iatBound=False,windowsStorageExecuted=False,
            startupExecuted=False),sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,subprocess.SubprocessError,q.UcError,q.pefile.PEFormatError):
        print('Storage ABI comparison failed; private details suppressed.',file=sys.stderr); return 2
    finally:
        if pe is not None: pe.close()

if __name__=='__main__':
    raise SystemExit(main())
