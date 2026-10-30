#!/usr/bin/env python3
"""Native hot ABI vs existing independent oracle and optional pinned x86 body.

Development-only. No original code/states emitted; cold resolution unsupported.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import encoded_cache_probe as p
r=p.r


def cases():
    return [(cookie,value,index,salt) for cookie in (*range(32),32,33,0x80000000,0x12345678,r.NEG)
            for value in (1,2,0x7fffffff,0x80000000,0xc7000020,r.NEG)
            for index in (0,33,63) for salt in (0,7)]


def request(case,mode=0,sp=None):
    cookie,value,index,salt=case
    regs,stack=p.inputs(index if index<64 else 0,salt)
    struct.pack_into('<I',stack,r.SP-r.STACK+4,index)
    if sp is not None: regs[7]=sp
    return ' '.join(map(str,[cookie,p.encode(value,cookie),mode,*regs,0x602,
                            *struct.unpack('<1024I',stack)]))+'\n'


def parse(text,count):
    lines=text.splitlines(); r.require(len(lines)==count)
    states=[]
    for line in lines:
        tokens=line.split()
        r.require(len(tokens)==3082 and all(t.isascii() and t.isdecimal() and len(t)<=10 for t in tokens))
        v=list(map(int,tokens)); r.require(v[0] in (0,1) and all(n<=r.NEG for n in v))
        states.append((v[0],dict(registers=v[1:9],flags=v[9]&p.MASK,
            stack=struct.pack('<1024I',*v[10:1034])),v[1034:]))
    return states


def run(sweep,native,runner=None,mode=0,sp=None):
    command=([str(runner)] if runner else [])+[str(Path(native).resolve())]
    done=subprocess.run(command,input=''.join(request(c,mode,sp) for c in sweep),
                        capture_output=True,text=True,timeout=60)
    r.require(done.returncode==0 and not done.stderr and len(done.stdout)<=64*1024*1024)
    return parse(done.stdout,len(sweep))


def verify(state,case):
    failure,actual,pages=state; r.require(failure==0)
    cookie,value,index,salt=case
    r.verify(actual,p.oracle(value,cookie,index,salt))
    expected=[0]*2048
    expected[(p.COOKIE&4095)//4]=cookie
    expected[1024+(p.CACHE&4095)//4+index]=p.encode(value,cookie)
    r.require(pages==expected)


def main(argv=None):
    a=argparse.ArgumentParser(description=__doc__)
    a.add_argument('--native',default=os.environ.get('TS2_GUEST_ENCODED_HOT_ABI_PROBE','build/host/ts2_guest_encoded_hot_abi_probe'))
    a.add_argument('--runner',default=os.environ.get('TS2_GUEST_ENCODED_HOT_ABI_RUNNER'))
    a.add_argument('--private-x86',action='store_true'); args=a.parse_args(argv)
    pe=None
    try:
        sweep=cases(); states=run(sweep,args.native,args.runner)
        if args.private_x86: pe=r.load_image()
        for case,state in zip(sweep,states):
            verify(state,case)
            if pe is not None:
                cookie,value,index,salt=case
                r.verify(p.exercise(pe.get_data(p.RVA,p.SIZE),cookie,p.encode(value,cookie),index,salt),state[1])
        print(json.dumps(dict(cases=len(sweep),privateX86Compared=pe is not None,
            coldSupported=False,originalBodyLifted=False,iatBound=False,startupExecuted=False),sort_keys=True)); return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,subprocess.SubprocessError,p.UcError,r.pefile.PEFormatError):
        print('Encoded hot ABI comparison failed; private details suppressed.',file=sys.stderr); return 2
    finally:
        if pe is not None: pe.close()

if __name__=='__main__': raise SystemExit(main())
