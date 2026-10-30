#!/usr/bin/env python3
"""Compare native value/request/cache policy; optionally execute pinned x86 bodies.

No CPU ABI comparison: native transport has no x86 register/stack state. Private
mode reuses the bounded composition reference, never publishes bytes or states.
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
r, m, c = x.r, x.m, x.c


def cases():
    responses = ((r.H1,0,0,0,0),(0,5,1,1,r.H2),(0,87,0,1,r.H2),
                 (0,87,1,0,r.H2),(0,87,1,1,r.H2),(0,87,1,1,0))
    yield from itertools.product((0,1,31,0x12345678,r.NEG),
        ((0,0),(r.NEG,0),(r.H1,0),(0,r.H2),(r.NEG,r.NEG)),
        itertools.product(responses,repeat=2),(0,0x80000000),range(3))
    for count in range(32):
        for export in (0,0x80000001):
            yield (0x12345660 | count,(0,0),((0,87,1,1,r.H1),(r.H2,0,0,0,0)),export,2)


def expected(case, bodies=None):
    cookie,modules,responses,export,length = case
    model = x.oracle(cookie,modules,responses,export,length)
    if bodies is not None:
        observed = x.exercise(*bodies,cookie,modules,responses,export,length)
        r.verify(observed,model)
        model = observed
    events = []
    for kind,args,_,_ in model['events']:
        events.extend([{'load':1,'error':2,'export':3,'compare':4}[kind],
                       *(args+[0]*(3-len(args)))])
    return [model['eax'],model['cache'],*model['modules'],model['eax'],
            len(model['events']),*events]


def parse(text, count):
    lines = text.splitlines()
    r.require(len(lines) == count)
    rows = []
    for line in lines:
        words = line.split()
        r.require(all(w.isascii() and w.isdecimal() for w in words))
        row = list(map(int,words))
        r.require(len(row) >= 6 and all(0 <= v <= r.NEG for v in row))
        r.require(row[5] <= 11 and len(row) == 6+4*row[5])
        rows.append(row)
    return rows


def compare(observed, wanted):
    r.require(observed == wanted)


def check(command, inputs, bodies=None):
    data = '\n'.join(' '.join(map(str,[cookie,length,*modules,
        *responses[0],*responses[1],export]))
        for cookie,modules,responses,export,length in inputs)+'\n'
    result = subprocess.run(command,input=data,text=True,capture_output=True,timeout=120)
    r.require(result.returncode == 0 and not result.stderr)
    observed = parse(result.stdout,len(inputs))
    for row,case in zip(observed,inputs): compare(row,expected(case,bodies))
    return len(inputs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',type=Path,default=Path(os.environ.get(
        'TS2_GUEST_ENCODED_RESOLVER_PROBE','build/host/ts2_guest_encoded_resolver_probe')))
    parser.add_argument('--runner',default=os.environ.get('TS2_GUEST_ENCODED_RESOLVER_RUNNER',''))
    parser.add_argument('--private-x86',action='store_true')
    args = parser.parse_args(argv)
    pe = None
    try:
        bodies = None
        if args.private_x86:
            pe = r.load_image()
            bodies = (pe.get_data(c.RVA,c.SIZE),pe.get_data(m.RVA,m.SIZE),
                      pe.get_data(x.ENCODER-r.BASE,x.ENCODER_SIZE))
            r.require(tuple(map(len,bodies)) == (c.SIZE,m.SIZE,x.ENCODER_SIZE))
        count = check([*shlex.split(args.runner),str(args.native.resolve())],list(cases()),bodies)
        print(json.dumps(dict(cases=count,privateX86Compared=bodies is not None,
            cpuAbiCompared=False,windowsServicesExecuted=False,startupExecuted=False),sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,x.struct.error,
            x.UcError,x.pefile.PEFormatError,subprocess.SubprocessError):
        print('Encoded resolver policy comparison failed; private details suppressed.',file=sys.stderr)
        return 2
    finally:
        if pe is not None: pe.close()


if __name__ == '__main__': raise SystemExit(main())
