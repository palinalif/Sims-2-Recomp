#!/usr/bin/env python3
"""Native existing-slot provider composition vs independent oracle/optional x86.

Diagnostic only. Emits counts, never original bytes or private reference states.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import provider_hot_composed_probe as p
r = p.r
KINDS = {1: ('resolve', 4), 2: ('guard', 0), 3: ('fls', 1),
         4: ('tls', 1), 5: ('get', 0), 6: ('set', 1)}


def request(case, mode=0, sp=None):
    value, cookie, pointer, index, error, salt, clobber = case
    regs, stack, _ = p.provider.init.inputs(salt)
    if sp is not None:
        regs[7] = sp
    return ' '.join(map(str, [cookie, p.hot.encode(value, cookie), index, pointer,
        int(clobber), mode, error, *regs, 0xCD7, *struct.unpack('<1024I', stack)]))+'\n'


def parse(text, count):
    lines = text.splitlines(); r.require(len(lines) == count)
    states = []
    for line in lines:
        tokens = line.split()
        r.require(all(t.isascii() and t.isdecimal() and len(t) <= 10 for t in tokens))
        v = list(map(int, tokens))
        r.require(len(v) >= 3084 and all(n <= r.NEG for n in v) and v[0] in (0, 1))
        state = dict(registers=v[1:9], flags=v[9] & 0xCC5,
                     stack=struct.pack('<1024I', *v[10:1034]), events=[], dataPages={}, lastError=v[3082])
        for i, page in enumerate(sorted(p.pages(0, 0, 0))):
            state['dataPages'][page] = struct.pack('<1024I', *v[1034+1024*i:2058+1024*i])
        n = v[3083]; r.require(n <= 5); pos = 3084
        for _ in range(n):
            r.require(pos < len(v) and v[pos] in KINDS)
            kind, size = KINDS[v[pos]]; size += 3
            r.require(pos+size <= len(v))
            e = v[pos:pos+size]; pos += size
            state['events'].append((kind, e[3:], e[1], e[2]))
        r.require(pos == len(v))
        states.append((v[0], state))
    return states


def run(sweep, native, runner=None, mode=0, sp=None):
    command = ([str(runner)] if runner else [])+[str(Path(native).resolve())]
    states = []
    for start in range(0, len(sweep), 256):
        batch = sweep[start:start+256]
        done = subprocess.run(command, input=''.join(request(c, mode, sp) for c in batch),
                              capture_output=True, text=True, timeout=60)
        r.require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 16*1024*1024)
        states.extend(parse(done.stdout, len(batch)))
    return states


def verify(state, case):
    failed, actual = state; r.require(failed == 0)
    value, cookie, pointer, index, error, salt, clobber = case
    r.verify(actual, p.oracle(value, cookie, pointer, index, error, salt, clobber=clobber))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', default=os.environ.get('TS2_GUEST_PROVIDER_HOT_ABI_PROBE',
                        'build/host/ts2_guest_provider_hot_abi_probe'))
    parser.add_argument('--runner', default=os.environ.get('TS2_GUEST_PROVIDER_HOT_ABI_RUNNER'))
    parser.add_argument('--private-x86', action='store_true')
    args = parser.parse_args(argv); pe = None
    try:
        sweep = p.cases(); states = run(sweep, args.native, args.runner)
        r.require(len(states) == len(sweep))
        codes = None
        if args.private_x86:
            pe = r.load_image()
            codes = {b.ENTRY: pe.get_data(b.RVA, b.SIZE) for b in p.BODIES}
        for case, state in zip(sweep, states):
            verify(state, case)
            if codes is not None:
                value, cookie, pointer, index, error, salt, clobber = case
                r.verify(p.exercise(codes, cookie, p.hot.encode(value, cookie), pointer,
                                   index, error, salt, clobber=clobber), state[1])
        print(json.dumps(dict(cases=len(sweep), privateX86Compared=pe is not None,
            coldSupported=False, originalBodiesLifted=False, windowsStorageExecuted=False,
            endpointCpuCompared=False, iatBound=False, startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, r.pefile.PEFormatError):
        print('Provider hot ABI comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
