#!/usr/bin/env python3
"""Diagnostic native composition vs independent frame oracle and optional x86.

No original bytes/states emitted. Cold CPU ABI and Windows APIs unsupported.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import storage_hot_composed_probe as p
r = p.r


def request(case, mode=0, sp=None):
    value, cookie, result, index, salt, clobber = case
    regs, stack = p.query.free.inputs(index, salt)
    if sp is not None:
        regs[7] = sp
    return ' '.join(map(str, [cookie, p.hot.encode(value, cookie), result,
        int(clobber), mode, *regs, 0xCD7, *struct.unpack('<1024I', stack)]))+'\n'


def parse(text, count):
    lines = text.splitlines(); r.require(len(lines) == count)
    states = []
    for line in lines:
        tokens = line.split()
        r.require(all(t.isascii() and t.isdecimal() and len(t) <= 10 for t in tokens))
        v = list(map(int, tokens))
        r.require(len(v) >= 3083 and all(n <= r.NEG for n in v) and v[0] in (0, 1))
        state = dict(registers=v[1:9], flags=v[9] & p.hot.MASK,
                     stack=struct.pack('<1024I', *v[10:1034]), events=[], dataPages={})
        for i, page in enumerate(sorted(p.pages(0, 0))):
            state['dataPages'][page] = struct.pack('<1024I', *v[1034+1024*i:2058+1024*i])
        n = v[3082]; r.require(n <= 3); pos = 3083
        for _ in range(n):
            r.require(pos < len(v))
            kind = v[pos]; r.require(kind in (1, 2, 3, 4))
            size = {1: 15, 2: 11, 3: 12, 4: 12}[kind]
            r.require(pos+size <= len(v))
            e = v[pos:pos+size]; pos += size
            state['events'].append(dict(kind={1: 'resolve', 2: 'guard', 3: 'fls', 4: 'tls'}[kind],
                returnRva=e[1], registers=e[2:10], flags=e[10] & p.hot.MASK, args=e[11:]))
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
    failure, actual = state; r.require(failure == 0)
    value, cookie, result, index, salt, clobber = case
    r.verify(actual, p.oracle(value, cookie, result, index, salt, clobber=clobber))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', default=os.environ.get('TS2_GUEST_STORAGE_HOT_ABI_PROBE',
                        'build/host/ts2_guest_storage_hot_abi_probe'))
    parser.add_argument('--runner', default=os.environ.get('TS2_GUEST_STORAGE_HOT_ABI_RUNNER'))
    parser.add_argument('--private-x86', action='store_true')
    args = parser.parse_args(argv); pe = None
    try:
        sweep = p.cases(); states = run(sweep, args.native, args.runner)
        codes = None
        if args.private_x86:
            pe = r.load_image()
            codes = {b.ENTRY: pe.get_data(b.RVA, b.SIZE) for b in p.BODIES}
        for case, state in zip(sweep, states):
            verify(state, case)
            if codes is not None:
                value, cookie, result, index, salt, clobber = case
                r.verify(p.exercise(codes, cookie, p.hot.encode(value, cookie), result,
                                   index, salt, clobber=clobber), state[1])
        print(json.dumps(dict(cases=len(sweep), privateX86Compared=pe is not None,
            coldSupported=False, originalBodiesLifted=False, windowsStorageExecuted=False,
            iatBound=False, startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, r.pefile.PEFormatError):
        print('Storage hot ABI comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
