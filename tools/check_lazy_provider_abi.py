#!/usr/bin/env python3
"""Native slow-provider ABI vs unchanged lazy oracle/optional pinned original x86."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import ptd_lazy_probe as p
r = p.r
KINDS = ('get', 'query', 'set', 'write', 'alloc', 'initialize', 'free')
COUNTS = (0, 1, 1, 2, 2, 2, 1)


def cases():
    return [(index, claim, pointer, publish, error, salt, clobber)
            for index in (0, 0x80000000, r.NEG)
            for claim in (0, 1, 0x80000000)
            for pointer in (0, 0x81234000, r.NEG)
            for publish in (0, 1, 0x80000000)
            for error in (0, r.NEG)
            for salt in range(2) for clobber in (False, True)]


def request(case, mode=0, sp=None):
    index, claim, pointer, publish, error, salt, clobber = case
    regs, stack, _ = p.p.init.inputs(salt)
    if sp is not None: regs[7] = sp
    return ' '.join(map(str, [index, claim, pointer, publish, error, int(clobber), mode,
        *regs, 0xcd7, *struct.unpack('<1024I', stack)]))+'\n'


def parse(text, count):
    lines = text.splitlines(); r.require(len(lines) == count)
    result = []
    for line in lines:
        tokens = line.split()
        r.require(len(tokens) >= 1036 and all(t.isascii() and t.isdecimal() and
                                              len(t) <= 10 for t in tokens))
        v = list(map(int, tokens)); r.require(all(n <= r.NEG for n in v))
        r.require(v[0] in (0, 1) and v[1035] <= 9)
        events, pos = [], 1036
        for _ in range(v[1035]):
            r.require(pos+3 <= len(v)); k, ret, sp = v[pos:pos+3]; pos += 3
            r.require(k < len(KINDS) and pos+COUNTS[k] <= len(v))
            args = v[pos:pos+COUNTS[k]]; pos += COUNTS[k]
            events.append((KINDS[k], args, (ret-r.BASE)&r.NEG, sp))
        r.require(pos == len(v))
        result.append((v[0], dict(registers=v[1:9], flags=v[9],
            stack=struct.pack('<1024I', *v[10:1034]), events=events), v[1034]))
    return result


def run(sweep, native, runner=None, mode=0, sp=None):
    command = ([str(runner)] if runner else [])+[str(Path(native).resolve())]
    done = subprocess.run(command, input=''.join(request(c, mode, sp) for c in sweep),
                          capture_output=True, text=True, timeout=60)
    r.require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 32*1024*1024)
    return parse(done.stdout, len(sweep))


def normalized(state, case):
    failed, actual, error = state
    r.require(failed == 0 and error == case[4])
    actual = dict(actual); actual['flags'] &= 0xcc5
    return actual


def verify(state, case):
    *args, clobber = case
    r.verify(normalized(state, case), p.oracle(*args, clobber=clobber))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', default=os.environ.get('TS2_GUEST_LAZY_PROVIDER_ABI_PROBE',
                        'build/host/ts2_guest_lazy_provider_abi_probe'))
    parser.add_argument('--runner', default=os.environ.get('TS2_GUEST_LAZY_PROVIDER_ABI_RUNNER'))
    parser.add_argument('--private-x86', action='store_true')
    args = parser.parse_args(argv); pe = None
    try:
        sweep = cases(); states = run(sweep, args.native, args.runner)
        r.require(len(states) == len(sweep))
        code = None
        if args.private_x86:
            pe = r.load_image(); code = pe.get_data(p.p.RVA, p.p.SIZE)
            r.require(len(code) == p.p.SIZE)
        for case, state in zip(sweep, states):
            verify(state, case)
            if code is not None:
                *values, clobber = case
                r.verify(normalized(state, case), p.exercise(code, *values, clobber=clobber))
        print(json.dumps(dict(cases=len(sweep), privateX86Compared=pe is not None,
            actualStorageImplemented=False, actualAllocationImplemented=False,
            runtimeBound=False, startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, p.pefile.PEFormatError):
        print('Lazy-provider ABI comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None: pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
