#!/usr/bin/env python3
"""Native error-slot accessor vs existing independent oracle/optional pinned x86."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import error_slot_probe as p
r = p.r


def cases():
    return [(pointer, salt, clobber)
            for pointer in (0, 1, 15, 16, 0x7fffffef, 0x7ffffff0, 0x80000000,
                            0xffffffef, 0xfffffff0, r.NEG)
            for salt in range(8) for clobber in (False, True)]


def request(case, mode=0, sp=None):
    pointer, salt, clobber = case
    regs, stack, _ = p.init.inputs(salt)
    if sp is not None: regs[7] = sp
    return ' '.join(map(str, [pointer, int(clobber), mode, *regs, 0xcd7,
                             *struct.unpack('<1024I', stack)]))+'\n'


def parse(text, count):
    lines = text.splitlines(); r.require(len(lines) == count)
    result = []
    for line in lines:
        tokens = line.split()
        r.require(len(tokens) == 1037 and all(t.isascii() and t.isdecimal() and
                                             len(t) <= 10 for t in tokens))
        v = list(map(int, tokens))
        r.require(all(n <= r.NEG for n in v) and v[0] in (0, 1) and v[1034] <= 1)
        events = [('provider', [], (v[1035]-r.BASE) & r.NEG, v[1036])] if v[1034] else []
        r.require(v[1034] or v[1035:1037] == [0, 0])
        result.append((v[0], dict(registers=v[1:9], flags=v[9],
            stack=struct.pack('<1024I', *v[10:1034]), events=events)))
    return result


def run(sweep, native, runner=None, mode=0, sp=None):
    command = ([str(runner)] if runner else [])+[str(Path(native).resolve())]
    done = subprocess.run(command, input=''.join(request(c, mode, sp) for c in sweep),
                          capture_output=True, text=True, timeout=60)
    r.require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 8*1024*1024)
    return parse(done.stdout, len(sweep))


def normalized(state, case):
    failed, actual = state; r.require(failed == 0)
    actual = dict(actual)
    actual['flags'] &= 0xcd5 if case[0] else 0xcc5
    return actual


def verify(state, case):
    pointer, salt, clobber = case
    r.verify(normalized(state, case), p.oracle(pointer, salt, clobber=clobber))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', default=os.environ.get('TS2_GUEST_ERROR_SLOT_ABI_PROBE',
                        'build/host/ts2_guest_error_slot_abi_probe'))
    parser.add_argument('--runner', default=os.environ.get('TS2_GUEST_ERROR_SLOT_ABI_RUNNER'))
    parser.add_argument('--private-x86', action='store_true')
    args = parser.parse_args(argv); pe = None
    try:
        sweep = cases(); states = run(sweep, args.native, args.runner)
        r.require(len(states) == len(sweep))
        code = None
        if args.private_x86:
            pe = r.load_image(); code = pe.get_data(p.RVA, p.SIZE)
            r.require(len(code) == p.SIZE)
        for case, state in zip(sweep, states):
            verify(state, case)
            if code is not None:
                pointer, salt, clobber = case
                r.verify(normalized(state, case), p.exercise(code, pointer, salt, clobber=clobber))
        print(json.dumps(dict(cases=len(sweep), privateX86Compared=pe is not None,
            providerExecuted=False, threadStorageImplemented=False, runtimeBound=False,
            startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, p.pefile.PEFormatError):
        print('Error-slot ABI comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None: pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
