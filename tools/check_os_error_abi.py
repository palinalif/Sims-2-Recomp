#!/usr/bin/env python3
"""Full native mapper integer ABI vs existing oracle and optional pinned x86.

Private tables travel only via child stdin. No recovery or runtime binding.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import check_os_error_policy as policy
p, r = policy.p, policy.r


def cases(table=None):
    return [(error, fixture, salt) for error, fixture in policy.cases(table)
            for salt in range(2)]


def request(case):
    error, table, salt = case
    p.validate(error, table)
    regs, stack, _ = p.init.inputs(salt)
    struct.pack_into('<I', stack, r.SP-r.STACK+4, error)
    return ' '.join(map(str, [*(v for pair in table for v in pair), *regs, 0xcd7,
                             *struct.unpack('<1024I', stack)]))+'\n'


def parse(text, count):
    lines = text.splitlines()
    r.require(len(lines) == count)
    result = []
    for index, line in enumerate(lines):
        tokens = line.split()
        r.require(len(tokens) == 1034 and all(t.isascii() and t.isdecimal() and
                                             len(t) <= 10 for t in tokens))
        v = list(map(int, tokens))
        r.require(v[0] == index and all(n <= r.NEG for n in v))
        result.append(dict(registers=v[1:9], flags=v[9],
                           stack=struct.pack('<1024I', *v[10:])))
    return result


def run(sweep, native, runner=None):
    command = ([str(runner)] if runner else [])+[str(Path(native).resolve())]
    done = subprocess.run(command, input=''.join(map(request, sweep)),
                          capture_output=True, text=True, timeout=60)
    r.require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 32*1024*1024)
    return parse(done.stdout, len(sweep))


def normalized(state):
    result = dict(state)
    result['flags'] &= 0xcd5
    return result


def verify(states, sweep, code=None):
    r.require(len(states) == len(sweep))
    for state, (error, table, salt) in zip(states, sweep):
        expected = p.oracle(error, table, salt)
        r.verify(normalized(state), expected)
        if code is not None:
            original = p.exercise(code, error, table, salt)
            r.verify(original, expected)
            r.verify(normalized(state), original)
    return len(sweep)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', default=os.environ.get('TS2_GUEST_OS_ERROR_ABI_PROBE',
                        'build/host/ts2_guest_os_error_abi_probe'))
    parser.add_argument('--runner', default=os.environ.get('TS2_GUEST_OS_ERROR_ABI_RUNNER'))
    parser.add_argument('--private-x86', action='store_true')
    args = parser.parse_args(argv)
    pe = None
    try:
        code = table = None
        if args.private_x86:
            pe = r.load_image()
            code = pe.get_data(p.RVA, p.SIZE)
            data = pe.get_data(p.TABLE-r.BASE, p.COUNT*8)
            r.require(len(code) == p.SIZE and len(data) == p.COUNT*8)
            table = list(struct.iter_unpack('<II', data))
        sweep = cases(table)
        count = verify(run(sweep, args.native, args.runner), sweep, code)
        print(json.dumps(dict(cases=count, privateX86Compared=pe is not None,
            cpuAbiCompared=True, runtimeBound=False, slotStoreImplemented=False,
            startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, p.pefile.PEFormatError):
        print('OS-error ABI comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
