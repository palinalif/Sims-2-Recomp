#!/usr/bin/env python3
"""Native value-only mapper vs independent oracle and optional pinned x86.

Private tables travel only through child stdin, never command arguments/output.
No recovery, new binding or original-body lift occurs.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import os_error_probe as p
r = p.r


def cases(table=None):
    fixture = table if table is not None else [(10000+n, 0x80000000+n) for n in range(p.COUNT)]
    errors = set(range(256)) | {0x7fffffff, 0x80000000, r.NEG}
    for key, _ in fixture:
        errors.update(((key-1) & r.NEG, key, (key+1) & r.NEG))
    result = [(error, fixture) for error in sorted(errors)]
    for error in (0, 18, 19, 36, 37, 187, 188, 202, 203, r.NEG):
        for position in range(p.COUNT):
            authored = [(20000+n, n) for n in range(p.COUNT)]
            authored[position] = (error, (0, 0x80000000, r.NEG)[position % 3])
            result.append((error, authored))
        duplicate = [(error, 0), (error, r.NEG)] + [(20000+n, n) for n in range(p.COUNT-2)]
        result.append((error, duplicate))
    return result


def request(case):
    error, table = case
    p.validate(error, table)
    return ' '.join(map(str, [error, *(v for pair in table for v in pair)]))+'\n'


def parse(text, count):
    lines = text.splitlines()
    r.require(len(lines) == count)
    values = []
    for index, line in enumerate(lines):
        tokens = line.split()
        r.require(len(tokens) == 2 and all(t.isascii() and t.isdecimal() and
                                         len(t) <= 10 for t in tokens))
        seq, value = map(int, tokens)
        r.require(seq == index and 0 <= value <= r.NEG)
        values.append(value)
    return values


def run(sweep, native, runner=None):
    command = ([str(runner)] if runner else [])+[str(Path(native).resolve())]
    done = subprocess.run(command, input=''.join(map(request, sweep)),
                          capture_output=True, text=True, timeout=60)
    r.require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 128*1024)
    return parse(done.stdout, len(sweep))


def verify(values, sweep, code=None):
    r.require(len(values) == len(sweep))
    for value, (error, table) in zip(values, sweep):
        expected = p.oracle(error, table)
        r.require(value == expected['registers'][0])
        if code is not None:
            # Retain the existing full x86-state oracle, not just EAX.
            r.verify(p.exercise(code, error, table), expected)
    return len(sweep)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', default=os.environ.get('TS2_GUEST_OS_ERROR_PROBE',
                        'build/host/ts2_guest_os_error_probe'))
    parser.add_argument('--runner', default=os.environ.get('TS2_GUEST_OS_ERROR_RUNNER'))
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
            valueOnly=True, cpuAbiCompared=False, runtimeBound=False,
            startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, p.pefile.PEFormatError):
        print('OS-error policy comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
