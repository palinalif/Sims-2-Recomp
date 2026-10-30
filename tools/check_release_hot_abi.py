#!/usr/bin/env python3
"""Six-model native release/error/hot composition vs unchanged oracle/pinned x86.

No heap/thread service or runtime binding. Private table travels only via stdin.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import heap_hot_composed_probe as p
r = p.r
chain = p.chain
KINDS = {1: ('heap_free', 3), 2: ('get', 0), 3: ('resolve', 4),
         4: ('set', 1), 5: ('guard', 0), 6: ('fls', 1), 7: ('tls', 1)}


def cases(table=None):
    table = table if table is not None else [(10000+i, 0x80000000+i) for i in range(45)]
    sweep = []
    for context, result in ((0, 0), (1, 1), (1, 0), (0x80000000, 0)):
        for error in (0, 19, r.NEG):
            for pointer in (chain.PTD, r.NEG):
                for value in (p.FLS, r.NEG):
                    for count in range(32):
                        for clobber in (False, True):
                            sweep.append((context, 0x80000000, result, error, 0x80000000,
                                          pointer, table, value, 0x12345660 | count,
                                          len(sweep) % 8, clobber))
    return sweep


def request(case, mode=0, sp=None):
    context, heap, result, error, index, pointer, table, value, cookie, salt, clobber = case
    chain.validate(context, heap, result, error, index, pointer, table)
    regs, stack = chain.release.callback.inputs(context, salt)
    if sp is not None:
        regs[7] = sp
    return ' '.join(map(str, [heap, index, cookie, p.hot.encode(value, cookie),
                              result, error, pointer, int(clobber), mode,
                              *(v for pair in table for v in pair), *regs, 0xcd7,
                              *struct.unpack('<1024I', stack)]))+'\n'


def parse(text, count):
    lines = text.splitlines(); r.require(len(lines) == count)
    states = []
    for line in lines:
        tokens = line.split()
        r.require(1040 <= len(tokens) <= 1080 and all(t.isascii() and t.isdecimal() and
                                                    len(t) <= 10 for t in tokens))
        v = list(map(int, tokens)); r.require(all(n <= r.NEG for n in v) and v[0] in (0, 1))
        n, offset, events = v[1039], 1040, []
        r.require(n <= 7)
        for _ in range(n):
            r.require(offset+3 <= len(v) and v[offset] in KINDS)
            kind, argc = KINDS[v[offset]]
            r.require(offset+3+argc <= len(v))
            events.append((kind, v[offset+3:offset+3+argc], v[offset+1], v[offset+2]))
            offset += 3+argc
        r.require(offset == len(v))
        states.append(dict(failed=v[0], registers=v[1:9], flags=v[9],
                           stack=struct.pack('<1024I', *v[10:1034]),
                           slots={chain.PTD+16: v[1034], chain.accessor.FALLBACK: v[1035]},
                           lastError=v[1036], cacheWords=v[1037:1039], events=events))
    return states


def run(sweep, native=None, runner=None, *, mode=0, sp=None):
    native = native or os.environ.get('TS2_GUEST_RELEASE_HOT_ABI_PROBE',
                                     'build/host/ts2_guest_release_hot_abi_probe')
    runner = runner or os.environ.get('TS2_GUEST_RELEASE_HOT_ABI_RUNNER')
    command = ([str(runner)] if runner else [])+[str(Path(native).resolve())]
    states = []
    # Bound each child/output rather than relaxing existing 60-second limits.
    for start in range(0, len(sweep), 512):
        batch = sweep[start:start+512]
        done = subprocess.run(command, input=''.join(request(c, mode, sp) for c in batch),
                              capture_output=True, text=True, timeout=60)
        r.require(done.returncode == 0 and not done.stderr and len(done.stdout) <= 16*1024*1024)
        states.extend(parse(done.stdout, len(batch)))
    return states


def verify(states, sweep, codes=None):
    r.require(len(states) == len(sweep))
    for actual, case in zip(states, sweep):
        *args, clobber = case
        expected = p.oracle(*args, clobber=clobber)
        state = dict(actual); r.require(state.pop('failed') == 0)
        context, _, result, _, _, pointer, *_ = args
        mask = 0xcd5 if not context or (result == 0 and pointer == chain.PTD) else 0xcc5
        state['flags'] &= mask
        r.verify(state, expected)
        if codes is not None:
            context, heap, result, error, index, pointer, table, value, cookie, salt = args
            original = p.exercise(codes, context, heap, result, error, index, pointer, table,
                                  cookie, p.hot.encode(value, cookie), salt, clobber=clobber)
            r.verify(original, expected); r.verify(state, original)
    return len(sweep)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native'); parser.add_argument('--runner')
    parser.add_argument('--private-x86', action='store_true')
    args = parser.parse_args(argv)
    pe = None
    try:
        table = codes = None
        if args.private_x86:
            pe = r.load_image()
            codes = {body.ENTRY: pe.get_data(body.RVA, body.SIZE) for body in p.BODIES}
            r.require(all(len(codes[body.ENTRY]) == body.SIZE for body in p.BODIES))
            data = pe.get_data(chain.mapper.TABLE-r.BASE, 360); r.require(len(data) == 360)
            table = list(struct.iter_unpack('<II', data))
        sweep = cases(table)
        count = verify(run(sweep, args.native, args.runner), sweep, codes)
        print(json.dumps(dict(cases=count, originalBodies=6 if codes else 0,
                              integerFrameCompared=True, destinationStoreCompared=True,
                              actualHeapExecuted=False, runtimeBound=False,
                              startupExecuted=False), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError,
            p.UcError, chain.pefile.PEFormatError):
        print('Release/hot ABI comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
