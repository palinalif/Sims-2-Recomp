#!/usr/bin/env python3
"""Private pinned resolver/helper/comparator composition; authored OS responses.

Synthetic names/prefix only; optional native policy comparison. No Windows,
races, native guest ABI or startup proof.
Outputs counts/RVAs only; reference emulation is development-only.
"""
import argparse
import itertools
import json
import struct
import sys
import subprocess

import pefile
from unicorn import UcError

import resolver_probe as r
import loader_policy_probe as p
import wide_compare_probe as w

NAMES = (r.NAME, r.NAME + 128)
PREFIX = (65, 66, 67, 68, 69, 70, 71, 0)


def expected_for(modules, responses, export, operands):
    loads = []
    for (first, error, retry), name in zip(responses, operands[:2]):
        comparison = w.oracle(name, operands[2], 7) if not first and error == 87 else 0
        loads.append(p.oracle(first, error, comparison, retry)['eax'])
    expected, selected = r.oracle(modules, loads, export, NAMES)
    events = []
    for event in expected['events']:
        events.append(event)
        if event[0] != 'load':
            continue
        index = NAMES.index(event[1][0])
        first, error, retry = responses[index]
        comparison = w.oracle(operands[index], operands[2], 7) if not first and error == 87 else 0
        nested = p.oracle(first, error, comparison, retry)
        for kind, args, ret, sp in nested['events']:
            args = [NAMES[index] if v == r.NAME else v for v in args]
            events.append(('api_load' if kind == 'load' else kind, args, ret, sp - 32))
    return {**expected, 'events': events}, loads, selected


def vectors():
    # Immediate success; no retry error; equal prefix; differing prefix with
    # failed/successful retry. Also unit8-only difference and unsigned units.
    policies = ((r.H1, 87, 0), (0, 5, 0), (0, 87, 0), (0, 87, r.H2))
    for modules, a, b, export, names in itertools.product(
            ((0, 0), (r.NEG, 0), (r.H1, 0), (0, r.H2), (r.NEG, r.NEG)),
            policies, policies, (0, 0x80000000, 0xFFFFFFFE),
            ((PREFIX, PREFIX), ((1,), (0xFFFF,)),
             (PREFIX[:7] + (99,), PREFIX[:6] + (72,)))):
        yield modules, (a, b), export, (*names, PREFIX)


def native_words(case):
    modules, responses, export, operands = case
    expected, _, _ = expected_for(*case)
    calls = []
    for kind, args, _, _ in expected['events']:
        if kind in ('load', 'compare'):
            continue
        calls.extend([{'api_load': 1, 'error': 2, 'export': 3}[kind],
                      *(args + [0] * (3 - len(args)))])
    return [expected['eax'], expected['cache'], *expected['modules'],
            0 if expected['cache'] == r.NEG else expected['cache'], len(calls) // 4,
            *calls]


def compare_native(binary, cases):
    lines = []
    for modules, responses, export, operands in cases:
        words = [*modules, *(v for response in responses for v in response), export,
                 *map(len, operands), *(v for operand in operands for v in operand)]
        lines.append(' '.join(map(str, words)))
    run = subprocess.run([str(binary)], input='\n'.join(lines) + '\n', text=True,
                         capture_output=True, timeout=30, check=False)
    r.require(run.returncode == 0 and not run.stderr)
    output = run.stdout.splitlines()
    r.require(len(output) == len(cases))
    for line, case in zip(output, cases):
        r.require([int(v) for v in line.split()] == native_words(case))


def probe(pe, native=None):
    code = pe.get_data(0x82A212, 160)
    helper = pe.get_data(p.ENTRY_RVA, p.SIZE)
    comparator = pe.get_data(w.ENTRY_RVA, w.SIZE)
    r.require(len(code) == 160 and len(helper) == p.SIZE and len(comparator) == w.SIZE)
    # Do not use original DLL names/prefix contents in this experiment.
    table = bytearray(4096)
    struct.pack_into('<II', table, 0xD8C, *NAMES)
    counts = [0, 0, 0]
    cases = 0
    inputs = list(vectors())
    for modules, responses, export, operands in inputs:
        expected, loads, selected = expected_for(modules, responses, export, operands)
        r.exercise(code, bytes(table), modules, loads, export, cases, expected,
                   composition=(helper, comparator, operands, responses))
        counts[2 if selected is None else selected] += 1
        cases += 1
    if native is not None:
        compare_native(native, inputs)
    return {'nativeCasesCompared': cases if native is not None else 0,
            'nativeCacheReentries': cases if native is not None else 0,
            'resolverRva': '0x82A212', 'helperRva': hex(p.ENTRY_RVA),
            'comparatorRva': hex(w.ENTRY_RVA), 'cases': cases,
            'sameMemoryReentries': cases, 'pathCounts': counts,
            'originalHelperAndComparatorExecuted': True,
            'originalNameOrPrefixContentsUsed': False,
            'windowsServicesExecuted': False, 'nativeResolverExecuted': native is not None,
            'nativeGuestAbiCompared': False,
            'arm64Executed': False, 'startupExecuted': False,
            'raceOrFreeLibraryTested': False, 'fullStackFlagsVolatileCompared': False}


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', help='Host ts2_guest_resolver_probe')
    args = parser.parse_args(argv)
    pe = None
    try:
        pe = r.load_image()
        result = probe(pe, args.native)
    except (OSError, ValueError, pefile.PEFormatError, UcError, struct.error,
            subprocess.SubprocessError):
        print('resolver-composed-probe: unavailable/pin mismatch/bounded comparison failed', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
