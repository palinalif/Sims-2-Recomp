#!/usr/bin/env python3
"""Bounded helper + actual comparator differential, with authored wide operands.

Pinned private image only; no real OS loads or original prefix contents. Emits
metadata/counts only. Not a guest ABI adapter or startup execution proof.
"""
import argparse
import itertools
import json
import struct
import subprocess
import sys

import pefile
from unicorn import UcError

import loader_policy_probe as p
import wide_compare_probe as w

require = p.require


def vectors():
    # Synthetic comparison operand at the helper's fixed VA, not original text.
    prefix = (65, 0x8000, 0xFFFF, 68, 69, 70, 71, 0)
    pairs = [(prefix, prefix),
             (prefix[:7] + (99,), prefix),  # unit8 must not influence retry
             (prefix[:6] + (72,), prefix),  # unit7 must influence retry
             ((0,), (0,)), ((1,), (2,)), ((0xFFFF,), (1,)),
             ((65, 0), (65, 0)), ((65, 0x7FFF), prefix),
             ((97,), prefix)]  # no case folding
    for (left, right), first, error, retry in itertools.product(
            pairs, (0, 0x80000000), (0, 87, 0xFFFFFFFF), (0, 0xFFFFFFFE)):
        yield left, right, first, error, retry
    # Unmapped operands must remain unread on bypass paths.
    yield (), (), 0x80000000, 87, 0
    yield (), (), 0, 5, 0


def expected_for(vector):
    left, right, first, error, retry = vector
    comparison = w.oracle(left, right, 7) if first == 0 and error == 87 else 0
    return p.oracle(first, error, comparison, retry)


def compare_native(binary, cases):
    request = ''.join(' '.join(map(str, (first, error, retry, len(left), len(right),
                                        *left, *right))) + '\n'
                      for left, right, first, error, retry in cases)
    run = subprocess.run([str(binary)], input=request, text=True,
                         capture_output=True, timeout=30, check=False)
    require(run.returncode == 0 and not run.stderr)
    lines = run.stdout.splitlines()
    require(len(lines) == len(cases))
    for line, case in zip(lines, cases):
        expected = expected_for(case)
        # Comparator is bound directly; transport records only external services.
        calls = [e for e in expected['events'] if e[0] != 'compare']
        words = [expected['eax'], len(calls)]
        for kind, args, _, _ in calls:
            words.extend([{'load': 1, 'error': 2}[kind], *(args or [0, 0, 0])])
        require([int(v) for v in line.split()] == words)


def probe(pe, native=None):
    helper = pe.get_data(p.ENTRY_RVA, p.SIZE)
    comparator = pe.get_data(w.ENTRY_RVA, w.SIZE)
    require(len(helper) == p.SIZE and len(comparator) == w.SIZE)
    cases = list(vectors())
    paths = [0, 0, 0, 0]
    for n, case in enumerate(cases):
        left, right, first, error, retry = case
        expected = expected_for(case)
        comparison = w.oracle(left, right, 7) if not first and error == 87 else 0
        p.exercise(helper, (first, error, comparison, retry), expected, n,
                   comparator=comparator, operands=(left, right))
        paths[0 if first else 1 if error != 87 else 2 if comparison == 0 else 3] += 1
    if native is not None:
        compare_native(native, cases)
    return {'helperRva': hex(p.ENTRY_RVA), 'comparatorRva': hex(w.ENTRY_RVA),
            'cases': len(cases), 'pathCounts': paths,
            'nativeCasesCompared': len(cases) if native is not None else 0,
            'actualComparatorExecuted': True, 'originalPrefixContentsUsed': False,
            'windowsServicesExecuted': False, 'arm64Executed': False,
            'startupExecuted': False, 'nativeGuestAbiCompared': False}


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', help='Host ts2_guest_loader_composed_probe')
    args = parser.parse_args(argv)
    pe = None
    try:
        pe = p.resolver.load_image()
        result = probe(pe, args.native)
    except (OSError, ValueError, pefile.PEFormatError, UcError, struct.error,
            subprocess.SubprocessError):
        print('loader-composed-probe: unavailable/pin mismatch/bounded comparison failed',
              file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
