#!/usr/bin/env python3
"""Compare 64 pinned pre-existing x86 states; emit counts, never private states."""
import argparse
import hashlib
import json
from pathlib import Path
from android_probe import parse_output, compare
from prepare_private_scoped_dispatch import REFERENCE_SHA


def check(reference, stdout):
    data = reference.read_bytes()
    if hashlib.sha256(data).hexdigest() != REFERENCE_SHA:
        raise ValueError('Reference pin mismatch')
    expected = json.loads(data)['states']
    actual = parse_output(stdout.read_text())
    result = compare(expected, actual)
    if len(expected)!=64 or len(actual)!=64 or result['matched']!=64 or result['differences']:
        raise ValueError('Private state comparison failed')
    return result['matched']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--stdout', type=Path, required=True)
    args = p.parse_args()
    try:
        matched = check(args.reference, args.stdout)
    except (OSError, ValueError, KeyError, TypeError):
        p.exit(1, 'Private reference/output unavailable, malformed or mismatched\n')
    print(f'Private scoped dispatch: {matched}/64 saved x86 states matched')


if __name__ == '__main__':
    main()
