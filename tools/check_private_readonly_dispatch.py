#!/usr/bin/env python3
"""Compare private fixture stdout to the pinned pre-existing 96 x86 states.

Reports counts only. Does not execute x86, modify inputs, or publish states.
"""
import argparse
import hashlib
import json
from pathlib import Path
from android_probe import parse_output, compare
from prepare_private_readonly_dispatch import REFERENCE_SHA


def check(reference, stdout):
    data = reference.read_bytes()
    if hashlib.sha256(data).hexdigest() != REFERENCE_SHA:
        raise ValueError('Reference pin mismatch')
    expected = json.loads(data)['states']
    actual = parse_output(stdout.read_text())
    result = compare(expected, actual)
    if len(expected) != 96 or len(actual) != 96 or result['matched'] != 96 or result['differences']:
        raise ValueError('Private state comparison failed')
    return result['matched']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--stdout', type=Path, required=True)
    args = parser.parse_args()
    try:
        matched = check(args.reference, args.stdout)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(1, 'Private reference/output unavailable, malformed or mismatched\n')
    print(f'Private read-only dispatch: {matched}/96 saved x86 states matched')


if __name__ == '__main__':
    main()
