#!/usr/bin/env python3
"""Read-only PE32 little-endian pointer search; candidates, never call sites."""
import argparse
import json
from pathlib import Path
import struct
import sys

import pefile

MAX_IMAGE_BYTES = 256 * 1024 * 1024


def scan(data: bytes, target_va: int, max_results: int = 256) -> dict:
    if not 0 <= target_va <= 0xFFFFFFFF:
        raise ValueError('target must be a uint32 VA')
    if not 1 <= max_results <= 100000:
        raise ValueError('max-results must be between 1 and 100000')
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError('image exceeds scan budget')
    pe = pefile.PE(data=data, fast_load=True)
    try:
        if pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise ValueError('only PE32 images are supported')
        base = pe.OPTIONAL_HEADER.ImageBase
        size = pe.OPTIONAL_HEADER.SizeOfImage
        headers = pe.OPTIONAL_HEADER.SizeOfHeaders
        # Explicit disk-backed mapping: headers plus every raw section, including
        # raw padding. No overlay, zero-fill, cross-region words or alignment filter.
        regions = [(0, 0, headers)]
        regions += [(s.PointerToRawData, s.VirtualAddress, s.SizeOfRawData)
                    for s in pe.sections if s.SizeOfRawData]
        if not 0 < headers <= len(data) or not 0 < size <= 0x100000000 - base:
            raise ValueError('invalid image bounds')
        for raw, rva, length in regions:
            if raw + length > len(data) or rva + length > size:
                raise ValueError('unbacked or out-of-image mapping')
        for index, (raw, rva, length) in enumerate(regions):
            for other_raw, other_rva, other_length in regions[:index]:
                if (raw < other_raw + other_length and other_raw < raw + length
                        or rva < other_rva + other_length and other_rva < rva + length):
                    raise ValueError('ambiguous overlapping mappings')
        needle = struct.pack('<I', target_va)
        rvas = []
        count = 0
        for raw, rva, length in sorted(regions, key=lambda region: region[1]):
            position = raw
            while True:
                position = data.find(needle, position, raw + length)
                if position < 0:
                    break
                count += 1
                if len(rvas) < max_results:
                    rvas.append(f'0x{rva + position - raw:X}')
                position += 1  # Include overlapping and unaligned occurrences.
        return {'rvas': rvas, 'count': count, 'truncated': count > len(rvas)}
    finally:
        pe.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, default=Path(
        'work/interop-legacy-002/analysis-image.bin'))
    parser.add_argument('--va', required=True, type=lambda value: int(value, 0))
    parser.add_argument('--max-results', type=int, default=256)
    args = parser.parse_args(argv)
    try:
        with args.image.open('rb') as source:
            data = source.read(MAX_IMAGE_BYTES + 1)
        result = scan(data, args.va, args.max_results)
    except (OSError, ValueError, pefile.PEFormatError):
        # Do not echo input contents (including pefile's malformed-header dumps).
        print('pointer-scan: invalid input, bounds, arguments or unavailable image', file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
