#!/usr/bin/env python3
"""Development-only bounded unsigned UTF-16-unit comparator differential.

Uses only the existing hash-pinned private analysis image. Emits metadata/counts,
never code, strings or raw states. Does not execute Windows or game startup.
"""
import argparse
import json
import random
import struct
import subprocess
import sys

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

import resolver_probe as r

ENTRY_RVA, SIZE = 0x845B53, 58
ENTRY = r.BASE + ENTRY_RVA
LEFT, RIGHT = 0xC1000000, 0xC2000000
require = r.require


def oracle(left, right, count):
    """Exact difference, not just sign; count measures 16-bit units, not bytes."""
    require(isinstance(count, int) and 0 <= count <= 32)
    require(all(isinstance(v, int) and 0 <= v <= 65535 for v in (*left, *right)))
    for i in range(count):
        require(i < len(left) and i < len(right))
        a, b = left[i], right[i]
        if a != b or a == 0:
            return (a - b) & r.NEG
    return 0


def exercise(code, left, right, count, expected, salt=0, unaligned=False):
    """Hook-free single steps, bounded code and guard-ended guest inputs.

    No implicit terminator is appended. Aligned spans end exactly at an unmapped
    page; unaligned spans leave one padding byte. Zero count uses unmapped inputs.
    """
    require(0 < len(code) <= SIZE)
    require(0 <= count <= 32 and len(left) <= 32 and len(right) <= 32)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in (ENTRY & ~4095, r.STACK, r.RETURN):
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    inputs, pointers = [], []
    for page, values in ((LEFT, left), (RIGHT, right)):
        if count == 0:
            pointers.append(page)
            continue
        require(len(values) > 0)
        payload = struct.pack('<' + 'H' * len(values), *values)
        size = 4096
        u.mem_map(page, size)
        address = page + size - len(payload) - int(unaligned)
        u.mem_write(address, payload)
        pointers.append(address)
        inputs.append((page, bytes(u.mem_read(page, size))))
    stack = bytearray([0x5A] * 4096)
    struct.pack_into('<4I', stack, r.SP - r.STACK, r.RETURN, *pointers, count)
    u.mem_write(r.STACK, bytes(stack))
    initial = [(0x82345678 + salt * 0x1020304 + n * 0x112233) & r.NEG
               for n in range(8)]
    initial[7] = r.SP
    for reg, value in zip(r.REGS, initial):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    for _ in range(600):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        require(ENTRY <= ip < ENTRY + len(code))
        u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(u.reg_read(UC_X86_REG_EAX) == expected)
    require(u.reg_read(UC_X86_REG_ESP) == r.SP + 4)
    require(all(u.reg_read(r.REGS[n]) == initial[n] for n in (1, 4, 5, 6)))
    require(bytes(u.mem_read(r.SP, 16)) == bytes(stack[r.SP-r.STACK:r.SP-r.STACK+16]))
    for page, before in inputs:
        require(bytes(u.mem_read(page, len(before))) == before)


def vectors():
    yield (), (), 0
    values = (0, 1, 65, 97, 0x7FFF, 0x8000, 0xD800, 0xFFFF)
    for a in values:
        for b in values:
            yield (a,), (b,), 1
            yield (7, a), (7, b), 2
            yield (a, 2), (b, 3), 1
    # Early NUL, early mismatch, exact bound, and differing after the bound.
    yield (0,), (0,), 32
    yield (1,), (2,), 32
    yield (1, 0), (1, 0), 32
    yield (1, 2), (1, 2), 2
    rng = random.Random(84553)
    for _ in range(256):
        n = rng.randrange(1, 33)
        left = tuple(rng.randrange(1, 65536) for _ in range(n))
        right = list(left)
        if rng.randrange(2):
            right[rng.randrange(n)] = rng.randrange(65536)
        yield left, tuple(right), n


def compare_native(executable, cases):
    rows, expected = [], []
    for left, right, count, unaligned in cases:
        rows.append(' '.join(map(str, (count, len(left), len(right), int(unaligned),
                                       *left, *right))))
        expected.append(str(oracle(left, right, count)))
    result = subprocess.run([str(executable)], input='\n'.join(rows) + '\n',
                            text=True, capture_output=True, timeout=30)
    require(result.returncode == 0 and result.stderr == '')
    require(result.stdout.splitlines() == expected)


def probe(pe, native=None):
    code = pe.get_data(ENTRY_RVA, SIZE)
    require(len(code) == SIZE)
    counts = [0, 0, 0]
    cases = 0
    native_cases = []
    for left, right, count in vectors():
        expected = oracle(left, right, count)
        for unaligned in (False, True):
            exercise(code, left, right, count, expected, cases, unaligned)
            native_cases.append((left, right, count, unaligned))
            cases += 1
            counts[0 if expected == 0 else 1 if expected < 0x80000000 else 2] += 1
    if native is not None:
        compare_native(native, native_cases)
    return {'entryRva': hex(ENTRY_RVA), 'codeSize': SIZE, 'cases': cases,
            'equalPositiveNegativeCounts': counts,
            'nativeCompared': native is not None, 'arm64Executed': False,
            'windowsServicesExecuted': False, 'startupExecuted': False,
            'fullStackFlagsVolatileCompared': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', help='bounded native comparator probe executable')
    args = parser.parse_args([] if argv is None else argv)
    pe = None
    try:
        pe = r.load_image()
        result = probe(pe, args.native)
    except (OSError, ValueError, pefile.PEFormatError, UcError, struct.error,
            subprocess.TimeoutExpired):
        print('wide-compare-probe: unavailable/pin mismatch/bounded comparison failed',
              file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
