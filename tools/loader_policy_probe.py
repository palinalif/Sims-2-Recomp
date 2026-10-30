#!/usr/bin/env python3
"""Development-only comparison of one pinned resolver dependency.

Authored API/comparator responses, not Windows services. No strings, image bytes,
raw states or disassembly are emitted. No original-code fixture is distributed.
"""
import argparse
import itertools
import json
import struct
import subprocess
import sys

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

import resolver_probe as resolver

ENTRY_RVA, SIZE = 0x82A2B2, 75
ENTRY = resolver.BASE + ENTRY_RVA
COMPARE = resolver.BASE + 0x845B53
PREFIX = resolver.BASE + 0xE06E20
IAT = resolver.BASE + 0xD9A000
LOAD_SLOT, ERROR_SLOT = IAT + 0x2D4, IAT + 0x118
LOAD, ERROR = resolver.TRAPS, resolver.TRAPS + 16
require = resolver.require


def oracle(first, error, comparison, retry):
    """Independent policy: retry only error87 and nonzero prefix comparison."""
    require(all(isinstance(v, int) and 0 <= v <= resolver.NEG
                for v in (first, error, comparison, retry)))
    events = [('load', [resolver.NAME, 0, 0x800], 0x82A2C5, resolver.SP - 20)]
    value = first
    if not first:
        events.append(('error', [], 0x82A2CF, resolver.SP - 8))
        if error == 87:
            events.append(('compare', [resolver.NAME, PREFIX, 7],
                           0x82A2E3, resolver.SP - 20))
            if comparison:
                events.append(('load', [resolver.NAME, 0, 0],
                               0x82A2F7, resolver.SP - 20))
                value = retry
    return {'events': events, 'eax': value, 'esp': resolver.SP + 4}


def exercise(code, responses, expected, salt=0, *, comparator=None, operands=None):
    """Single-step bounded body; intercept only explicitly declared dependencies."""
    require(len(responses) == 4 and 0 < len(code) <= SIZE)
    first, error, comparison, retry = responses
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in (ENTRY & ~4095, resolver.STACK, resolver.RETURN, IAT,
                 resolver.TRAPS, COMPARE & ~4095):
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    inputs = []
    if comparator is not None:
        require(0 < len(comparator) <= 58 and operands is not None and len(operands) == 2)
        u.mem_write(COMPARE, comparator)
        for address, values in zip((resolver.NAME, PREFIX), operands):
            require(len(values) <= 16)
            if not values:
                continue  # unmapped: bypass paths must not touch operands
            require(all(isinstance(v, int) and 0 <= v <= 65535 for v in values))
            page = address & ~4095
            u.mem_map(page, 4096)
            u.mem_write(address, struct.pack('<' + 'H' * len(values), *values))
            inputs.append((page, bytes(u.mem_read(page, 4096))))
    iat = bytearray([0x96] * 4096)
    struct.pack_into('<I', iat, LOAD_SLOT - IAT, LOAD)
    struct.pack_into('<I', iat, ERROR_SLOT - IAT, ERROR)
    u.mem_write(IAT, bytes(iat))
    stack = bytearray([0x5A] * 4096)
    struct.pack_into('<II', stack, resolver.SP - resolver.STACK,
                     resolver.RETURN, resolver.NAME)
    u.mem_write(resolver.STACK, bytes(stack))
    initial = [(0x12345678 + salt * 0x1020304 + n * 0x112233) & resolver.NEG
               for n in range(8)]
    initial[7] = resolver.SP
    for reg, value in zip(resolver.REGS, initial):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events, loads = [], 0
    for _ in range(700 if comparator is not None else 100):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == resolver.RETURN:
            break
        if ip == COMPARE and comparator is not None:
            sp = u.reg_read(UC_X86_REG_ESP)
            ret, *args = struct.unpack('<4I', u.mem_read(sp, 16))
            events.append(('compare', args, ret - resolver.BASE, sp))
        if ip in (LOAD, ERROR) or (ip == COMPARE and comparator is None):
            kind, count, cleanup = {LOAD: ('load', 3, 12),
                                    ERROR: ('error', 0, 0),
                                    COMPARE: ('compare', 3, 0)}[ip]
            sp = u.reg_read(UC_X86_REG_ESP)
            words = struct.unpack('<' + 'I' * (count + 1),
                                  u.mem_read(sp, 4 * (count + 1)))
            ret, *args = words
            events.append((kind, args, ret - resolver.BASE, sp))
            if kind == 'load':
                require(loads < 2)
                value = first if loads == 0 else retry
                loads += 1
            else:
                value = error if kind == 'error' else comparison
            u.reg_write(UC_X86_REG_EAX, value)
            u.reg_write(UC_X86_REG_EIP, ret)
            u.reg_write(UC_X86_REG_ESP, sp + 4 + cleanup)
        else:
            require(ENTRY <= ip < ENTRY + len(code) or
                    (comparator is not None and COMPARE <= ip < COMPARE + len(comparator)))
            u.emu_start(ip, resolver.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    resolver.verify({'events': events, 'eax': u.reg_read(UC_X86_REG_EAX),
                     'esp': u.reg_read(UC_X86_REG_ESP)}, expected)
    require(all(u.reg_read(resolver.REGS[n]) == initial[n] for n in (1, 4, 5, 6)))
    require(bytes(u.mem_read(IAT, 4096)) == bytes(iat))
    for page, before in inputs:
        require(bytes(u.mem_read(page, 4096)) == before)
    # The caller's return word and argument are not scratch space.
    require(bytes(u.mem_read(resolver.SP, 8)) ==
            bytes(stack[resolver.SP - resolver.STACK:resolver.SP - resolver.STACK + 8]))


def compare_native(binary, vectors):
    """Compare the portable policy's result and ordered dependency arguments.

    Native code has no x86 stack/register/flags contract; those remain checked
    only on the x86 side. Fail on missing, extra, malformed or changed records.
    """
    request = ''.join(' '.join(str(v) for v in (resolver.NAME, *values)) + '\n'
                      for values in vectors)
    run = subprocess.run([str(binary)], input=request, text=True,
                         capture_output=True, timeout=30, check=False)
    require(run.returncode == 0 and not run.stderr)
    lines = run.stdout.splitlines()
    require(len(lines) == len(vectors))
    for line, values in zip(lines, vectors):
        expected = oracle(*values)
        words = [expected['eax'], len(expected['events'])]
        for kind, args, _, _ in expected['events']:
            words.extend([{'load': 1, 'error': 2, 'compare': 3}[kind],
                          *(args if args else [0, 0, 0])])
        require([int(word) for word in line.split()] == words)


def probe(pe, native=None):
    code = pe.get_data(ENTRY_RVA, SIZE)
    require(len(code) == SIZE)
    counts = [0, 0, 0, 0]
    vectors = []
    for first, error, comparison, retry, salt in itertools.product(
            (0, 1, 0x80000000, 0xFFFFFFFE), (0, 5, 87, 0xFFFFFFFF),
            (0, 1, 0xFFFFFFFF), (0, 1, 0x80000000, 0xFFFFFFFE), range(2)):
        expected = oracle(first, error, comparison, retry)
        exercise(code, (first, error, comparison, retry), expected, salt)
        path = 0 if first else 1 if error != 87 else 2 if not comparison else 3
        counts[path] += 1
        vectors.append((first, error, comparison, retry))
    if native is not None:
        compare_native(native, vectors)
    return {'entryRva': hex(ENTRY_RVA), 'codeSize': SIZE, 'cases': sum(counts),
            'pathCounts': counts, 'windowsServicesExecuted': False,
            'originalComparatorExecuted': False,
            'nativePolicyCasesCompared': len(vectors) if native is not None else 0,
            'arm64Executed': False,
            'startupExecuted': False, 'fullStackFlagsVolatileCompared': False}


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', help='Host ts2_guest_loader_policy_probe executable')
    args = parser.parse_args(argv)
    pe = None
    try:
        pe = resolver.load_image()
        result = probe(pe, args.native)
    except (OSError, ValueError, pefile.PEFormatError, UcError, struct.error,
            subprocess.SubprocessError):
        print('loader-policy-probe: unavailable/pin mismatch/bounded comparison failed',
              file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
