#!/usr/bin/env python3
"""Bounded development-only x86 resolver comparison; no game/Windows execution.

Reads only the pinned ignored analysis image. Outputs counts/RVAs, never bytes,
strings, pointers, raw states or disassembly. Providers are authored responses,
NOT LoadLibrary/GetProcAddress implementations. No races/FreeLibrary path tested.
"""
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
    UC_X86_REG_ESP, UC_X86_REG_EIP, UC_X86_REG_EFLAGS)

ROOT = Path(__file__).resolve().parents[1]
IMAGE = ROOT / 'work/interop-legacy-002/analysis-image.bin'
PIN = '63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985'
BASE = 0xA0000000
ENTRY, END, HELPER = BASE + 0x82A212, BASE + 0x82A2B2, BASE + 0x82A2B2
GLOBAL = BASE + 0x10DF000
MODULES, CACHE = BASE + 0x10DFC68, BASE + 0x10DFC84
STACK, RETURN, ARRAY, TRAPS = 0xB8000000, 0xBA000000, 0xC2345000, 0xC7000000
SP, NAME = STACK + 0x800, 0xC1234567
NEG, H1, H2 = 0xFFFFFFFF, 0xC8001111, 0xC8002222
REGS = (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP)


def require(condition):
    if not condition:
        raise ValueError('comparison or bounded execution failed')


def oracle(modules, loads, export, names):
    """Independent value-level model: first usable module stops search."""
    require(len(modules) == len(loads) == len(names) == 2)
    require(all(0 <= v <= NEG for v in (*modules, *loads, export, *names)))
    updated = list(modules)
    events, selected = [], None
    for index, module in enumerate(modules):
        if module == NEG:
            continue
        if module == 0:
            events.append(('load', [names[index]], 0x82A263, SP - 32))
            module = loads[index]
            updated[index] = module or NEG
        if module:
            selected = index
            events.append(('export', [module, NAME], 0x82A2A5, SP - 36))
            break
    value = export if selected is not None else 0
    return {'events': events, 'eax': value, 'cache': value or NEG,
            'modules': updated, 'esp': SP + 4}, selected


def verify(observed, expected):
    require(observed == expected)


def load_image():
    # No CLI override: original code is accepted only from this pinned private input.
    with IMAGE.open('rb') as source:
        data = source.read(256 * 1024 * 1024 + 1)
    require(hashlib.sha256(data).hexdigest() == PIN)
    pe = pefile.PE(data=data, fast_load=True)
    require(pe.OPTIONAL_HEADER.Magic == 0x10B)
    require(pe.OPTIONAL_HEADER.ImageBase == BASE)
    return pe


def exercise(code, table, modules, loads, export, salt, expected, *, composition=None):
    """Single-step with explicit call boundaries; hooks are deliberately unused."""
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in (STACK, RETURN, GLOBAL, ENTRY & ~4095, BASE + 0xD9A000,
                 ARRAY, BASE + 0xE06000, TRAPS):
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(BASE + 0xE06000, table)
    inputs = []
    if composition is not None:
        helper, comparator, operands, responses = composition
        require(0 < len(helper) <= 75 and 0 < len(comparator) <= 58)
        u.mem_write(HELPER, helper)
        u.mem_map(BASE + 0x845000, 4096)
        u.mem_write(BASE + 0x845B53, comparator)
        u.mem_map(NAME & ~4095, 4096)
        for address, values in zip((NAME, NAME + 128, BASE + 0xE06E20), operands):
            require(0 < len(values) <= 16 and all(0 <= v <= 65535 for v in values))
            u.mem_write(address, struct.pack('<' + 'H' * len(values), *values))
        u.mem_write(BASE + 0xD9A2D4, struct.pack('<I', TRAPS + 32))
        u.mem_write(BASE + 0xD9A118, struct.pack('<I', TRAPS + 48))
        inputs.append((NAME & ~4095, bytes(u.mem_read(NAME & ~4095, 4096))))
        inputs.append((BASE + 0xE06000, bytes(u.mem_read(BASE + 0xE06000, 4096))))
    initial = [(0x12345678 + salt * 0x1020304 + n * 0x112233) & NEG
               for n in range(8)]
    initial[7] = SP
    page = bytearray([0x96] * 4096)
    struct.pack_into('<I', page, CACHE - GLOBAL, 0)
    for index, module in enumerate(modules, 1):
        struct.pack_into('<I', page, MODULES + 4 * index - GLOBAL, module)
    u.mem_write(GLOBAL, bytes(page))
    u.mem_write(ARRAY, struct.pack('<II', 1, 2))
    u.mem_write(BASE + 0xD9A120, struct.pack('<II', TRAPS, TRAPS + 16))
    iat_before = bytes(u.mem_read(BASE + 0xD9A000, 4096))
    stack = bytearray([0x5A] * 4096)
    struct.pack_into('<5I', stack, SP - STACK, RETURN, 4, NAME, ARRAY, ARRAY + 8)
    u.mem_write(STACK, bytes(stack))

    def reset():
        for reg, value in zip(REGS, initial):
            u.reg_write(reg, value)
        u.reg_write(UC_X86_REG_EFLAGS, 0x202 | ((salt & 1) << 10))
        u.reg_write(UC_X86_REG_EIP, ENTRY)

    def step(allow_calls):
        events = []
        load_index = 0
        active, attempts = None, 0
        for _ in range(2000 if composition is not None else 400):
            ip = u.reg_read(UC_X86_REG_EIP)
            if ip == RETURN:
                return events
            if composition is not None and ip == BASE + 0x845B53:
                require(allow_calls)
                sp = u.reg_read(UC_X86_REG_ESP)
                ret, *args = struct.unpack('<4I', u.mem_read(sp, 16))
                events.append(('compare', args, ret - BASE, sp))
            if composition is not None and ip in (TRAPS + 32, TRAPS + 48):
                require(allow_calls and active is not None)
                sp = u.reg_read(UC_X86_REG_ESP)
                count = 3 if ip == TRAPS + 32 else 0
                ret, *args = struct.unpack('<' + 'I' * (count + 1), u.mem_read(sp, 4 * (count + 1)))
                events.append(('api_load' if count else 'error', args, ret - BASE, sp))
                if count:
                    require(attempts < 2)
                    value = responses[active][0 if attempts == 0 else 2]
                    attempts += 1
                else:
                    value = responses[active][1]
                u.reg_write(UC_X86_REG_EAX, value)
                u.reg_write(UC_X86_REG_EIP, ret)
                u.reg_write(UC_X86_REG_ESP, sp + 4 + count * 4)
                continue
            if ip in (HELPER, TRAPS + 16):
                require(allow_calls)
                sp = u.reg_read(UC_X86_REG_ESP)
                ret = struct.unpack('<I', u.mem_read(sp, 4))[0]
                kind, count = ('load', 1) if ip == HELPER else ('export', 2)
                args = list(struct.unpack('<' + 'I' * count, u.mem_read(sp + 4, 4 * count)))
                events.append((kind, args, ret - BASE, sp))
                if kind == 'load':
                    # Response stream depends only on encountered zero slots.
                    zero_slots = [i for i, m in enumerate(modules) if m == 0]
                    require(load_index < len(zero_slots))
                    active = zero_slots[load_index]
                    result = loads[active]
                    load_index += 1
                    attempts = 0
                    if composition is not None:
                        u.emu_start(ip, RETURN, count=1)
                        continue
                else:
                    result = export
                u.reg_write(UC_X86_REG_EAX, result)
                u.reg_write(UC_X86_REG_EIP, ret)
                u.reg_write(UC_X86_REG_ESP, sp + 4 + (8 if kind == 'export' else 0))
            else:
                # Also rejects unmodelled FreeLibrary/race/other dependency paths.
                require(ENTRY <= ip < END or (composition is not None and
                        (HELPER <= ip < HELPER + len(helper) or
                         BASE + 0x845B53 <= ip < BASE + 0x845B53 + len(comparator))))
                u.emu_start(ip, RETURN, count=1)
        raise ValueError('instruction budget exceeded')

    def snapshot(events):
        return {'events': events, 'eax': u.reg_read(UC_X86_REG_EAX),
                'esp': u.reg_read(UC_X86_REG_ESP),
                'modules': list(struct.unpack('<II', u.mem_read(MODULES + 4, 8))),
                'cache': struct.unpack('<I', u.mem_read(CACHE, 4))[0]}

    reset()
    verify(snapshot(step(True)), expected)
    for index, module in enumerate(expected['modules'], 1):
        struct.pack_into('<I', page, MODULES + 4 * index - GLOBAL, module)
    struct.pack_into('<I', page, CACHE - GLOBAL, expected['cache'])

    def check_memory_registers():
        require(bytes(u.mem_read(GLOBAL, 4096)) == bytes(page))
        require(all(u.reg_read(REGS[n]) == initial[n] for n in (1, 4, 5, 6)))
        for address, before in inputs:
            require(bytes(u.mem_read(address, 4096)) == before)
        require(bytes(u.mem_read(SP, 20)) == bytes(stack[SP - STACK:SP - STACK + 20]))

    check_memory_registers()
    require(bytes(u.mem_read(BASE + 0xD9A000, 4096)) == iat_before)
    # Same-memory positive/negative cache reentry must bypass these dependencies.
    for address in (ARRAY, BASE + 0xE06000, BASE + 0xD9A000):
        u.mem_unmap(address, 4096)
    if composition is not None:
        u.mem_unmap(NAME & ~4095, 4096)
        inputs.clear()
    u.mem_write(SP, struct.pack('<5I', RETURN, 4, NAME, ARRAY, ARRAY + 8))
    reset()
    verify(snapshot(step(False)), {**expected, 'events': []})
    check_memory_registers()


def probe(pe):
    code = pe.get_data(0x82A212, 160)
    table = pe.get_data(0xE06000, 4096)
    require(len(code) == 160 and len(table) == 4096)
    names = struct.unpack_from('<II', table, 0xD8C)
    counts = [0, 0, 0]
    for m1, m2, l1, l2, export, salt in itertools.product(
            (0, NEG, H1), (0, NEG, H2), (0, H1), (0, H2),
            (0, 1, 0x80000000, 0xFFFFFFFE), range(2)):
        expected, selected = oracle((m1, m2), (l1, l2), export, names)
        exercise(code, table, (m1, m2), (l1, l2), export, salt, expected)
        counts[2 if selected is None else selected] += 1
    return {'entryRva': '0x82A212', 'codeSize': 160, 'cases': sum(counts),
            'sameMemoryReentries': sum(counts), 'pathCounts': counts,
            'originalHelperExecuted': False, 'nativeOrArm64Executed': False,
            'startupExecuted': False, 'raceOrFreeLibraryTested': False,
            'fullStackFlagsVolatileCompared': False}


def main():
    pe = None
    try:
        pe = load_image()
        result = probe(pe)
    except (OSError, ValueError, pefile.PEFormatError, UcError, struct.error):
        print('resolver-probe: unavailable/pin mismatch/bounded comparison failed', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
