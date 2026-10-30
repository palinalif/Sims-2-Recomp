#!/usr/bin/env python3
"""Bounded pinned x86 cleanup-boundary check, not a Windows lock service.

Only the existing ignored hash-pinned image is accepted. Output is numeric
metadata/counts, never original bytes, disassembly, strings or raw state.
The import response and optional counter interference are authored test inputs.
"""
import argparse
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import sys

import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS

import resolver_probe as r

RVA, SIZE = 0x82A1E3, 47
ENTRY = r.BASE + RVA
COUNTER, OBJECT = r.BASE + 0x10DFC28, r.BASE + 0x10DFC10
IAT, SLOT, PROVIDER = r.BASE + 0xD9A000, r.BASE + 0xD9A160, r.TRAPS
require = r.require


def inputs(count, salt):
    require(isinstance(count, int) and 0 <= count <= 8)
    require(isinstance(salt, int) and 0 <= salt < 16)
    registers = [(0x81234567 + salt * 0x1020304 + n * 0x112233) & r.NEG
                 for n in range(8)]
    registers[7] = r.SP
    stack = bytearray([0x5A] * 4096)
    struct.pack_into('<III', stack, r.SP - r.STACK, r.RETURN, 0x87654321, 0xFEDCBA98)
    data = bytearray([0x96] * 4096)
    struct.pack_into('<I', data, COUNTER - r.GLOBAL, count)
    return registers, stack, data


def oracle(count, salt, interference=False):
    """Value/stack model: reverse stride24; decrement AFTER provider returns.

    Loop length derives from the entry count, NOT a re-read of the shared word.
    Interference writes a synthetic value inside each provider invocation.
    """
    registers, stack, data = inputs(count, salt)
    initial = list(registers)
    struct.pack_into('<I', stack, r.SP - r.STACK - 4, initial[4])
    events = []
    shared = count
    if count:
        struct.pack_into('<I', stack, r.SP - r.STACK - 8, initial[5])
        for index in range(count):
            address = (OBJECT + 24 * (count - index - 1)) & r.NEG
            events.append((address, shared, 0x82A1FF, r.SP - 16))
            struct.pack_into('<II', stack, r.SP - r.STACK - 16,
                             r.BASE + 0x82A1FF, address)
            shared = ((0x80000000 + index) if interference else shared) - 1
            shared &= r.NEG
        registers[0] = (response(count - 1, salt) & 0xFFFFFF00) | 1
    else:
        registers[0] = (registers[0] & 0xFFFFFF00) | 1
    struct.pack_into('<I', data, COUNTER - r.GLOBAL, shared)
    registers[7] += 4
    return {'registers': registers, 'events': events, 'stack': bytes(stack),
            'data': bytes(data), 'flags': 0x444}


def response(index, salt):
    return (0x98765432 + salt * 0x1000100 + index * 0x10101) & r.NEG


def exercise(code, count, salt=0, interference=False, *, cleanup=4):
    """Single-step only declared body/trap; full stack/data/IAT snapshots.

    Provider preserves registers except EAX, uses authored stdcall pop4 and may
    change the counter. This is a test assumption, not actual callee execution.
    """
    require(0 < len(code) <= SIZE and cleanup in (0, 4))
    registers, stack, data = inputs(count, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in (ENTRY & ~4095, r.STACK, r.RETURN, r.GLOBAL, IAT, PROVIDER):
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    u.mem_write(r.GLOBAL, bytes(data))
    iat = bytearray([0xA6] * 4096)
    struct.pack_into('<I', iat, SLOT - IAT, PROVIDER)
    u.mem_write(IAT, bytes(iat))
    for reg, value in zip(r.REGS, registers):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)  # varied status bits, DF set
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(250):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip == PROVIDER:
            require(len(events) < 8)
            sp = u.reg_read(r.REGS[7])
            ret, argument = struct.unpack('<II', u.mem_read(sp, 8))
            shared, = struct.unpack('<I', u.mem_read(COUNTER, 4))
            index = len(events)
            events.append((argument, shared, ret - r.BASE, sp))
            if interference:
                u.mem_write(COUNTER, struct.pack('<I', 0x80000000 + index))
            u.reg_write(r.REGS[0], response(index, salt))
            u.reg_write(r.REGS[7], sp + 4 + cleanup)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY + len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(bytes(u.mem_read(IAT, 4096)) == bytes(iat))
    return {'registers': [u.reg_read(reg) for reg in r.REGS], 'events': events,
            'stack': bytes(u.mem_read(r.STACK, 4096)),
            'data': bytes(u.mem_read(r.GLOBAL, 4096)),
            # TEST leaves AF undefined; use same defined mask on both paths.
            'flags': u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5}


def compare_index(code, document):
    """Compare bounded indexed boundaries/mnemonics, not decompiler semantics."""
    require(document['program']['executableSha256'].lower() == r.PIN)
    require(int(document['program']['imageBaseVa'], 16) == r.BASE)
    require(int(document['function']['entryRva'], 16) == RVA)
    require(not any(document['truncation'][key]
                    for key in ('instructions', 'references', 'callers', 'callees')))
    items = document['function']['disassembly']['items']
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(len(items) == len(decoded) == 17)
    require(sum(i.size for i in decoded) == SIZE)
    for item, instruction in zip(items, decoded):
        require(int(item['rva'], 16) == instruction.address - r.BASE)
        # Ghidra uses JZ/JNZ aliases for Capstone's JE/JNE.
        normalize = lambda s: {'JZ': 'JE', 'JNZ': 'JNE'}.get(s.upper(), s.upper())
        require(normalize(item['text'].split()[0]) == normalize(instruction.mnemonic))
    return len(items)


def probe(pe, index=None):
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    matches = [(dll.dll, imp.name) for dll in pe.DIRECTORY_ENTRY_IMPORT
               for imp in dll.imports if imp.address == SLOT]
    require(matches == [(b'KERNEL32.dll', b'DeleteCriticalSection')])
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, index) if index is not None else 0
    cases = 0
    for count in (0, 1, 2, 3, 8):
        for salt in range(8):
            for interference in (False, True):
                r.verify(exercise(code, count, salt, interference),
                         oracle(count, salt, interference))
                cases += 1
    # A cdecl/no-pop dependency must not silently satisfy this boundary.
    rejected = False
    try:
        r.verify(exercise(code, 1, cleanup=0), oracle(1, 0))
    except (ValueError, UcError):
        rejected = True
    require(rejected)
    return {'entryRva': hex(RVA), 'codeSize': SIZE, 'cases': cases,
            'wrongCleanupRejected': rejected, 'counterInterferenceCases': cases // 2,
            'indexedBoundariesMnemonicsCompared': indexed,
            'windowsServiceExecuted': False, 'arm64Executed': False,
            'startupExecuted': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, help='Existing private Ghidra query JSON')
    args = parser.parse_args(argv)
    pe = None
    try:
        index = None
        if args.index is not None:
            require(args.index.stat().st_size <= 1024 * 1024)
            index = json.loads(args.index.read_text())
        pe = r.load_image()
        print(json.dumps(probe(pe, index), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, pefile.PEFormatError):
        print('Pinned cleanup comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
