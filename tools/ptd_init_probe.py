#!/usr/bin/env python3
"""Pinned PTD initialization boundary; injected dependencies, NOT OS FLS/TLS.

Reads only the existing ignored image; prints numeric metadata/counts, no bytes.
Library names from Ghidra are hypotheses until dependency bodies are checked.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import pefile
import resolver_probe as r

RVA, SIZE = 0x828BE3, 51
ENTRY = r.BASE + RVA
ALLOC, SET, CLEAN = (r.BASE + n for n in (0x82A2FD, 0x82A3AE, 0x828C16))
CALLBACK, VALUE = r.BASE + 0x828AF0, r.BASE + 0x10DFB58
SLOT = r.BASE + 0x104F5A0
PAGE = SLOT & ~4095
require = r.require


def inputs(salt):
    require(isinstance(salt, int) and 0 <= salt < 8)
    regs = [(0x81234567 + salt * 0x1020304 + n * 0x112233) & r.NEG for n in range(8)]
    regs[7] = r.SP
    stack = bytearray([0x5A] * 4096)
    struct.pack_into('<III', stack, r.SP - r.STACK, r.RETURN, 0x87654321, 0xFEDCBA98)
    return regs, stack, bytearray([0x96] * 4096)


def oracle(index, result, cleanup, salt=0):
    require(all(isinstance(v, int) and 0 <= v <= r.NEG for v in (index, result, cleanup)))
    regs, stack, data = inputs(salt)
    struct.pack_into('<II', stack, r.SP - r.STACK - 8, r.BASE + 0x828BED, CALLBACK)
    struct.pack_into('<I', data, SLOT - PAGE, index)
    events = [('alloc', [CALLBACK], 0x828BED, r.SP - 8, 0x96969696)]
    regs[2] = CALLBACK
    flags = 0x444  # XOR AL,AL; defined flags and DF, excluding AF
    if index == r.NEG:
        regs[0] = index & 0xFFFFFF00
    else:
        struct.pack_into('<III', stack, r.SP - r.STACK - 12,
                         r.BASE + 0x828C06, index, VALUE)
        events.append(('set', [index, VALUE], 0x828C06, r.SP - 12, index))
        regs[2] = VALUE
        if result:
            regs[0] = (result & 0xFFFFFF00) | 1
            flags = 0x400 | (0x80 if result & 0x80000000 else 0)
            flags |= 4 if (result & 255).bit_count() % 2 == 0 else 0
        else:
            events.append(('cleanup', [], 0x828C11, r.SP - 4, index))
            struct.pack_into('<I', stack, r.SP - r.STACK - 4, r.BASE + 0x828C11)
            regs[0] = cleanup & 0xFFFFFF00
    regs[7] += 4
    return dict(registers=regs, stack=bytes(stack), data=bytes(data), events=events, flags=flags)


def exercise(code, index, result, cleanup, salt=0, *, pop=0):
    require(0 < len(code) <= SIZE and pop in (0, 4))
    regs, stack, data = inputs(salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for page in {ENTRY & ~4095, ALLOC & ~4095, PAGE, r.STACK, r.RETURN}:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack)); u.mem_write(PAGE, bytes(data))
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(100):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (ALLOC, SET, CLEAN):
            require(len(events) < 3)
            kind, count, response = {ALLOC: ('alloc', 1, index), SET: ('set', 2, result),
                                      CLEAN: ('cleanup', 0, cleanup)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<' + 'I' * (count + 1), u.mem_read(sp, 4 * (count + 1)))
            published, = struct.unpack('<I', u.mem_read(SLOT, 4))
            events.append((kind, args, ret - r.BASE, sp, published))
            u.reg_write(r.REGS[0], response)
            u.reg_write(r.REGS[7], sp + 4 + (pop if count else 0))
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY + len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    return dict(registers=[u.reg_read(reg) for reg in r.REGS], events=events,
                stack=bytes(u.mem_read(r.STACK, 4096)), data=bytes(u.mem_read(PAGE, 4096)),
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions', 'references', 'callers', 'callees')))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 19 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JNZ': 'JNE', 'JZ': 'JE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address - r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    cases = 0
    for index in (0, 1, 0x80000000, r.NEG):
        for result in (0, 1, 0x80000000, 0xFFFFFF00):
            for salt in range(8):
                cleanup = (0x98765432 + salt * 0x10101) & r.NEG
                r.verify(exercise(code, index, result, cleanup, salt), oracle(index, result, cleanup, salt))
                cases += 1
    rejected = False
    try:
        r.verify(exercise(code, 0, 1, 0, pop=4), oracle(0, 1, 0))
    except (ValueError, UcError):
        rejected = True
    require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongCalleePopRejected=rejected,
                windowsServiceExecuted=False, arm64Executed=False, startupExecuted=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path)
    args = parser.parse_args(argv)
    pe = None
    try:
        doc = None
        if args.index is not None:
            require(args.index.stat().st_size <= 1024 * 1024)
            doc = json.loads(args.index.read_text())
        pe = r.load_image()
        print(json.dumps(probe(pe, doc), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, pefile.PEFormatError):
        print('Pinned PTD comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
