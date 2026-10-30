#!/usr/bin/env python3
"""Pinned OS-error mapping comparison; development-only, no runtime binding.

Reads only the existing ignored pinned image. Emits counts/RVAs, never table
contents or original code. A shared input table is data, not a behavior oracle.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import resolver_probe as r
import ptd_init_probe as init

RVA, SIZE, COUNT = 0x831A7A, 67, 45
ENTRY, TABLE = r.BASE + RVA, r.BASE + 0xE073F0
require = r.require


def validate(error, table):
    require(isinstance(error, int) and 0 <= error <= r.NEG)
    require(len(table) == COUNT and all(len(pair) == 2 and
            all(isinstance(v, int) and 0 <= v <= r.NEG for v in pair) for pair in table))


def arithmetic_flags(left, right, *, subtract=False):
    raw = left-right if subtract else left+right
    value = raw & r.NEG
    overflow = ((left ^ right) if subtract else ~(left ^ right)) & (left ^ value)
    return (0x400 | int(raw < 0 if subtract else raw > r.NEG)
            | (4 if (value & 255).bit_count() % 2 == 0 else 0)
            | (0x10 if (left ^ right ^ value) & 16 else 0)
            | (0x40 if value == 0 else 0) | (0x80 if value & 0x80000000 else 0)
            | (0x800 if overflow & 0x80000000 else 0))


def oracle(error, table, salt=0):
    validate(error, table)
    regs, stack, _ = init.inputs(salt)
    struct.pack_into('<I', stack, r.SP-r.STACK+4, error)
    struct.pack_into('<I', stack, r.SP-r.STACK-4, regs[6])
    regs[2] = error
    for key, value in table:
        if key == error:
            flags = arithmetic_flags(error, key, subtract=True)
            break
    else:
        # Unsigned interval tests, after exact table lookup; not signed ranges.
        if 19 <= error <= 36:
            value = 13
            flags = arithmetic_flags(error-19, 17, subtract=True)
            struct.pack_into('<I', stack, r.SP-r.STACK-8, 13)
        else:
            value = 8 if 188 <= error <= 202 else 22
            regs[2] = 14
            flags = arithmetic_flags(value-8, 8)
            struct.pack_into('<I', stack, r.SP-r.STACK-8, 14)
    regs[0], regs[7] = value, r.SP+4
    return dict(registers=regs, stack=bytes(stack), flags=flags)


def exercise(code, error, table, salt=0):
    validate(error, table)
    require(0 < len(code) <= SIZE)
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack, _ = init.inputs(salt)
    struct.pack_into('<I', stack, r.SP-r.STACK+4, error)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, TABLE & ~4095, r.STACK, r.RETURN}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(TABLE, b''.join(struct.pack('<II', *pair) for pair in table))
    u.mem_write(r.STACK, bytes(stack))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    for _ in range(1000):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        require(ENTRY <= ip < ENTRY+len(code))
        u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == before for p, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)),
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCD5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not doc['truncation']['instructions'])
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 29 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JZ': 'JE', 'JC': 'JB'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address-r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    data = pe.get_data(TABLE-r.BASE, COUNT*8)
    require(len(data) == COUNT*8)
    table = list(struct.iter_unpack('<II', data))
    # All low codes, every table key and adjacent values, unsigned boundaries.
    errors = set(range(256)) | {0x7FFFFFFF, 0x80000000, r.NEG}
    for key, _ in table:
        errors.update(((key-1) & r.NEG, key, (key+1) & r.NEG))
    cases = 0
    for error in sorted(errors):
        for salt in range(2):
            r.verify(exercise(code, error, table, salt), oracle(error, table, salt))
            cases += 1
    # Authored table substitutions adjudicate first-match and interval priority
    # independently of the original table's coverage.
    for error in (0, 18, 19, 36, 37, 187, 188, 202, 203, r.NEG):
        for position in (None, 0, COUNT-1):
            fixture = [(0x12340000+n, n) for n in range(COUNT)]
            if position is not None:
                fixture[position] = (error, 0x80000000)
            r.verify(exercise(code, error, fixture), oracle(error, fixture))
            cases += 1
    duplicate = [(19, 0x80000000), (19, 1)] + [(10000+n, n) for n in range(COUNT-2)]
    r.verify(exercise(code, 19, duplicate), oracle(19, duplicate))
    return dict(entryRva=hex(RVA), codeSize=SIZE, tableRva=hex(TABLE-r.BASE),
                tableEntries=COUNT, cases=cases+1,
                indexedBoundariesMnemonicsCompared=indexed,
                runtimeBound=False, arm64Executed=False, startupExecuted=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path)
    args = parser.parse_args(argv)
    pe = None
    try:
        doc = None
        if args.index is not None:
            require(args.index.stat().st_size <= 1024*1024)
            doc = json.loads(args.index.read_text())
        pe = r.load_image()
        print(json.dumps(probe(pe, doc), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, pefile.PEFormatError):
        print('Pinned OS-error comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
