#!/usr/bin/env python3
"""Pinned error-slot accessor ABI; injected PTD provider, NOT thread storage.

Only the existing ignored pinned image is read. Output is counts/RVAs, not bytes.
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

RVA, SIZE = 0x831B17, 19
ENTRY, PROVIDER, FALLBACK = (r.BASE+n for n in (RVA, 0x84601E, 0x104F750))
require = r.require


def add_flags(left, right):
    value = (left+right) & r.NEG
    return (0x400 | int(left+right > r.NEG)
            | (4 if (value & 255).bit_count() % 2 == 0 else 0)
            | (0x10 if (left ^ right ^ value) & 16 else 0)
            | (0x40 if value == 0 else 0) | (0x80 if value & 0x80000000 else 0)
            | (0x800 if ~(left ^ right) & (left ^ value) & 0x80000000 else 0))


def oracle(pointer, salt=0, *, clobber=False):
    require(isinstance(pointer, int) and 0 <= pointer <= r.NEG)
    regs, stack, _ = init.inputs(salt)
    struct.pack_into('<I', stack, r.SP-r.STACK-4, r.BASE+0x831B1C)
    regs[0] = (pointer+16) & r.NEG if pointer else FALLBACK
    regs[7] = r.SP+4
    if clobber:
        regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]
    return dict(registers=regs, stack=bytes(stack),
                flags=add_flags(pointer, 16) if pointer else 0x444,
                events=[('provider', [], 0x831B1C, r.SP-4)])


def exercise(code, pointer, salt=0, *, clobber=False, pop=0):
    require(isinstance(pointer, int) and 0 <= pointer <= r.NEG)
    require(0 < len(code) <= SIZE and pop in (0, 4))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack, _ = init.inputs(salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    # PTD and fallback intentionally unmapped: accessor returns addresses only.
    pages = {ENTRY & ~4095, PROVIDER & ~4095, r.STACK, r.RETURN}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(40):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip == PROVIDER:
            require(not events)
            sp = u.reg_read(r.REGS[7])
            ret = struct.unpack('<I', u.mem_read(sp, 4))[0]
            events.append(('provider', [], ret-r.BASE, sp))
            u.reg_write(r.REGS[0], pointer)
            if clobber:
                u.reg_write(r.REGS[2], 0xFEEDFACE)
                u.reg_write(r.REGS[3], 0xDEADBEEF)
                u.reg_write(UC_X86_REG_EFLAGS, 0xC97)
            u.reg_write(r.REGS[7], sp+4+pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY+len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == before for p, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events,
                flags=u.reg_read(UC_X86_REG_EFLAGS) & (0xCD5 if pointer else 0xCC5))


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not doc['truncation']['instructions'])
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 7 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JNZ': 'JNE', 'JZ': 'JE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address-r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    cases = 0
    pointers = (0, 1, 15, 16, 0x7FFFFFEF, 0x7FFFFFF0, 0x80000000,
                0xFFFFFFEF, 0xFFFFFFF0, r.NEG)
    for pointer in pointers:
        for salt in range(8):
            for clobber in (False, True):
                r.verify(exercise(code, pointer, salt, clobber=clobber),
                         oracle(pointer, salt, clobber=clobber))
                cases += 1
    rejected = False
    try:
        r.verify(exercise(code, 1, pop=4), oracle(1))
    except (ValueError, UcError):
        rejected = True
    require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed,
                wrongProviderCalleePopRejected=rejected, actualPtdProviderExecuted=False,
                threadStorageImplemented=False, arm64Executed=False, startupExecuted=False)


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
        print('Pinned error-slot comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
