#!/usr/bin/env python3
"""Pinned PTD destruction callback ABI; injected free, NOT an allocator or FLS.

Only the existing pinned ignored image is read. Output is counts/RVAs, not bytes.
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

RVA, SIZE = 0x828AF0, 28
ENTRY, FREE, STATIC = (r.BASE + n for n in (RVA, 0x831A54, 0x10DFB58))
require = r.require


def inputs(context, salt):
    require(isinstance(context, int) and 0 <= context <= r.NEG)
    regs, stack, _ = init.inputs(salt)
    struct.pack_into('<I', stack, r.SP - r.STACK + 4, context)
    return regs, stack


def cmp_flags(left, right):
    value = (left - right) & r.NEG
    return (0x400 | int(left < right) | (4 if (value & 255).bit_count() % 2 == 0 else 0)
            | (0x10 if (left ^ right ^ value) & 16 else 0)
            | (0x40 if value == 0 else 0) | (0x80 if value & 0x80000000 else 0)
            | (0x800 if (left ^ right) & (left ^ value) & 0x80000000 else 0))


def oracle(context, result, salt=0, *, clobber=False):
    require(isinstance(result, int) and 0 <= result <= r.NEG)
    regs, stack = inputs(context, salt)
    struct.pack_into('<I', stack, r.SP - r.STACK - 4, regs[6])
    events = []
    flags = cmp_flags(context, STATIC) if context else 0x444
    mask = 0xCD5 if context else 0xCC5  # TEST AF undefined; CMP AF defined.
    regs[0] = context
    if context not in (0, STATIC):
        struct.pack_into('<II', stack, r.SP - r.STACK - 12, r.BASE + 0x828B07, context)
        events = [('free', [context], 0x828B07, r.SP - 12)]
        regs[0], regs[2] = result, context  # caller POP overwrites provider ECX
        if clobber:
            regs[3], flags = 0xDEADBEEF, 0xC95
    regs[7] += 8  # callback itself is callee-pop4
    return dict(registers=regs, stack=bytes(stack), flags=flags & mask, events=events)


def exercise(code, context, result, salt=0, *, pop=0, clobber=False):
    require(0 < len(code) <= SIZE and pop in (0, 4))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(ins.size for ins in decoded) == len(code))
    regs, stack = inputs(context, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    # Context and static PTD pages intentionally NOT mapped: body must not read them.
    pages = {ENTRY & ~4095, FREE & ~4095, r.STACK, r.RETURN}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, word in zip(r.REGS, regs):
        u.reg_write(reg, word)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(80):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip == FREE:
            require(not events)
            sp = u.reg_read(r.REGS[7])
            ret, arg = struct.unpack('<II', u.mem_read(sp, 8))
            events.append(('free', [arg], ret - r.BASE, sp))
            u.reg_write(r.REGS[0], result)
            if clobber:
                u.reg_write(r.REGS[2], 0xFEEDFACE)
                u.reg_write(r.REGS[3], 0xDEADBEEF)
                u.reg_write(UC_X86_REG_EFLAGS, 0xC97)
            u.reg_write(r.REGS[7], sp + 4 + pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY + len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == data for p, data in immutable.items()))
    mask = 0xCD5 if context else 0xCC5
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events,
                flags=u.reg_read(UC_X86_REG_EFLAGS) & mask)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions', 'references', 'callers', 'callees')))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 12 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JZ': 'JE', 'JNZ': 'JNE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address - r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    cases = 0
    for context in (0, STATIC, STATIC - 1, STATIC + 1, 1, 0x80000000, r.NEG):
        for result in (0, 1, 0x80000000, r.NEG):
            for salt in range(8):
                for clobber in (False, True):
                    r.verify(exercise(code, context, result, salt, clobber=clobber),
                             oracle(context, result, salt, clobber=clobber))
                    cases += 1
    rejected = False
    try:
        r.verify(exercise(code, 1, 0, pop=4), oracle(1, 0))
    except (ValueError, UcError):
        rejected = True
    require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongFreeCalleePopRejected=rejected,
                allocatorExecuted=False, flsLifecycleExecuted=False,
                arm64Executed=False, startupExecuted=False)


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
        print('Pinned callback comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
