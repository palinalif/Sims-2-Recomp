#!/usr/bin/env python3
"""Pinned free-wrapper ABI, NOT a heap implementation or lifecycle adapter.

Reads only the existing pinned ignored image; emits counts/RVAs, never bytes.
The downstream dependency has authored responses and optional volatile clobbers.
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
import ptd_callback_probe as callback

RVA, SIZE = 0x831A54, 27
ENTRY, PROVIDER = r.BASE + RVA, r.BASE + 0x8461B8
require = r.require


def oracle(context, result, salt=0, *, clobber=False):
    require(isinstance(result, int) and 0 <= result <= r.NEG)
    regs, stack = callback.inputs(context, salt)
    struct.pack_into('<4I', stack, r.SP-r.STACK-16,
                     r.BASE+0x831A6C, context, 0, regs[6])
    events = [('provider', [context], 0x831A6C, r.SP-16, 0)]
    regs[0], regs[2], regs[7] = result, context, r.SP+4
    if clobber:
        regs[3] = 0xDEADBEEF
    return dict(registers=regs, stack=bytes(stack), events=events,
                flags=(0xC95 if clobber else 0xCD5))


def exercise(code, context, result, salt=0, *, pop=0, clobber=False):
    require(0 < len(code) <= SIZE and pop in (0, 4))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack = callback.inputs(context, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    # Context pages intentionally absent: this wrapper must not dereference them.
    pages = {ENTRY & ~4095, PROVIDER & ~4095, r.STACK, r.RETURN}
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
        if ip == PROVIDER:
            require(not events)
            sp = u.reg_read(r.REGS[7])
            ret, arg = struct.unpack('<II', u.mem_read(sp, 8))
            events.append(('provider', [arg], ret-r.BASE, sp, u.reg_read(r.REGS[0])))
            u.reg_write(r.REGS[0], result)
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
    require(all(bytes(u.mem_read(p, 4096)) == data for p, data in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events,
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCD5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    # Caller lists may exceed the query cap: they are not a completeness claim.
    require(not doc['truncation']['instructions'])
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 11 and sum(i.size for i in decoded) == SIZE)
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address-r.BASE)
        require(item['text'].split()[0].upper() == ins.mnemonic.upper())
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    cases = 0
    for context in (0, callback.STATIC, callback.STATIC-1, callback.STATIC+1,
                    1, 0x80000000, r.NEG):
        for result in (0, 1, 0x80000000, r.NEG):
            for salt in range(8):
                for clobber in (False, True):
                    r.verify(exercise(code, context, result, salt, clobber=clobber),
                             oracle(context, result, salt, clobber=clobber))
                    cases += 1
    # Wrong cleanup need not break the return: LEAVE repairs ESP, but POP reads
    # the zero local instead of the argument. Full state must still reject it.
    rejected = False
    try:
        r.verify(exercise(code, 1, 0, pop=4), oracle(1, 0))
    except (ValueError, UcError):
        rejected = True
    require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed,
                wrongProviderCalleePopRejected=rejected, heapExecuted=False,
                arm64Executed=False, startupExecuted=False)


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
        print('Pinned free-wrapper comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
