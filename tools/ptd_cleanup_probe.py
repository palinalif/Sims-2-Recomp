#!/usr/bin/env python3
"""Pinned PTD cleanup boundary; injected free dependency, NOT an OS service.

Reads only the existing ignored image; emits counts/metadata, never image bytes.
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
import ptd_init_probe as init

RVA, SIZE = 0x828C16, 27
ENTRY, FREE = r.BASE + RVA, r.BASE + 0x82A338
SLOT, PAGE = init.SLOT, init.PAGE
require = r.require


def inputs(index, salt):
    require(isinstance(index, int) and 0 <= index <= r.NEG)
    regs, stack, data = init.inputs(salt)
    struct.pack_into('<I', data, SLOT - PAGE, index)
    return regs, stack, data


def oracle(index, result, salt=0):
    require(isinstance(result, int) and 0 <= result <= r.NEG)
    regs, stack, data = inputs(index, salt)
    events = []
    flags = 0x444
    if index != r.NEG:
        struct.pack_into('<II', stack, r.SP - r.STACK - 8, r.BASE + 0x828C26, index)
        events.append(('free', [index], 0x828C26, r.SP - 8, index))
        struct.pack_into('<I', data, SLOT - PAGE, r.NEG)
        regs[0], regs[2] = (result & 0xFFFFFF00) | 1, index
        flags = 0x484
    else:
        regs[0] = 0xFFFFFF01
    regs[7] += 4
    return dict(registers=regs, stack=bytes(stack), data=bytes(data), events=events, flags=flags)


def exercise(code, index, result, salt=0, *, pop=0, interference=None):
    require(0 < len(code) <= SIZE and pop in (0, 4))
    require(interference is None or isinstance(interference, int) and 0 <= interference <= r.NEG)
    regs, stack, data = inputs(index, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, FREE & ~4095, PAGE, r.STACK, r.RETURN}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack)); u.mem_write(PAGE, bytes(data))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p not in (PAGE, r.STACK)}
    for reg, word in zip(r.REGS, regs):
        u.reg_write(reg, word)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(100):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip == FREE:
            require(not events)
            sp = u.reg_read(r.REGS[7])
            ret, arg = struct.unpack('<II', u.mem_read(sp, 8))
            published, = struct.unpack('<I', u.mem_read(SLOT, 4))
            events.append(('free', [arg], ret - r.BASE, sp, published))
            if interference is not None:
                u.mem_write(SLOT, struct.pack('<I', interference))
            u.reg_write(r.REGS[0], result)
            u.reg_write(r.REGS[7], sp + 4 + pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY + len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == value for p, value in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), data=bytes(u.mem_read(PAGE, 4096)),
                events=events, flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions', 'references', 'callers', 'callees')))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 9 and sum(i.size for i in decoded) == SIZE)
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
    for index in (0, 1, 0x80000000, r.NEG):
        for result in (0, 1, 0x80000000, r.NEG):
            for salt in range(8):
                for interference in (None, 0, 0xFEDCBA98):
                    r.verify(exercise(code, index, result, salt, interference=interference),
                             oracle(index, result, salt))
                    cases += 1
    rejected = False
    try:
        r.verify(exercise(code, 0, 0, pop=4), oracle(0, 0))
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
        print('Pinned cleanup comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
