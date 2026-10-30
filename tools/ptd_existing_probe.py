#!/usr/bin/env python3
"""Pinned existing-slot provider path only; lazy allocation deliberately rejected.

Reads only the existing ignored pinned image. Emits RVAs/counts, never bytes.
The query and last-error APIs have authored contracts, not Windows services.
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

RVA, SIZE = 0x84601E, 177
ENTRY, QUERY = (r.BASE+n for n in (RVA, 0x8480BF))
INDEX = r.BASE+0x104F89C
GET_SLOT, SET_SLOT = (r.BASE+n for n in (0xD9A118, 0xD9A140))
GET, SET = r.TRAPS, r.TRAPS+16
require = r.require


def oracle(index, pointer, error, salt=0, *, clobber=False):
    require(0 <= index < r.NEG and 0 < pointer <= r.NEG and 0 <= error <= r.NEG)
    regs, stack, _ = init.inputs(salt)
    for offset, value in ((-4, regs[1]), (-8, regs[5]), (-12, error),
                          (-16, r.BASE+0x8460CA)):
        struct.pack_into('<I', stack, r.SP-r.STACK+offset, value)
    result = 0 if pointer == r.NEG else pointer
    regs[0], regs[7] = result, r.SP+4
    if clobber:
        regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]
    flags = 0x400 | (4 if (result & 255).bit_count() % 2 == 0 else 0)
    flags |= (0x40 if not result else 0) | (0x80 if result & 0x80000000 else 0)
    return dict(registers=regs, stack=bytes(stack), flags=flags,
                events=[('get', [], 0x846028, r.SP-12),
                        ('query', [index], 0x84603A, r.SP-16),
                        ('set', [error], 0x8460CA, r.SP-16)])


def exercise(code, index, pointer, error, salt=0, *, clobber=False, query_pop=4, set_pop=4):
    require(0 < len(code) <= SIZE and all(0 <= n <= r.NEG for n in (index, pointer, error)))
    require(query_pop in (0, 4) and set_pop in (0, 4))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack, _ = init.inputs(salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, QUERY & ~4095, INDEX & ~4095,
             GET_SLOT & ~4095, r.STACK, r.RETURN, r.TRAPS}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    for addr, value in ((INDEX, index), (GET_SLOT, GET), (SET_SLOT, SET)):
        u.mem_write(addr, struct.pack('<I', value))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(80):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (GET, QUERY, SET):
            require(len(events) < 3)
            kind, count, response, pop = {
                GET: ('get', 0, error, 0), QUERY: ('query', 1, pointer, query_pop),
                SET: ('set', 1, 0xBAADF00D, set_pop)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp))
            u.reg_write(r.REGS[0], response)
            if clobber:
                u.reg_write(r.REGS[2], 0xFEEDFACE)
                u.reg_write(r.REGS[3], 0xDEADBEEF)
            u.reg_write(r.REGS[7], sp+4+pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY+len(code))
            require(ip < r.BASE+0x846049 or ip >= r.BASE+0x8460C3)
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == before for p, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events,
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not doc['truncation']['instructions'])
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 67 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JNZ': 'JNE', 'JZ': 'JE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address-r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    names = {i.address: i.name for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    require(names[GET_SLOT] == b'GetLastError' and names[SET_SLOT] == b'SetLastError')
    cases = 0
    for index in (0, 1, 0x80000000, r.NEG-1):
        for pointer in (1, 0x80000000, r.NEG-1, r.NEG):
            for error in (0, 0x80000000, r.NEG):
                for salt in range(4):
                    for clobber in (False, True):
                        r.verify(exercise(code, index, pointer, error, salt, clobber=clobber),
                                 oracle(index, pointer, error, salt, clobber=clobber))
                        cases += 1
    for index, pointer in ((r.NEG, 1), (0, 0)):
        rejected = False
        try:
            exercise(code, index, pointer, 0)
        except ValueError:
            rejected = True
        require(rejected)
    for options in ({'query_pop': 0}, {'set_pop': 0}):
        rejected = False
        try:
            r.verify(exercise(code, 0, 1, 0, **options), oracle(0, 1, 0))
        except (ValueError, UcError):
            rejected = True
        require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, slowPathsRejected=2,
                wrongCleanupModelsRejected=2, actualStorageQueryExecuted=False,
                lazyAllocationExecuted=False, arm64Executed=False, startupExecuted=False)


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
        print('Pinned existing-slot comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
