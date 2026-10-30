#!/usr/bin/env python3
"""Pinned allocation selector ABI, not a Windows FLS/TLS implementation.

Reads only the existing ignored image; emits counts/RVAs, never original bytes.
Resolver, guard and OS boundaries have authored preservation/response contracts.
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

RVA, SIZE = 0x82A2FD, 59
ENTRY = r.BASE + RVA
RESOLVE = r.BASE + 0x82A212
GUARD_SLOT, TLS_SLOT = r.BASE + 0xD9A71C, r.BASE + 0xD9A2C4
GUARD, TLS, FLS = (r.TRAPS + n for n in (0, 16, 32))
NAME, BEGIN, END = (r.BASE + n for n in (0xE06E38, 0xE06E30, 0xE06E38))
require = r.require


def oracle(target, result, salt=0):
    require(target in (0, FLS) and 0 <= result <= r.NEG)
    regs, stack, _ = init.inputs(salt)
    callback = struct.unpack_from('<I', stack, r.SP - r.STACK + 4)[0]
    def put(offset, value):
        struct.pack_into('<I', stack, r.SP - r.STACK + offset, value)
    for offset, value in ((-4, regs[6]), (-8, regs[4]), (-12, END),
                          (-16, BEGIN), (-20, NAME), (-24, 0), (-28, r.BASE + 0x82A317)):
        put(offset, value)
    events = [('resolve', [0, NAME, BEGIN, END], 0x82A317, r.SP - 28, regs[2])]
    if target:
        put(-12, callback)
        put(-16, r.BASE + 0x82A32D)
        events += [('guard', [], 0x82A32B, r.SP - 16, target),
                   ('fls', [callback], 0x82A32D, r.SP - 16, target)]
        regs[2] = target
    else:
        events += [('tls', [], r.RETURN - r.BASE, r.SP, regs[2])]
    regs[0] = result
    regs[7] += 4
    flags = 0x400 | (0x40 if not target else 0) | (0x80 if target & 0x80000000 else 0)
    flags |= 4 if (target & 255).bit_count() % 2 == 0 else 0
    return dict(registers=regs, stack=bytes(stack), events=events, flags=flags)


def exercise(code, target, result, salt=0, *, fls_pop=4, resolver_pop=0):
    require(0 < len(code) <= SIZE and target in (0, FLS))
    require(fls_pop in (0, 4) and resolver_pop in (0, 16))
    regs, stack, _ = init.inputs(salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, RESOLVE & ~4095, GUARD_SLOT & ~4095,
             r.STACK, r.RETURN, r.TRAPS}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    u.mem_write(GUARD_SLOT, struct.pack('<I', GUARD))
    u.mem_write(TLS_SLOT, struct.pack('<I', TLS))
    immutable = {page: bytes(u.mem_read(page, 4096)) for page in pages if page != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    for _ in range(100):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (RESOLVE, GUARD, TLS, FLS):
            require(len(events) < 3)
            kind, count, response, pop = {
                RESOLVE: ('resolve', 4, target, resolver_pop),
                GUARD: ('guard', 0, None, 0), TLS: ('tls', 0, result, 0),
                FLS: ('fls', 1, result, fls_pop)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<' + 'I' * (count + 1), u.mem_read(sp, 4 * (count + 1)))
            ecx = u.reg_read(r.REGS[2])
            events.append((kind, args, ret - r.BASE, sp, ecx))
            if response is not None:
                u.reg_write(r.REGS[0], response)
            u.reg_write(r.REGS[7], sp + 4 + pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(ENTRY <= ip < ENTRY + len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(page, 4096)) == data for page, data in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events,
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions', 'references', 'callers', 'callees')))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 22 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JZ': 'JE', 'JNZ': 'JNE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address - r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    names = {imp.address: imp.name for desc in pe.DIRECTORY_ENTRY_IMPORT for imp in desc.imports}
    require(names[TLS_SLOT] == b'TlsAlloc')
    require(pe.get_string_at_rva(NAME - r.BASE) == b'FlsAlloc')
    require(struct.unpack('<II', pe.get_data(BEGIN - r.BASE, 8)) == (0, 2))
    require(struct.unpack('<I', pe.get_data(GUARD_SLOT - r.BASE, 4))[0] == r.BASE + 0x140FE0)
    cases = 0
    for target in (0, FLS):
        for result in (0, 1, 0x80000000, r.NEG):
            for salt in range(8):
                r.verify(exercise(code, target, result, salt), oracle(target, result, salt))
                cases += 1
    for options in ({'fls_pop': 0}, {'resolver_pop': 16}):
        rejected = False
        try:
            r.verify(exercise(code, FLS, 1, **options), oracle(FLS, 1))
        except (ValueError, UcError):
            rejected = True
        require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongCleanupModelsRejected=2,
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
        print('Pinned allocation selector comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
