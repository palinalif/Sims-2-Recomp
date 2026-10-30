#!/usr/bin/env python3
"""Pinned storage-query selector ABI, not a Windows storage implementation.

Only the existing ignored image is read. Resolver/guard/providers are authored
contracts; output is counts/RVAs only. No encoded-cache resolver is emulated.
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
import ptd_free_probe as free

RVA, SIZE = 0x8480BF, 63
ENTRY, RESOLVE = r.BASE+RVA, r.BASE+0x847E6C
GUARD_SLOT, TLS_SLOT = r.BASE+0xD9A71C, r.BASE+0xD9A2C8
GUARD, TLS, FLS = (r.TRAPS+n for n in (0, 16, 32))
NAME, BEGIN, END = (r.BASE+n for n in (0xE06E5C, 0xE0A05C, 0xE0A064))
require = r.require


def oracle(target, result, index, salt=0, *, clobber=False):
    require(target in (0, FLS) and 0 <= result <= r.NEG)
    regs, stack = free.inputs(index, salt)
    def put(offset, word):
        struct.pack_into('<I', stack, r.SP-r.STACK+offset, word)
    for offset, word in ((-4, regs[6]), (-8, regs[4]), (-12, END),
                         (-16, BEGIN), (-20, NAME), (-24, 33), (-28, r.BASE+0x8480DB)):
        put(offset, word)
    events = [('resolve', [33, NAME, BEGIN, END], 0x8480DB, r.SP-28, regs[2])]
    if clobber:
        regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]
    if target:
        put(-12, index); put(-16, r.BASE+0x8480F1)
        events += [('guard', [], 0x8480EF, r.SP-16, target),
                   ('fls', [index], 0x8480F1, r.SP-16, target)]
        regs[2] = target
    else:
        # Tail provider receives the ORIGINAL caller frame, unlike the FLS call.
        events += [('tls', [index], r.RETURN-r.BASE, r.SP, regs[2])]
    if clobber:
        regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]
    regs[0], regs[7] = result, r.SP+8
    flags = 0x400 | (0x40 if not target else 0) | (0x80 if target & 0x80000000 else 0)
    flags |= 4 if (target & 255).bit_count() % 2 == 0 else 0
    return dict(registers=regs, stack=bytes(stack), events=events, flags=flags)


def exercise(code, target, result, index, salt=0, *, clobber=False,
             provider_pop=4, resolver_pop=0):
    require(0 < len(code) <= SIZE and target in (0, FLS) and 0 <= result <= r.NEG)
    require(provider_pop in (0, 4) and resolver_pop in (0, 16))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack = free.inputs(index, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, RESOLVE & ~4095, GUARD_SLOT & ~4095,
             r.STACK, r.RETURN, r.TRAPS}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    u.mem_write(GUARD_SLOT, struct.pack('<I', GUARD))
    u.mem_write(TLS_SLOT, struct.pack('<I', TLS))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, word in zip(r.REGS, regs):
        u.reg_write(reg, word)
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
                GUARD: ('guard', 0, None, 0), TLS: ('tls', 1, result, provider_pop),
                FLS: ('fls', 1, result, provider_pop)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp, u.reg_read(r.REGS[2])))
            if response is not None:
                u.reg_write(r.REGS[0], response)
                if clobber:
                    u.reg_write(r.REGS[2], 0xFEEDFACE)
                    u.reg_write(r.REGS[3], 0xDEADBEEF)
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
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions', 'references', 'callers', 'callees')))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 23 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JZ': 'JE', 'JNZ': 'JNE'}.get(s.upper(), s.upper())
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
    require(names[TLS_SLOT] == b'TlsGetValue')
    require(pe.get_string_at_rva(NAME-r.BASE) == b'FlsGetValue')
    require(struct.unpack('<II', pe.get_data(BEGIN-r.BASE, 8)) == (21, 16))
    require(struct.unpack('<I', pe.get_data(GUARD_SLOT-r.BASE, 4))[0] == r.BASE+0x140FE0)
    cases = 0
    for target in (0, FLS):
        for result in (0, 1, 0x80000000, r.NEG):
            for index in (0, 1, 0x80000000, r.NEG):
                for salt in range(4):
                    for clobber in (False, True):
                        r.verify(exercise(code, target, result, index, salt, clobber=clobber),
                                 oracle(target, result, index, salt, clobber=clobber))
                        cases += 1
    rejected = 0
    for target, options in ((0, {'provider_pop': 0}), (FLS, {'provider_pop': 0}),
                            (FLS, {'resolver_pop': 16})):
        try:
            r.verify(exercise(code, target, 1, 0, **options), oracle(target, 1, 0))
        except (ValueError, UcError):
            rejected += 1
    require(rejected == 3)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongCleanupModelsRejected=rejected,
                encodedResolverExecuted=False, windowsStorageExecuted=False,
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
        print('Pinned query selector comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
