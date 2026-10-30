#!/usr/bin/env python3
"""Pinned PTD set selector ABI; injected providers, NOT Windows FLS/TLS.

Only the existing ignored image is read. Output is metadata/counts, never bytes.
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

RVA, SIZE = 0x82A3AE, 62
ENTRY, RESOLVE = r.BASE + RVA, r.BASE + 0x82A212
GUARD_SLOT, TLS_SLOT = r.BASE + 0xD9A71C, r.BASE + 0xD9A2CC
GUARD, TLS, FLS = (r.TRAPS + n for n in (0, 16, 32))
NAME, BEGIN, END = (r.BASE + n for n in (0xE06E70, 0xE06E68, 0xE06E70))
require = r.require


def inputs(index, value, salt):
    require(all(isinstance(v, int) and 0 <= v <= r.NEG for v in (index, value)))
    regs, stack, _ = init.inputs(salt)
    struct.pack_into('<II', stack, r.SP - r.STACK + 4, index, value)
    return regs, stack


def oracle(target, result, index, value, salt=0):
    require(target in (0, FLS) and 0 <= result <= r.NEG)
    regs, stack = inputs(index, value, salt)
    def put(offset, word):
        struct.pack_into('<I', stack, r.SP - r.STACK + offset, word)
    for offset, word in ((-4, regs[6]), (-8, regs[4]), (-12, END),
                         (-16, BEGIN), (-20, NAME), (-24, 3), (-28, r.BASE + 0x82A3C8)):
        put(offset, word)
    events = [('resolve', [3, NAME, BEGIN, END], 0x82A3C8, r.SP - 28, regs[2])]
    put(-12, value); put(-16, index)
    if target:
        events += [('guard', [], 0x82A3DF, r.SP - 20, target),
                   ('fls', [index, value], 0x82A3E1, r.SP - 20, target)]
        put(-20, r.BASE + 0x82A3E1)
        regs[2] = target
    else:
        events += [('tls', [index, value], 0x82A3E9, r.SP - 20, regs[2])]
        put(-20, r.BASE + 0x82A3E9)
    regs[0] = result
    regs[7] += 4
    flags = 0x400 | (0x40 if not target else 0) | (0x80 if target & 0x80000000 else 0)
    flags |= 4 if (target & 255).bit_count() % 2 == 0 else 0
    return dict(registers=regs, stack=bytes(stack), events=events, flags=flags)


def exercise(code, target, result, index, value, salt=0, *, provider_pop=8, resolver_pop=0):
    require(0 < len(code) <= SIZE and target in (0, FLS))
    require(provider_pop in (0, 8) and resolver_pop in (0, 16))
    regs, stack = inputs(index, value, salt)
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
                GUARD: ('guard', 0, None, 0), TLS: ('tls', 2, result, provider_pop),
                FLS: ('fls', 2, result, provider_pop)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<' + 'I' * (count + 1), u.mem_read(sp, 4 * (count + 1)))
            events.append((kind, args, ret - r.BASE, sp, u.reg_read(r.REGS[2])))
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
    require(names[TLS_SLOT] == b'TlsSetValue')
    require(pe.get_string_at_rva(NAME - r.BASE) == b'FlsSetValue')
    require(struct.unpack('<II', pe.get_data(BEGIN - r.BASE, 8)) == (0, 2))
    require(struct.unpack('<I', pe.get_data(GUARD_SLOT - r.BASE, 4))[0] == r.BASE + 0x140FE0)
    cases = 0
    for target in (0, FLS):
        for result in (0, 1, 0x80000000, r.NEG):
            for index in (0, 1, 0x80000000, r.NEG):
                for value in (0, 0xFEDCBA98):
                    for salt in range(8):
                        r.verify(exercise(code, target, result, index, value, salt),
                                 oracle(target, result, index, value, salt))
                        cases += 1
    rejected = 0
    for target, options in ((0, {'provider_pop': 0}), (FLS, {'provider_pop': 0}),
                            (FLS, {'resolver_pop': 16})):
        try:
            r.verify(exercise(code, target, 1, 0, 0, **options), oracle(target, 1, 0, 0))
        except (ValueError, UcError):
            rejected += 1
    require(rejected == 3)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongCleanupModelsRejected=rejected,
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
        print('Pinned set selector comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
