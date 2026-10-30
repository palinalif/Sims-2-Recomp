#!/usr/bin/env python3
"""Pinned downstream heap-release boundary; injected APIs, NOT a guest heap.

Reads only the existing ignored hash-pinned image. Emits counts/RVAs, not bytes.
Reference x86 runs only at development time; nothing is bound into the runtime.
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

RVA, SIZE = 0x8461B8, 58
ENTRY = r.BASE + RVA
HEAP, IAT = r.BASE + 0x10E0380, r.BASE + 0xD9A000
MAPPER, ERRNO = r.BASE + 0x831A7A, r.BASE + 0x831B17
FREE, ERROR, SLOT = r.TRAPS, r.TRAPS + 16, r.ARRAY + 128
require = r.require


def oracle(context, heap, result, error, mapped, salt=0, *, clobber=False):
    require(all(isinstance(v, int) and 0 <= v <= r.NEG
                for v in (context, heap, result, error, mapped)))
    regs, stack = callback.inputs(context, salt)
    struct.pack_into('<I', stack, r.SP-r.STACK-4, regs[6])
    events, slot = [], 0x96969696
    flags = callback.cmp_flags(0, 0)
    if context:
        struct.pack_into('<4I', stack, r.SP-r.STACK-20,
                         r.BASE+0x8461D4, heap, 0, context)
        events.append(('heap_free', [heap, 0, context], 0x8461D4, r.SP-20))
        regs[0] = result
        if clobber:
            regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]
        flags = (0x400 | (4 if (result & 255).bit_count() % 2 == 0 else 0)
                 | (0x40 if result == 0 else 0) | (0x80 if result & 0x80000000 else 0))
        if result == 0:
            events.extend([('last_error', [], 0x8461DF, r.SP-12),
                           ('map_error', [error], 0x8461E5, r.SP-16),
                           ('errno', [], 0x8461ED, r.SP-12)])
            struct.pack_into('<3I', stack, r.SP-r.STACK-16,
                             r.BASE+0x8461E5, r.BASE+0x8461ED, regs[4])
            regs[0], regs[2], slot = SLOT, (0xFEEDFACE if clobber else error), mapped
            if clobber:
                flags = 0xC95
    regs[7] = r.SP+4  # cdecl; original argument remains caller-owned
    return dict(registers=regs, stack=bytes(stack), events=events, slot=slot,
                flags=flags & (0xCC5 if context else 0xCD5))


def exercise(code, context, heap, result, error, mapped, salt=0, *, clobber=False,
             free_pop=12, mapper_pop=0):
    require(0 < len(code) <= SIZE and free_pop in (0, 12) and mapper_pop in (0, 4))
    require(all(isinstance(v, int) and 0 <= v <= r.NEG
                for v in (context, heap, result, error, mapped)))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack = callback.inputs(context, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, MAPPER & ~4095, r.STACK, r.RETURN,
             HEAP & ~4095, IAT, r.TRAPS, r.ARRAY}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(r.STACK, bytes(stack))
    u.mem_write(HEAP, struct.pack('<I', heap))
    u.mem_write(IAT+0x1DC, struct.pack('<I', FREE))
    u.mem_write(IAT+0x118, struct.pack('<I', ERROR))
    u.mem_write(SLOT, struct.pack('<I', 0x96969696))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events = []
    dependencies = {FREE: ('heap_free', 3, result, free_pop),
                    ERROR: ('last_error', 0, error, 0),
                    MAPPER: ('map_error', 1, mapped, mapper_pop),
                    ERRNO: ('errno', 0, SLOT, 0)}
    for _ in range(100):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in dependencies:
            require(len(events) < 4)
            kind, count, value, pop = dependencies[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp))
            u.reg_write(r.REGS[0], value)
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
    slot = struct.unpack('<I', u.mem_read(SLOT, 4))[0]
    # Only the four-byte errno slot may change outside the stack.
    for page, before in immutable.items():
        after = bytes(u.mem_read(page, 4096))
        if page == r.ARRAY:
            offset = SLOT-page
            require(after[:offset] == before[:offset] and after[offset+4:] == before[offset+4:])
        else:
            require(after == before)
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events, slot=slot,
                flags=u.reg_read(UC_X86_REG_EFLAGS) & (0xCC5 if context else 0xCD5))


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not doc['truncation']['instructions'])
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 22 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JZ': 'JE', 'JNZ': 'JNE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'], 16) == ins.address-r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    pe.parse_data_directories(directories=[1])
    imports = {i.address-r.BASE: i.name for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    require(imports[0xD9A1DC] == b'HeapFree' and imports[0xD9A118] == b'GetLastError')
    cases = 0
    for context in (0, callback.STATIC, 1, 0x80000000, r.NEG):
        for heap in (0, 0x80000000):
            for result in (0, 1, 0x80000000, r.NEG):
                for error, mapped in ((0, 0), (5, 13), (r.NEG, 0x80000000)):
                    for salt in range(2):
                        for clobber in (False, True):
                            args = context, heap, result, error, mapped, salt
                            r.verify(exercise(code, *args, clobber=clobber),
                                     oracle(*args, clobber=clobber))
                            cases += 1
    for kwargs in ({'free_pop': 0}, {'mapper_pop': 4}):
        rejected = False
        try:
            r.verify(exercise(code, 1, 2, 0, 5, 13, **kwargs), oracle(1, 2, 0, 5, 13))
        except (ValueError, UcError):
            rejected = True
        require(rejected)
    return dict(entryRva=hex(RVA), codeSize=SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongCleanupModelsRejected=2,
                actualHeapExecuted=False, actualErrnoHelpersExecuted=False,
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
        print('Pinned heap-release comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
