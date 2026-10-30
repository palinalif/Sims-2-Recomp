#!/usr/bin/env python3
"""Pinned provider slow paths with injected dependencies, NOT thread services.

Reads only the existing ignored hash-pinned image. Emits counts/RVAs, no bytes.
Publication means observed setter requests, not actual FLS/TLS implementation.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import pefile
import ptd_existing_probe as p
from error_slot_probe import add_flags
r, require = p.r, p.require
WRITE, ALLOC, INITIALIZE, FREE = (r.BASE+n for n in (0x8480FE, 0x849A00, 0x845CF9, 0x8461B8))
LOCALE = r.BASE+0x10E002C


def oracle(index, claim, pointer, publish, error, salt=0, *, clobber=False):
    require(all(isinstance(n, int) and 0 <= n <= r.NEG
                for n in (index, claim, pointer, publish, error)))
    regs, stack, _ = p.init.inputs(salt)
    sp, events = r.SP, []

    def push(value):
        nonlocal sp
        sp -= 4
        struct.pack_into('<I', stack, sp-r.STACK, value)

    def call(kind, args, ret, response, pop):
        nonlocal sp
        push(r.BASE+ret)
        events.append((kind, args, ret, sp))
        sp += 4+pop
        regs[0] = response
        if clobber:
            regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]

    push(regs[1]); push(regs[5])
    call('get', [], 0x846028, error, 0)
    if index != r.NEG:
        push(index)
        call('query', [index], 0x84603A, 0, 4)
    push(r.NEG); push(index)
    call('write', [index, r.NEG], 0x846056, claim, 8)
    result, flags = 0, 0x444
    if claim:
        push(regs[4])
        push(0x364); push(1)
        call('alloc', [1, 0x364], 0x84606B, pointer, 0)
        sp += 8
        regs[2] = 0x364  # second POP ECX, even if allocator clobbers it
        if pointer:
            push(pointer); push(index)
            call('write', [index, pointer], 0x846090, publish, 8)
        if not pointer or not publish:
            push(0); push(index)
            call('write', [index, 0], 0x846081 if not pointer else 0x8460A2,
                 0xBAADF00D, 8)  # rollback result is ignored
            push(pointer)
            call('free', [pointer], 0x8460A8, 0xBAADF00D, 0)
            regs[2] = pointer  # POP ECX after caller-cleaned free
            sp += 4
        else:
            push(LOCALE); push(pointer)
            call('initialize', [pointer, LOCALE], 0x8460B6, 0xBAADF00D, 0)
            push(0)
            call('free', [0], 0x8460BD, 0xBAADF00D, 0)
            flags = add_flags(sp, 12) & 0xCC5
            sp += 12
            result = pointer
        sp += 4  # restored ESI
    push(error)
    call('set', [error], 0x8460CA, 0xBAADF00D, 4)
    regs[0], regs[7] = result, r.SP+4
    return dict(registers=regs, stack=bytes(stack), events=events, flags=flags)


def exercise(code, index, claim, pointer, publish, error, salt=0, *, clobber=False,
             write_pop=8, alloc_pop=0, free_pop=0):
    require(0 < len(code) <= p.SIZE)
    require(all(isinstance(n, int) and 0 <= n <= r.NEG
                for n in (index, claim, pointer, publish, error)))
    require(write_pop in (0, 8) and alloc_pop in (0, 8) and free_pop in (0, 4))
    decoded = list(p.Cs(p.CS_ARCH_X86, p.CS_MODE_32).disasm(code, p.ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    regs, stack, _ = p.init.inputs(salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {addr & ~4095 for addr in (p.ENTRY, p.QUERY, WRITE, ALLOC, INITIALIZE,
             FREE, p.INDEX, p.GET_SLOT, p.SET_SLOT, r.STACK, r.RETURN, r.TRAPS)}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(p.ENTRY, code); u.mem_write(r.STACK, bytes(stack))
    for addr, value in ((p.INDEX, index), (p.GET_SLOT, p.GET), (p.SET_SLOT, p.SET)):
        u.mem_write(addr, struct.pack('<I', value))
    immutable = {page: bytes(u.mem_read(page, 4096)) for page in pages if page != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, p.ENTRY)
    events, writes = [], 0
    for _ in range(150):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (p.GET, p.QUERY, p.SET, WRITE, ALLOC, INITIALIZE, FREE):
            require(len(events) < 9)
            if ip == WRITE:
                response = (claim, publish if pointer else 0xBAADF00D, 0xBAADF00D)[writes]
                writes += 1
                kind, count, pop = 'write', 2, write_pop
            else:
                kind, count, response, pop = {
                    p.GET: ('get', 0, error, 0), p.QUERY: ('query', 1, 0, 4),
                    p.SET: ('set', 1, 0xBAADF00D, 4),
                    ALLOC: ('alloc', 2, pointer, alloc_pop),
                    INITIALIZE: ('initialize', 2, 0xBAADF00D, 0),
                    FREE: ('free', 1, 0xBAADF00D, free_pop)}[ip]
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
            require(p.ENTRY <= ip < p.ENTRY+len(code))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(page, 4096)) == before for page, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS], events=events,
                stack=bytes(u.mem_read(r.STACK, 4096)),
                flags=u.reg_read(UC_X86_REG_EFLAGS) & 0xCC5)


def probe(pe, doc=None):
    code = pe.get_data(p.RVA, p.SIZE)
    require(len(code) == p.SIZE)
    indexed = p.compare_index(code, doc) if doc is not None else 0
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    names = {i.address: i.name for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    require(names[p.GET_SLOT] == b'GetLastError' and names[p.SET_SLOT] == b'SetLastError')
    cases = 0
    for index in (0, 0x80000000, r.NEG):
        for claim in (0, 1, 0x80000000):
            for pointer in (0, 0x81234000, r.NEG):
                for publish in (0, 1, 0x80000000):
                    for error in (0, r.NEG):
                        for salt in range(2):
                            for clobber in (False, True):
                                args = (index, claim, pointer, publish, error, salt)
                                r.verify(exercise(code, *args, clobber=clobber),
                                         oracle(*args, clobber=clobber))
                                cases += 1
    for options in ({'write_pop': 0}, {'alloc_pop': 8}, {'free_pop': 4}):
        rejected = False
        try:
            args = (0, 1, 0x81234000, 0, 0)
            r.verify(exercise(code, *args, **options), oracle(*args))
        except (ValueError, UcError):
            rejected = True
        require(rejected)
    return dict(entryRva=hex(p.RVA), codeSize=p.SIZE, cases=cases,
                indexedBoundariesMnemonicsCompared=indexed, wrongCleanupModelsRejected=3,
                actualStorageExecuted=False, actualAllocationExecuted=False,
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
        print('Pinned lazy-provider comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
