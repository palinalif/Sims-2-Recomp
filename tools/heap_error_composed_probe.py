#!/usr/bin/env python3
"""Development-only release/error-path composition, NOT heap or TLS services.

Four cached, pinned original bodies execute in one x86 context. Only HeapFree,
Get/SetLastError and the existing-slot query remain authored dependencies.
Reads only the existing ignored image; prints counts/RVAs, never image bytes.
"""
import argparse
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import heap_release_probe as release
import os_error_probe as mapper
import error_slot_probe as accessor
import ptd_existing_probe as provider

r = release.r
require = r.require
PTD = r.ARRAY + 256
SENTINEL = 0x96969696
FREE, GET, SET = r.TRAPS, r.TRAPS+16, r.TRAPS+32
BODIES = (release, mapper, accessor, provider)


def validate(context, heap, result, error, index, pointer, table):
    mapper.validate(error, table)
    require(all(isinstance(n, int) and 0 <= n <= r.NEG
                for n in (context, heap, result, index, pointer)))
    # Only already-verified existing-slot paths. No lazy allocation surrogate.
    require(index != r.NEG and pointer in (PTD, r.NEG))


def oracle(context, heap, result, error, index, pointer, table, salt=0, *, clobber=False):
    validate(context, heap, result, error, index, pointer, table)
    base = release.oracle(context, heap, result, error, 0, salt, clobber=clobber)
    regs, stack = base['registers'], bytearray(base['stack'])
    slot = PTD+16 if pointer == PTD else accessor.FALLBACK
    values = {PTD+16: SENTINEL, accessor.FALLBACK: SENTINEL}
    events = base['events'][:2]  # no synthetic mapper/accessor interception
    last_error = error
    if context and result == 0:
        mapping = mapper.oracle(error, table, salt)
        mapped = mapping['registers'][0]
        regs[0] = slot
        # Release's caller cleanup at8461E5 pops the error argument into ECX,
        # overriding the mapper's range-path scratch value (14).
        regs[2] = 0xFEEDFACE if clobber else error
        regs[3] = 0xDEADBEEF if clobber else regs[3]
        # Nested frames overwrite the earlier mapper/free scratch slots.
        for offset, value in ((-32, r.BASE+0x8460CA), (-28, error),
                              (-24, regs[5]), (-20, regs[1]),
                              (-16, r.BASE+0x831B1C)):
            struct.pack_into('<I', stack, r.SP-r.STACK+offset, value)
        events.extend([('get', [], 0x846028, r.SP-28),
                       ('query', [index], 0x84603A, r.SP-32),
                       ('set', [error], 0x8460CA, r.SP-32)])
        values[slot] = mapped
        flags = accessor.add_flags(PTD, 16) if pointer == PTD else 0x444
    else:
        flags = base['flags']
    # External get events have the same label at both call sites.
    events = [('get' if k == 'last_error' else k, a, ret, sp)
              for k, a, ret, sp in events]
    return dict(registers=regs, stack=bytes(stack), flags=flags &
                (0xCD5 if not context or (result == 0 and pointer == PTD) else 0xCC5),
                events=events, slots=values, lastError=last_error)


def exercise(codes, context, heap, result, error, index, pointer, table, salt=0,
             *, clobber=False, query_pop=4, set_pop=4):
    validate(context, heap, result, error, index, pointer, table)
    require(query_pop in (0, 4) and set_pop in (0, 4))
    require(set(codes) == {p.ENTRY for p in BODIES})
    ranges = []
    for p in BODIES:
        code = codes[p.ENTRY]
        require(0 < len(code) <= p.SIZE)
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, p.ENTRY))
        require(sum(i.size for i in decoded) == len(code))
        ranges.append((p.ENTRY, p.ENTRY+len(code)))
    regs, stack = release.callback.inputs(context, salt)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    data = {release.HEAP: struct.pack('<I', heap),
            release.IAT+0x1DC: struct.pack('<I', FREE),
            provider.GET_SLOT: struct.pack('<I', GET),
            provider.SET_SLOT: struct.pack('<I', SET),
            provider.INDEX: struct.pack('<I', index),
            mapper.TABLE: b''.join(struct.pack('<II', *pair) for pair in table),
            PTD+16: struct.pack('<I', SENTINEL),
            accessor.FALLBACK: struct.pack('<I', SENTINEL), r.STACK: bytes(stack)}
    data.update(codes)
    pages = {r.RETURN, r.TRAPS, provider.QUERY & ~4095}
    for address, payload in data.items():
        pages.update(range(address & ~4095, ((address+len(payload)-1) & ~4095)+4096, 4096))
    for page in pages:
        u.mem_map(page, 4096)
    for address, payload in data.items():
        u.mem_write(address, payload)
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, value in zip(r.REGS, regs):
        u.reg_write(reg, value)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, release.ENTRY)
    events, last_error = [], error
    for _ in range(1500):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (FREE, GET, SET, provider.QUERY):
            require(len(events) < 5)
            kind, count, response, pop = {
                FREE: ('heap_free', 3, result, 12), GET: ('get', 0, last_error, 0),
                SET: ('set', 1, 0xBAADF00D, set_pop),
                provider.QUERY: ('query', 1, pointer, query_pop)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp))
            if ip == provider.QUERY:
                last_error = (error+1) & r.NEG  # query may disturb last-error
            elif ip == SET:
                last_error = args[0]
            u.reg_write(r.REGS[0], response)
            if clobber:
                u.reg_write(r.REGS[2], 0xFEEDFACE)
                u.reg_write(r.REGS[3], 0xDEADBEEF)
            u.reg_write(r.REGS[7], sp+4+pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(any(lo <= ip < hi for lo, hi in ranges))
            # The full provider bytes are present, but allocation is unsupported.
            require(not (r.BASE+0x846049 <= ip < r.BASE+0x8460C3))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    slots = {a: struct.unpack('<I', u.mem_read(a, 4))[0]
             for a in (PTD+16, accessor.FALLBACK)}
    for page, before in immutable.items():
        after = bytearray(u.mem_read(page, 4096))
        for address in slots:
            if page <= address < page+4096:
                offset = address-page
                after[offset:offset+4] = before[offset:offset+4]
        require(bytes(after) == before)
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events, slots=slots,
                lastError=last_error, flags=u.reg_read(UC_X86_REG_EFLAGS) &
                (0xCD5 if not context or (result == 0 and pointer == PTD) else 0xCC5))


def probe(pe):
    codes = {p.ENTRY: pe.get_data(p.RVA, p.SIZE) for p in BODIES}
    require(all(len(codes[p.ENTRY]) == p.SIZE for p in BODIES))
    raw = pe.get_data(mapper.TABLE-r.BASE, mapper.COUNT*8)
    require(len(raw) == mapper.COUNT*8)
    table = list(struct.iter_unpack('<II', raw))
    pe.parse_data_directories(directories=[1])
    names = {i.address: i.name for d in pe.DIRECTORY_ENTRY_IMPORT for i in d.imports}
    require(names[release.IAT+0x1DC] == b'HeapFree' and
            names[provider.GET_SLOT] == b'GetLastError' and names[provider.SET_SLOT] == b'SetLastError')
    cases = 0
    for context in (0, release.callback.STATIC, 0x80000000):
        for result in (0, 0x80000000):
            for error in (0, 19, 36, 37, 188, 202, 203, r.NEG):
                for pointer in (PTD, r.NEG):
                    for clobber in (False, True):
                        args = context, 0x80000000, result, error, 0x80000000, pointer, table, cases % 8
                        r.verify(exercise(codes, *args, clobber=clobber),
                                 oracle(*args, clobber=clobber))
                        cases += 1
    # Adjudicate priority/high-bit mapped values independently of original data.
    for error in (19, 188, r.NEG):
        fixture = [(error, 0x80000000)] + [(10000+n, n) for n in range(mapper.COUNT-1)]
        for pointer in (PTD, r.NEG):
            args = 1, 2, 0, error, 3, pointer, fixture
            r.verify(exercise(codes, *args), oracle(*args))
            cases += 1
    for options in ({'query_pop': 0}, {'set_pop': 0}):
        rejected = False
        try:
            args = 1, 2, 0, 19, 3, PTD, table
            r.verify(exercise(codes, *args, **options), oracle(*args))
        except (ValueError, UcError):
            rejected = True
        require(rejected)
    return dict(entryRva=hex(release.RVA), originalBodies=4, cases=cases,
                wrongCleanupModelsRejected=2,
                actualHeapExecuted=False, actualStorageQueryExecuted=False,
                runtimeBound=False, arm64Executed=False, startupExecuted=False)


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    pe = None
    try:
        pe = r.load_image()
        print(json.dumps(probe(pe), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, pefile.PEFormatError):
        print('Pinned composed error-path comparison failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
