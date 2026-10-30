#!/usr/bin/env python3
"""Five cached original bodies in one bounded development-only x86 context.

No heap/storage/encoded-resolver implementation or runtime binding. Reads the
existing pinned private image only; emits counts, never original bytes/states.
"""
import argparse
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import heap_error_composed_probe as chain
import ptd_query_probe as query

r = chain.r
require = r.require
# Distinct authored external endpoints; no alias to the unrelated 82A212 resolver.
FREE, GET, SET, GUARD, TLS, FLS = (r.TRAPS+n*16 for n in range(6))
BODIES = (*chain.BODIES, query)


def oracle(context, heap, result, error, index, pointer, table, target, salt=0,
           *, clobber=False):
    require(target in (0, FLS))
    state = chain.oracle(context, heap, result, error, index, pointer, table,
                         salt, clobber=clobber)
    if context and result == 0:
        stack = bytearray(state['stack'])
        mapped = chain.mapper.oracle(error, table, salt)['registers'][0]
        # Selector entry SP is the provider's nested query frame, SP-32.
        words = [(-36, r.SP-4), (-40, mapped), (-44, query.END),
                 (-48, query.BEGIN), (-52, query.NAME), (-56, 33),
                 (-60, r.BASE+0x8480DB)]
        if target:
            words += [(-44, index), (-48, r.BASE+0x8480F1)]
            # Unlike an opaque query, the dynamic selector explicitly loads ECX.
            # The later SetLastError preserves it only in the non-clobber model.
            if not clobber:
                state['registers'][2] = target
        for offset, value in words:
            struct.pack_into('<I', stack, r.SP-r.STACK+offset, value)
        state['stack'] = bytes(stack)
        events = state['events']
        # External trace deliberately excludes the now-executed original query.
        replacement = [('resolve', [33, query.NAME, query.BEGIN, query.END],
                        0x8480DB, r.SP-60)]
        if target:
            replacement += [('guard', [], 0x8480EF, r.SP-48),
                            ('fls', [index], 0x8480F1, r.SP-48)]
        else:
            replacement += [('tls', [index], 0x84603A, r.SP-32)]
        state['events'] = events[:3]+replacement+events[4:]
    return state


def exercise(codes, context, heap, result, error, index, pointer, table, target,
             salt=0, *, clobber=False, provider_pop=4, resolver_pop=0,
             set_pop=4, restore=True):
    chain.validate(context, heap, result, error, index, pointer, table)
    require(target in (0, FLS) and provider_pop in (0, 4) and
            resolver_pop in (0, 16) and set_pop in (0, 4))
    require(set(codes) == {p.ENTRY for p in BODIES})
    ranges = []
    for p in BODIES:
        code = codes[p.ENTRY]
        require(0 < len(code) <= p.SIZE)
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, p.ENTRY))
        require(sum(i.size for i in decoded) == len(code))
        ranges.append((p.ENTRY, p.ENTRY+len(code)))
    regs, stack = chain.release.callback.inputs(context, salt)
    data = {chain.release.HEAP: struct.pack('<I', heap),
            chain.release.IAT+0x1DC: struct.pack('<I', FREE),
            chain.provider.GET_SLOT: struct.pack('<I', GET),
            chain.provider.SET_SLOT: struct.pack('<I', SET),
            chain.provider.INDEX: struct.pack('<I', index),
            chain.mapper.TABLE: b''.join(struct.pack('<II', *pair) for pair in table),
            chain.PTD+16: struct.pack('<I', chain.SENTINEL),
            chain.accessor.FALLBACK: struct.pack('<I', chain.SENTINEL),
            query.GUARD_SLOT: struct.pack('<I', GUARD),
            query.TLS_SLOT: struct.pack('<I', TLS), r.STACK: bytes(stack)}
    data.update(codes)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {r.RETURN, r.TRAPS, query.RESOLVE & ~4095}
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
    u.reg_write(UC_X86_REG_EIP, chain.release.ENTRY)
    events, last_error = [], error
    externals = {FREE: ('heap_free', 3, result, 12),
                 GET: ('get', 0, None, 0), SET: ('set', 1, 0xBAADF00D, set_pop),
                 query.RESOLVE: ('resolve', 4, target, resolver_pop),
                 GUARD: ('guard', 0, None, 0),
                 TLS: ('tls', 1, pointer, provider_pop),
                 FLS: ('fls', 1, pointer, provider_pop)}
    for _ in range(1600):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in externals:
            require(len(events) < 8)
            kind, count, response, pop = externals[ip]
            if ip in (GUARD, FLS):
                require(target == FLS and u.reg_read(r.REGS[2]) == target)
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp))
            if ip == GET:
                response = last_error
            elif ip == SET and restore:
                last_error = args[0]
            elif ip in (query.RESOLVE, TLS, FLS):
                last_error = (last_error+1) & r.NEG
            # Authored guard preserves state, as required by this narrow fixture.
            if response is not None:
                u.reg_write(r.REGS[0], response)
                if clobber:
                    u.reg_write(r.REGS[2], 0xFEEDFACE)
                    u.reg_write(r.REGS[3], 0xDEADBEEF)
            u.reg_write(r.REGS[7], sp+4+pop)
            u.reg_write(UC_X86_REG_EIP, ret)
        else:
            require(any(lo <= ip < hi for lo, hi in ranges))
            require(not (r.BASE+0x846049 <= ip < r.BASE+0x8460C3))
            u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    slots = {a: struct.unpack('<I', u.mem_read(a, 4))[0]
             for a in (chain.PTD+16, chain.accessor.FALLBACK)}
    for page, before in immutable.items():
        after = bytearray(u.mem_read(page, 4096))
        for address in slots:
            if page <= address < page+4096:
                off = address-page
                after[off:off+4] = before[off:off+4]
        require(bytes(after) == before)
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events, slots=slots,
                lastError=last_error, flags=u.reg_read(UC_X86_REG_EFLAGS) &
                (0xCD5 if not context or (result == 0 and pointer == chain.PTD) else 0xCC5))


def probe(pe):
    codes = {p.ENTRY: pe.get_data(p.RVA, p.SIZE) for p in BODIES}
    require(all(len(codes[p.ENTRY]) == p.SIZE for p in BODIES))
    # Reuse metadata/import checks and independent individual-body controls.
    chain.probe(pe)
    query.probe(pe)
    table = list(struct.iter_unpack('<II', pe.get_data(chain.mapper.TABLE-r.BASE,
                                                      chain.mapper.COUNT*8)))
    cases = 0
    for context in (0, chain.release.callback.STATIC, 0x80000000):
        for result in (0, 0x80000000):
            for error in (0, 19, 188, 203, r.NEG):
                for index in (0, 0x80000000, r.NEG-1):
                    for pointer in (chain.PTD, r.NEG):
                        for target in (0, FLS):
                            for clobber in (False, True):
                                args = context, 2, result, error, index, pointer, table, target, cases % 8
                                r.verify(exercise(codes, *args, clobber=clobber),
                                         oracle(*args, clobber=clobber))
                                cases += 1
    rejected = 0
    for target, options in ((0, {'provider_pop': 0}), (FLS, {'provider_pop': 0}),
                            (FLS, {'resolver_pop': 16}), (0, {'set_pop': 0}),
                            (FLS, {'restore': False})):
        try:
            args = 1, 2, 0, 19, 3, chain.PTD, table, target
            r.verify(exercise(codes, *args, **options), oracle(*args))
        except (ValueError, UcError):
            rejected += 1
    require(rejected == 5)
    return dict(originalBodies=5, cases=cases, wrongModelsRejected=rejected,
                encodedResolverExecuted=False, windowsStorageExecuted=False,
                arm64Executed=False, runtimeBound=False, startupExecuted=False)


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    pe = None
    try:
        pe = r.load_image()
        print(json.dumps(probe(pe), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, pefile.PEFormatError):
        print('Pinned storage composition failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
