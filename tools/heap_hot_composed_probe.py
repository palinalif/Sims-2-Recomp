#!/usr/bin/env python3
"""Six-body release/error/hot-storage x86 reference, development only.

Only the existing pinned private image is read. Heap/last-error/guard/storage
endpoints are authored contracts, not Windows services. No native binding.
"""
import argparse
import json
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import heap_storage_composed_probe as prior
import provider_hot_composed_probe as provider_hot

r, require = prior.r, prior.require
chain, query, hot = prior.chain, prior.query, provider_hot.hot
FREE, GET, SET, GUARD, TLS, FLS = prior.FREE, prior.GET, prior.SET, prior.GUARD, prior.TLS, prior.FLS
BODIES = (*prior.BODIES, hot)


def oracle(context, heap, result, error, index, pointer, table, value, cookie,
           salt=0, *, clobber=False):
    require(value in (FLS, r.NEG) and 0 <= cookie <= r.NEG)
    target = FLS if value == FLS else 0
    state = prior.oracle(context, heap, result, error, index, pointer, table,
                         target, salt, clobber=clobber)
    if context and result == 0:
        initial, _ = chain.release.callback.inputs(context, salt)
        mapped = chain.mapper.oracle(error, table, salt)['registers'][0]
        stack = bytearray(state['stack'])
        # Selector entry SP-32; resolver entry SP-60. Its three saves remain
        # below SetLastError's later frame, and must not be treated as opaque.
        for offset, word in ((-64, r.SP-36), (-68, initial[1]), (-72, mapped)):
            struct.pack_into('<I', stack, r.SP-r.STACK+offset, word)
        state['stack'] = bytes(stack)
        if not clobber:
            state['registers'][2:4] = [target if target else cookie & 31, value]
    state['cacheWords'] = [cookie, hot.encode(value, cookie)]
    return state


def exercise(codes, context, heap, result, error, index, pointer, table, cookie,
             encoded, salt=0, *, clobber=False, storage_pop=4, set_pop=4,
             restore=True, budget=1600):
    chain.validate(context, heap, result, error, index, pointer, table)
    require(set(codes) == {p.ENTRY for p in BODIES})
    require(0 <= cookie <= r.NEG and 0 <= encoded <= r.NEG and
            storage_pop in (0, 4) and set_pop in (0, 4) and 0 < budget <= 1600)
    starts = set()
    for p in BODIES:
        code = codes[p.ENTRY]
        require(0 < len(code) <= p.SIZE)
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, p.ENTRY))
        require(sum(i.size for i in decoded) == len(code))
        starts.update(i.address for i in decoded)
    regs, stack = chain.release.callback.inputs(context, salt)
    data = {**codes, r.STACK: bytes(stack),
            chain.mapper.TABLE: b''.join(struct.pack('<II', *pair) for pair in table)}
    for address, word in ((chain.release.HEAP, heap), (chain.release.IAT+0x1DC, FREE),
                          (chain.provider.GET_SLOT, GET), (chain.provider.SET_SLOT, SET),
                          (chain.provider.INDEX, index), (chain.PTD+16, chain.SENTINEL),
                          (chain.accessor.FALLBACK, chain.SENTINEL),
                          (query.GUARD_SLOT, GUARD), (query.TLS_SLOT, TLS),
                          (hot.COOKIE, cookie), (hot.CACHE+33*4, encoded)):
        data[address] = struct.pack('<I', word)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {r.RETURN, r.TRAPS}
    for address, payload in data.items():
        pages.update(range(address & ~4095, ((address+len(payload)-1) & ~4095)+4096, 4096))
    for page in pages:
        u.mem_map(page, 4096)
    for address, payload in data.items():
        u.mem_write(address, payload)
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, word in zip(r.REGS, regs):
        u.reg_write(reg, word)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, chain.release.ENTRY)
    endpoints = {FREE: ('heap_free', 3, 12), GET: ('get', 0, 0),
                 SET: ('set', 1, set_pop), GUARD: ('guard', 0, 0),
                 TLS: ('tls', 1, storage_pop), FLS: ('fls', 1, storage_pop),
                 hot.ENTRY: ('resolve', 4, 0)}
    events, last_error = [], error
    for _ in range(budget):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in endpoints:
            require(len(events) < 8)
            kind, count, pop = endpoints[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp))
            if ip in (GUARD, FLS):
                require(u.reg_read(r.REGS[2]) == FLS)
            if ip != hot.ENTRY:
                if ip != GUARD:
                    response = (result if ip == FREE else last_error if ip == GET
                                else 0xBAADF00D if ip == SET else pointer)
                    if ip == SET and restore:
                        last_error = args[0]
                    elif ip in (TLS, FLS):
                        last_error = (last_error+1) & r.NEG
                    u.reg_write(r.REGS[0], response)
                    if clobber:
                        u.reg_write(r.REGS[2], 0xFEEDFACE)
                        u.reg_write(r.REGS[3], 0xDEADBEEF)
                u.reg_write(r.REGS[7], sp+4+pop)
                u.reg_write(UC_X86_REG_EIP, ret)
                continue
        require(ip in starts)
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
                (0xCD5 if not context or (result == 0 and pointer == chain.PTD) else 0xCC5),
                cacheWords=[struct.unpack('<I', u.mem_read(a, 4))[0]
                            for a in (hot.COOKIE, hot.CACHE+33*4)])


def probe(pe):
    codes = {p.ENTRY: pe.get_data(p.RVA, p.SIZE) for p in BODIES}
    require(all(len(codes[p.ENTRY]) == p.SIZE for p in BODIES))
    # Retain independent import and single-body checks, without repeating the
    # large three/five-body sweeps as an incidental prerequisite.
    chain.probe(pe)
    query.probe(pe)
    table = list(struct.iter_unpack('<II', pe.get_data(chain.mapper.TABLE-r.BASE,
                                                      chain.mapper.COUNT*8)))
    cases = 0
    for context, result in ((0, 0), (1, 1), (1, 0), (0x80000000, 0)):
        for error in (0, 19, 188, 203, r.NEG):
            for pointer in (chain.PTD, r.NEG):
                for value in (FLS, r.NEG):
                    for count in range(32):
                        for clobber in (False, True):
                            cookie = 0x12345660 | count
                            args = context, 2, result, error, 0x80000000, pointer, table
                            r.verify(exercise(codes, *args, cookie, hot.encode(value, cookie),
                                              cases % 8, clobber=clobber),
                                     oracle(*args, value, cookie, cases % 8, clobber=clobber))
                            cases += 1
    rejected = 0
    for value, options in ((FLS, {'storage_pop': 0}), (r.NEG, {'storage_pop': 0}),
                           (FLS, {'set_pop': 0}), (r.NEG, {'restore': False}),
                           (0, {}), (FLS+4, {}), (FLS, {'budget': 1})):
        try:
            args = 1, 2, 0, 19, 3, chain.PTD, table
            r.verify(exercise(codes, *args, 31, hot.encode(value, 31), **options),
                     oracle(*args, value, 31))
        except (ValueError, UcError):
            rejected += 1
    require(rejected == 7)
    return dict(originalBodies=6, cases=cases, rejectedControls=rejected,
                encodedHotResolverExecuted=True, nativeCompared=False,
                windowsServicesExecuted=False, coldExecuted=False,
                runtimeBound=False, arm64Executed=False, startupExecuted=False)


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    pe = None
    try:
        pe = r.load_image()
        print(json.dumps(probe(pe), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, query.pefile.PEFormatError):
        print('Pinned heap/hot composition failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
