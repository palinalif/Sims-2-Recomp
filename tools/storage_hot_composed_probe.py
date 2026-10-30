#!/usr/bin/env python3
"""Bounded selector + actual hot resolver x86 reference, development only.

Pinned originals stay private. Guard/storage are authored contracts. No cold
initialization, Windows services, native lift, IAT binding or startup is supplied.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import encoded_cache_probe as hot
import ptd_query_probe as query

r = hot.r
require = r.require
BODIES = (query, hot)


def pages(cookie, encoded):
    result = {}
    for address, word in ((hot.COOKIE, cookie), (hot.CACHE+33*4, encoded)):
        page = address & ~4095
        data = bytearray(4096)
        struct.pack_into('<I', data, address-page, word)
        result[page] = bytes(data)
    return result


def oracle(value, cookie, result, index, salt=0, *, clobber=False):
    """Independent composed frame arithmetic, not stitched isolated snapshots."""
    require(value in (query.FLS, r.NEG) and 0 <= cookie <= r.NEG and
            0 <= result <= r.NEG)
    regs, stack = query.free.inputs(index, salt)
    initial = regs.copy()
    def put(offset, word):
        struct.pack_into('<I', stack, r.SP-r.STACK+offset, word)
    def event(kind, args, ret, sp, flags):
        snapshot = regs.copy(); snapshot[7] = sp
        return dict(kind=kind, args=args, returnRva=ret, registers=snapshot,
                    flags=flags)
    for offset, word in ((-4, initial[6]), (-8, initial[4]),
                         (-12, query.END), (-16, query.BEGIN), (-20, query.NAME),
                         (-24, 33), (-28, r.BASE+0x8480DB),
                         (-32, r.SP-4), (-36, initial[1]), (-40, initial[4])):
        put(offset, word)
    regs[6] = r.SP-4
    events = [event('resolve', [33, query.NAME, query.BEGIN, query.END],
                    0x8480DB, r.SP-28, 0xCD7 & hot.MASK)]
    target = 0 if value == r.NEG else value
    regs[0], regs[2], regs[3], regs[4] = target, cookie & 31, value, target
    flags = 0x400 | (0x44 if not target else
                     (0x80 if target & 0x80000000 else 0) |
                     (4 if (target & 255).bit_count() % 2 == 0 else 0))
    if target:
        regs[2] = target
        put(-12, index); put(-16, r.BASE+0x8480F1)
        events += [event('guard', [], 0x8480EF, r.SP-16, flags),
                   event('fls', [index], 0x8480F1, r.SP-16, flags)]
    else:
        regs[4], regs[6] = initial[4], initial[6]
        events += [event('tls', [index], r.RETURN-r.BASE, r.SP, flags)]
    regs[0], regs[4], regs[6], regs[7] = result, initial[4], initial[6], r.SP+8
    if clobber:
        regs[2:4] = [0xFEEDFACE, 0xDEADBEEF]
    return dict(registers=regs, flags=flags, stack=bytes(stack), events=events,
                dataPages=pages(cookie, hot.encode(value, cookie)))


def exercise(codes, cookie, encoded, result, index, salt=0, *, clobber=False,
             provider_pop=4, budget=200):
    require(set(codes) == {p.ENTRY for p in BODIES})
    require(all(0 <= v <= r.NEG for v in (cookie, encoded, result)))
    require(provider_pop in (0, 4) and 0 < budget <= 200)
    starts = set()
    for p in BODIES:
        code = codes[p.ENTRY]
        require(0 < len(code) <= p.SIZE)
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, p.ENTRY))
        require(sum(i.size for i in decoded) == len(code))
        starts.update(i.address for i in decoded)
    regs, stack = query.free.inputs(index, salt)
    data = {**codes, r.STACK: bytes(stack),
            query.GUARD_SLOT: struct.pack('<I', query.GUARD),
            query.TLS_SLOT: struct.pack('<I', query.TLS)}
    data.update(pages(cookie, encoded))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    mapped = {r.RETURN, r.TRAPS}
    for address, payload in data.items():
        mapped.update(range(address & ~4095,
                            ((address+len(payload)-1) & ~4095)+4096, 4096))
    for page in mapped:
        u.mem_map(page, 4096)
    for address, payload in data.items():
        u.mem_write(address, payload)
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in mapped if p != r.STACK}
    for reg, word in zip(r.REGS, regs):
        u.reg_write(reg, word)
    u.reg_write(UC_X86_REG_EFLAGS, 0xCD7)
    u.reg_write(UC_X86_REG_EIP, query.ENTRY)
    events = []
    for _ in range(budget):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (hot.ENTRY, query.GUARD, query.FLS, query.TLS):
            require(len(events) < 3)
            kind, count = {hot.ENTRY: ('resolve', 4), query.GUARD: ('guard', 0),
                           query.FLS: ('fls', 1), query.TLS: ('tls', 1)}[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            if ip in (query.GUARD, query.FLS):
                require(u.reg_read(r.REGS[2]) == query.FLS)
            events.append(dict(kind=kind, args=args, returnRva=ret-r.BASE,
                               registers=[u.reg_read(reg) for reg in r.REGS],
                               flags=u.reg_read(UC_X86_REG_EFLAGS) & hot.MASK))
            if ip != hot.ENTRY:
                if ip != query.GUARD:
                    u.reg_write(r.REGS[0], result)
                    if clobber:
                        u.reg_write(r.REGS[2], 0xFEEDFACE)
                        u.reg_write(r.REGS[3], 0xDEADBEEF)
                u.reg_write(r.REGS[7], sp+4+(0 if ip == query.GUARD else provider_pop))
                u.reg_write(UC_X86_REG_EIP, ret)
                continue
        require(ip in starts)  # Cold helpers, arbitrary exports and gaps reject.
        u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == before for p, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                flags=u.reg_read(UC_X86_REG_EFLAGS) & hot.MASK,
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events,
                dataPages={p: bytes(u.mem_read(p, 4096)) for p in pages(cookie, encoded)})


def cases():
    return [(value, cookie, result, index, salt, clobber)
            for value in (query.FLS, r.NEG)
            for cookie in [0x12345660 | n for n in range(32)]+[0, 32, 0x80000000, r.NEG]
            for result in (0, 1, 0x80000000, r.NEG)
            for index in (0, 0x80000000, r.NEG)
            for salt in (0, 7) for clobber in (False, True)]


def probe(pe, selector_index=None, hot_index=None):
    codes = {p.ENTRY: pe.get_data(p.RVA, p.SIZE) for p in BODIES}
    require(all(len(codes[p.ENTRY]) == p.SIZE for p in BODIES))
    indexed = [p.compare_index(codes[p.ENTRY], doc) if doc is not None else 0
               for p, doc in ((query, selector_index), (hot, hot_index))]
    sweep = cases()
    for value, cookie, result, index, salt, clobber in sweep:
        r.verify(exercise(codes, cookie, hot.encode(value, cookie), result, index,
                          salt, clobber=clobber),
                 oracle(value, cookie, result, index, salt, clobber=clobber))
    rejected = 0
    for value, options in ((0, {}), (query.FLS+4, {}),
                           (query.FLS, {'provider_pop': 0}), (r.NEG, {'provider_pop': 0}),
                           (query.FLS, {'budget': 1})):
        try:
            actual = exercise(codes, 31, hot.encode(value, 31), 1, 0, **options)
            r.verify(actual, oracle(value, 31, 1, 0))
        except (ValueError, UcError):
            rejected += 1
    require(rejected == 5)
    return dict(cases=len(sweep), originalBodies=2, indexedBoundariesMnemonicsCompared=indexed,
                rejectedControls=rejected, coldExecuted=False, nativeCompared=False,
                windowsStorageExecuted=False, runtimeBound=False, startupExecuted=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selector-index', type=Path)
    parser.add_argument('--hot-index', type=Path)
    args = parser.parse_args(argv)
    pe = None
    try:
        docs = []
        for path in (args.selector_index, args.hot_index):
            if path is not None:
                require(path.stat().st_size <= 1024*1024)
            docs.append(json.loads(path.read_text()) if path is not None else None)
        pe = r.load_image()
        print(json.dumps(probe(pe, *docs), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError, query.pefile.PEFormatError):
        print('Pinned hot storage composition failed; private details suppressed.', file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
