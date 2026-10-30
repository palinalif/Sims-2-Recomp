#!/usr/bin/env python3
"""Accessor/provider/selector/hot resolver, bounded private x86 reference.

Last-error, guard and storage are authored contracts, not Windows services.
No cold allocation, native translation, runtime binding or startup is supplied.
"""
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import ptd_existing_probe as provider
import storage_hot_composed_probe as storage
import error_slot_probe as accessor

r = storage.r
require = r.require
query, hot = storage.query, storage.hot
BODIES = (accessor, provider, query, hot)
# Avoid aliasing GET/SET to the selector's guard/storage trap endpoints.
GET, SET = r.TRAPS+0x100, r.TRAPS+0x110


def pages(cookie, encoded, index):
    result = storage.pages(cookie, encoded)
    page = provider.INDEX & ~4095
    data = bytearray(result[page])
    struct.pack_into('<I', data, provider.INDEX-page, index)
    result[page] = bytes(data)
    return result


def validate(value, cookie, pointer, index, error):
    require(value in (query.FLS, r.NEG) and 0 <= cookie <= r.NEG and
            0 < pointer <= r.NEG and 0 <= index < r.NEG and 0 <= error <= r.NEG)


def oracle(value, cookie, pointer, index, error, salt=0, *, clobber=False):
    """Independent nested frame arithmetic; no reference execution used."""
    validate(value, cookie, pointer, index, error)
    initial, stack, _ = provider.init.inputs(salt)
    regs = list(initial)
    result = 0 if pointer == r.NEG else pointer
    regs[0] = (result+16) & r.NEG if result else accessor.FALLBACK
    regs[7] = r.SP+4
    regs[2:4] = ([0xFEEDFACE, 0xDEADBEEF] if clobber else
                 [value if value == query.FLS else cookie & 31, value])
    state = dict(registers=regs, flags=accessor.add_flags(result, 16) if result else 0x444)
    # Accessor CALL shifts nested frames four bytes. Independent final stores.
    words = [(-4, r.BASE+0x831B1C), (-8, initial[1]), (-12, initial[5]),
             (-16, error), (-20, r.BASE+0x8460CA),
             (-24, initial[6]), (-28, initial[4]), (-32, query.END),
             (-36, query.BEGIN), (-40, query.NAME), (-44, 33),
             (-48, r.BASE+0x8480DB), (-52, r.SP-24),
             (-56, initial[1]), (-60, initial[4])]
    if value == query.FLS:
        words += [(-32, index), (-36, r.BASE+0x8480F1)]
    for offset, word in words:
        struct.pack_into('<I', stack, r.SP-r.STACK+offset, word)
    state['stack'] = bytes(stack)
    events = [('get', [], 0x846028, r.SP-16),
              ('resolve', [33, query.NAME, query.BEGIN, query.END], 0x8480DB, r.SP-48)]
    if value == query.FLS:
        events += [('guard', [], 0x8480EF, r.SP-36),
                   ('fls', [index], 0x8480F1, r.SP-36)]
    else:
        events += [('tls', [index], 0x84603A, r.SP-20)]
    state.update(events=events+[('set', [error], 0x8460CA, r.SP-20)],
                 lastError=error, dataPages=pages(cookie, hot.encode(value, cookie), index))
    return state


def exercise(codes, cookie, encoded, pointer, index, error, salt=0, *, clobber=False,
             storage_pop=4, set_pop=4, restore=True, budget=300):
    require(set(codes) == {p.ENTRY for p in BODIES})
    require(all(0 <= n <= r.NEG for n in (cookie, encoded, pointer, index, error)))
    require(storage_pop in (0, 4) and set_pop in (0, 4) and 0 < budget <= 300)
    starts = set()
    for p in BODIES:
        code = codes[p.ENTRY]
        require(0 < len(code) <= p.SIZE)
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, p.ENTRY))
        require(sum(i.size for i in decoded) == len(code))
        starts.update(i.address for i in decoded)
    regs, stack, _ = provider.init.inputs(salt)
    data = {**codes, r.STACK: bytes(stack), **pages(cookie, encoded, index)}
    for address, word in ((provider.INDEX, index), (provider.GET_SLOT, GET),
                          (provider.SET_SLOT, SET), (query.GUARD_SLOT, query.GUARD),
                          (query.TLS_SLOT, query.TLS)):
        data[address] = struct.pack('<I', word)
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
    u.reg_write(UC_X86_REG_EIP, accessor.ENTRY)
    events, last_error = [], error
    endpoints = {GET: ('get', 0, 0), SET: ('set', 1, set_pop),
                 query.GUARD: ('guard', 0, 0), query.FLS: ('fls', 1, storage_pop),
                 query.TLS: ('tls', 1, storage_pop), hot.ENTRY: ('resolve', 4, 0)}
    for _ in range(budget):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in endpoints:
            require(len(events) < 5)
            kind, count, pop = endpoints[ip]
            sp = u.reg_read(r.REGS[7])
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp, 4*(count+1)))
            events.append((kind, args, ret-r.BASE, sp))
            if ip in (query.GUARD, query.FLS):
                require(u.reg_read(r.REGS[2]) == query.FLS)
            if ip != hot.ENTRY:
                if ip != query.GUARD:
                    response = last_error if ip == GET else 0xBAADF00D if ip == SET else pointer
                    if ip == SET and restore:
                        last_error = args[0]
                    elif ip in (query.FLS, query.TLS):
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
    require(all(bytes(u.mem_read(p, 4096)) == before for p, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                flags=u.reg_read(UC_X86_REG_EFLAGS) & (0xCC5 if pointer == r.NEG else 0xCD5),
                stack=bytes(u.mem_read(r.STACK, 4096)), events=events, lastError=last_error,
                dataPages={p: bytes(u.mem_read(p, 4096)) for p in pages(cookie, encoded, index)})


def cases():
    return [(value, cookie, pointer, index, error, salt, clobber)
            for value in (query.FLS, r.NEG)
            for cookie in [0x12345660 | n for n in range(32)]+[0, 32, 0x80000000, r.NEG]
            for pointer in (1, 0x7FFFFFF0, 0xFFFFFFF0, r.NEG-1, r.NEG)
            for index in (0, 0x80000000, r.NEG-1)
            for error in (0, r.NEG) for salt in (0, 7) for clobber in (False, True)]
