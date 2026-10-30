#!/usr/bin/env python3
"""Development-only hot-cache reference for the actual 0x847E6C resolver.

Only pinned private input is read; output contains counts/RVAs, never code or
states. Cold initialization and all external dependencies fail closed. This is
not a portable resolver, Windows service, runtime binding or ARM64 execution.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import resolver_probe as r

RVA, SIZE = 0x847E6C, 133
ENTRY = r.BASE + RVA
COOKIE = r.BASE + 0x104F540
CACHE = r.BASE + 0x10E02B0
MASK = 0xCC5  # Defined logic/CMP flags; AF excluded, DF retained.
require = r.require


def rotate(value, count, *, left=False):
    require(0 <= value <= r.NEG and 0 <= count <= 31)
    if not count:
        return value
    if left:
        return ((value << count) | (value >> (32-count))) & r.NEG
    return ((value >> count) | (value << (32-count))) & r.NEG


def encode(value, cookie):
    require(0 <= cookie <= r.NEG)
    return rotate(value, cookie & 31, left=True) ^ cookie


def inputs(index, salt):
    require(0 <= index < 64 and 0 <= salt < 256)
    regs = [(0x12345678 + salt*0x1020304 + n*0x112233) & r.NEG for n in range(8)]
    regs[7] = r.SP
    stack = bytearray([0x5A]*4096)
    struct.pack_into('<5I', stack, r.SP-r.STACK, r.RETURN, index, r.NAME, r.ARRAY, r.ARRAY+8)
    return regs, stack


def exercise(code, cookie, encoded, index=33, salt=0):
    require(0 < len(code) <= 256 and 0 <= cookie <= r.NEG and 0 <= encoded <= r.NEG)
    regs, stack = inputs(index, salt)
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in decoded) == len(code))
    starts = {i.address for i in decoded}
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    pages = {ENTRY & ~4095, COOKIE & ~4095, CACHE & ~4095, r.STACK, r.RETURN}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    u.mem_write(COOKIE, struct.pack('<I', cookie))
    u.mem_write(CACHE+4*index, struct.pack('<I', encoded))
    u.mem_write(r.STACK, bytes(stack))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages if p != r.STACK}
    for reg, word in zip(r.REGS, regs):
        u.reg_write(reg, word)
    u.reg_write(UC_X86_REG_EFLAGS, 0x602)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    for _ in range(100):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        require(ip in starts)  # No helper/API, code gaps or mid-instruction entry.
        u.emu_start(ip, r.RETURN, count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(bytes(u.mem_read(p, 4096)) == before for p, before in immutable.items()))
    return dict(registers=[u.reg_read(reg) for reg in r.REGS],
                flags=u.reg_read(UC_X86_REG_EFLAGS) & MASK,
                stack=bytes(u.mem_read(r.STACK, 4096)))


def oracle(value, cookie, index=33, salt=0):
    require(0 < value <= r.NEG and 0 <= cookie <= r.NEG)
    regs, stack = inputs(index, salt)
    # Original hot path's saved frame, including dead stack contents after RET.
    for offset, word in ((-4, regs[6]), (-8, regs[1]), (-12, regs[4])):
        struct.pack_into('<I', stack, r.SP-r.STACK+offset, word)
    regs[0] = 0 if value == r.NEG else value
    regs[2:4] = [cookie & 31, value]
    regs[7] = r.SP+4  # cdecl: four arguments stay with the caller.
    flags = 0x400 | (0x44 if value == r.NEG else
                    (0x80 if value & 0x80000000 else 0) |
                    (4 if (value & 255).bit_count() % 2 == 0 else 0))
    return dict(registers=regs, flags=flags, stack=bytes(stack))


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'], 16) == r.BASE)
    require(int(doc['function']['entryRva'], 16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions','references','callers','callees')))
    decoded = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 56 and sum(i.size for i in decoded) == SIZE)
    normalize = lambda s: {'JZ':'JE','JNZ':'JNE'}.get(s.upper(), s.upper())
    for item, ins in zip(items, decoded):
        require(int(item['rva'],16) == ins.address-r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code, doc) if doc is not None else 0
    cases = 0
    for cookie in (0, 1, 31, 32, 33, 0x80000000, 0x12345678, r.NEG):
        for value in (1, 2, 0x7FFFFFFF, 0x80000000, 0xC7000020, r.NEG):
            for index in (0, 33, 63):
                for salt in (0, 7):
                    r.verify(exercise(code, cookie, encode(value,cookie), index,salt),
                             oracle(value,cookie,index,salt))
                    cases += 1
    # Encoded zero is unresolved, not a cached-null return. Never provide a stub.
    rejected = 0
    for cookie in (0, 31, 0x12345678, r.NEG):
        try:
            exercise(code,cookie,encode(0,cookie))
        except (ValueError, UcError):
            rejected += 1
    require(rejected == 4)
    cookie, value = 0x12345678, 0xC7000020
    encoded = encode(value,cookie)
    observed = exercise(code,cookie,encoded)
    wrong_models = 0
    for wrong_value in (encoded, rotate(encoded^cookie,cookie&31,left=True),
                        rotate(encoded,cookie&31)^cookie):
        require(wrong_value not in (0,value))
        try:
            r.verify(observed,oracle(wrong_value,cookie))
        except ValueError:
            wrong_models += 1
    wrong = oracle(r.NEG,cookie)
    wrong['registers'][0] = r.NEG
    try:
        r.verify(exercise(code,cookie,encode(r.NEG,cookie)),wrong)
    except ValueError:
        wrong_models += 1
    require(wrong_models == 4)
    return dict(entryRva=hex(RVA), cases=cases, indexedBoundariesMnemonicsCompared=indexed,
                wrongDecodeModelsRejected=wrong_models,
                coldPathsRejected=rejected, externalServicesExecuted=False,
                arm64Executed=False, startupExecuted=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index',type=Path)
    args = parser.parse_args(argv)
    pe = None
    try:
        doc = None
        if args.index is not None:
            require(args.index.stat().st_size <= 1024*1024)
            doc = json.loads(args.index.read_text())
        pe = r.load_image()
        print(json.dumps(probe(pe,doc),sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError, UcError):
        print('Pinned encoded-cache comparison failed; private details suppressed.',file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
