#!/usr/bin/env python3
"""Private development reference for actual resolver dependency 0x847DA1.

Counts/RVAs only. Windows APIs and both prefix comparisons are authored
responses, NOT services. Single-threaded module publication only; no races,
ownership, full volatile/flags/stack contract, ARM64 or startup claim.
"""
import argparse
import itertools
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_EFLAGS
import resolver_probe as r

RVA, SIZE = 0x847DA1, 203
ENTRY = r.BASE + RVA
MODULES, NAMES = r.BASE + 0x10E0258, r.BASE + 0xE09960
IAT = r.BASE + 0xD9A000
COMPARE = r.BASE + 0x845B53
PREFIXES = (r.BASE + 0xE06E20, r.BASE + 0xE09E5C)
INDICES = (1, 33)
NAME_VALUES = (r.NAME, r.NAME + 128)
require = r.require


def validate(modules, responses):
    require(len(modules) == len(responses) == 2)
    require(all(type(v) is int and 0 <= v <= r.NEG for v in modules))
    require(all(len(row) == 5 and all(type(v) is int and 0 <= v <= r.NEG for v in row)
                for row in responses))


def oracle(modules, responses, length=2):
    """Value/publication policy independent of x86 instruction effects.

    Per module: first load, last-error, two prefix comparisons, retry load.
    All-ones skips. A failed cold attempt publishes all-ones then continues.
    Error87 retries without flags ONLY if BOTH comparisons are nonzero.
    """
    validate(modules, responses)
    require(type(length) is int and 0 <= length <= 2)
    updated, events, value = list(modules), [], 0
    for n in range(length):
        value = modules[n]
        if value == r.NEG:
            value = 0
            continue
        if value:
            break
        first, error, cmp1, cmp2, retry = responses[n]
        name = NAME_VALUES[n]
        events.append(('load', [name, 0, 0x800], 0x847DE5, r.SP-36))
        value = first
        if not first:
            events.append(('error', [], 0x847DF1, r.SP-24))
            if error == 87:
                events.append(('compare', [name, PREFIXES[0], 7], 0x847E03, r.SP-36))
                if cmp1:
                    events.append(('compare', [name, PREFIXES[1], 7], 0x847E17, r.SP-36))
                    if cmp2:
                        events.append(('load', [name, 0, 0], 0x847E27, r.SP-36))
                        value = retry
        updated[n] = value or r.NEG
        if value:
            break
    return dict(events=events, eax=value, esp=r.SP+4, modules=updated)


def exercise(code, modules, responses, length=2, salt=0):
    validate(modules, responses)
    require(type(length) is int and 0 <= length <= 2 and 0 <= salt < 256)
    require(0 < len(code) <= 512)
    instructions = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, ENTRY))
    require(sum(i.size for i in instructions) == len(code))
    starts = {i.address for i in instructions}
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    mutable = MODULES & ~4095
    pages = {ENTRY & ~4095, mutable, NAMES & ~4095, IAT, COMPARE & ~4095,
             r.TRAPS, r.STACK, r.RETURN, r.ARRAY}
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(ENTRY, code)
    module_page = bytearray(b'\x96'*4096)
    for index, value, name in zip(INDICES, modules, NAME_VALUES):
        struct.pack_into('<I', module_page, MODULES+index*4-mutable, value)
        u.mem_write(NAMES+index*4, struct.pack('<I', name))
    u.mem_write(mutable, bytes(module_page))
    u.mem_write(r.ARRAY, struct.pack('<2I', *INDICES))
    u.mem_write(IAT+0x2D4, struct.pack('<I', r.TRAPS))
    u.mem_write(IAT+0x118, struct.pack('<I', r.TRAPS+16))
    # FreeLibrary/race and any other import remain unresolved.
    stack = bytearray(b'\x5a'*4096)
    struct.pack_into('<3I', stack, r.SP-r.STACK, r.RETURN, r.ARRAY, r.ARRAY+4*length)
    u.mem_write(r.STACK, bytes(stack))
    immutable = {p: bytes(u.mem_read(p,4096)) for p in pages if p not in (mutable,r.STACK)}
    initial = [(0x12345678+salt*0x1020304+n*0x112233)&r.NEG for n in range(8)]
    initial[7] = r.SP
    for reg, word in zip(r.REGS, initial):
        u.reg_write(reg, word)
    u.reg_write(UC_X86_REG_EFLAGS, 0x602)
    u.reg_write(UC_X86_REG_EIP, ENTRY)
    events, loads, comparisons, active = [], [0,0], [0,0], None
    for _ in range(600):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN:
            break
        if ip in (r.TRAPS, r.TRAPS+16, COMPARE):
            kind, count, cleanup = {r.TRAPS: ('load',3,12),
                r.TRAPS+16: ('error',0,0), COMPARE: ('compare',3,0)}[ip]
            sp = u.reg_read(UC_X86_REG_ESP)
            ret, *args = struct.unpack('<'+'I'*(count+1), u.mem_read(sp,4*(count+1)))
            events.append((kind,args,ret-r.BASE,sp))
            if kind == 'load':
                require(args[0] in NAME_VALUES)
                active = NAME_VALUES.index(args[0])
                require(active < length and loads[active] < 2)
                value = responses[active][0 if loads[active] == 0 else 4]
                loads[active] += 1
            else:
                require(active is not None)
                if kind == 'error':
                    value = responses[active][1]
                else:
                    require(comparisons[active] < 2)
                    value = responses[active][2+comparisons[active]]
                    comparisons[active] += 1
            u.reg_write(UC_X86_REG_EAX,value)
            u.reg_write(UC_X86_REG_EIP,ret)
            u.reg_write(UC_X86_REG_ESP,sp+4+cleanup)
        else:
            require(ip in starts)
            u.emu_start(ip,r.RETURN,count=1)
    else:
        raise ValueError('instruction budget exceeded')
    require(all(u.reg_read(r.REGS[n]) == initial[n] for n in (1,4,5,6)))
    require(all(bytes(u.mem_read(p,4096)) == before for p,before in immutable.items()))
    # Frame scratch only: no whole-stack oracle or transient write guarantee.
    after = bytes(u.mem_read(r.STACK,4096))
    offset = r.SP-r.STACK
    require(after[:offset-36] == stack[:offset-36] and after[offset:] == stack[offset:])
    updated = [struct.unpack('<I',u.mem_read(MODULES+4*i,4))[0] for i in INDICES]
    for index, value in zip(INDICES,updated):
        struct.pack_into('<I',module_page,MODULES+index*4-mutable,value)
    require(bytes(u.mem_read(mutable,4096)) == bytes(module_page))
    return dict(events=events,eax=u.reg_read(UC_X86_REG_EAX),
                esp=u.reg_read(UC_X86_REG_ESP),modules=updated)


def compare_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'],16) == r.BASE)
    require(int(doc['function']['entryRva'],16) == RVA)
    require(not any(doc['truncation'][k] for k in ('instructions','references','callers','callees')))
    instructions = list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,ENTRY))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(instructions) == 74)
    normalize = lambda s: {'JZ':'JE','JNZ':'JNE'}.get(s.upper(),s.upper())
    for item, ins in zip(items,instructions):
        require(int(item['rva'],16) == ins.address-r.BASE)
        require(normalize(item['text'].split()[0]) == normalize(ins.mnemonic))
    return len(items)


def probe(pe, doc=None):
    code = pe.get_data(RVA,SIZE)
    require(len(code) == SIZE)
    indexed = compare_index(code,doc) if doc is not None else 0
    # Compare failure, each prefix veto, retry success/failure, direct success.
    scenarios = ((r.H1,0,0,0,0), (0,5,1,1,r.H2), (0,87,0,1,r.H2),
                 (0,87,1,0,r.H2), (0,87,1,1,0), (0,87,r.NEG,1,r.H2))
    cases = 0
    for modules, first, second, length, salt in itertools.product(
            itertools.product((0,r.NEG,r.H1),(0,r.NEG,r.H2)),
            scenarios,scenarios,range(3),(0,7)):
        responses = (first,second)
        r.verify(exercise(code,modules,responses,length,salt),oracle(modules,responses,length))
        cases += 1
    # Wrong shared-policy substitutions must not pass merely on final EAX.
    controls = [
        ((0,r.NEG), ((0,87,1,0,r.H1),(0,0,0,0,0)),
         ((0,87,1,1,r.H1),(0,0,0,0,0))),  # missing second prefix veto
        ((0,r.NEG), ((0,87,0,1,r.H1),(0,0,0,0,0)),
         ((0,87,1,1,r.H1),(0,0,0,0,0))),  # missing first prefix veto
        ((0,r.NEG), ((0,5,1,1,r.H1),(0,0,0,0,0)),
         ((0,87,1,1,r.H1),(0,0,0,0,0))),  # retry all errors
    ]
    rejected = 0
    for modules,responses,wrong_responses in controls:
        observed = exercise(code,modules,responses)
        r.verify(observed,oracle(modules,responses))
        try:
            r.verify(observed,oracle(modules,wrong_responses))
        except ValueError:
            rejected += 1
    responses = ((0,5,1,1,r.H1),(r.H2,0,0,0,0))
    wrong = oracle((0,0),responses)
    wrong['modules'][0] = 0  # failed cold attempt must publish all-ones
    observed = exercise(code,(0,0),responses)
    r.verify(observed,oracle((0,0),responses))
    try:
        r.verify(observed,wrong)
    except ValueError:
        rejected += 1
    require(rejected == 4)
    return dict(entryRva=hex(RVA),cases=cases,indexedBoundariesMnemonicsCompared=indexed,
                wrongPolicyModelsRejected=rejected,
                windowsServicesExecuted=False, originalComparatorsExecuted=False,
                racesTested=False,fullStackFlagsVolatileCompared=False,
                arm64Executed=False,startupExecuted=False)


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
    except (OSError,ValueError,KeyError,TypeError,IndexError,struct.error,UcError,pefile.PEFormatError):
        print('Pinned module-acquisition comparison failed; private details suppressed.',file=sys.stderr)
        return 2
    finally:
        if pe is not None:
            pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
