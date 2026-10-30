#!/usr/bin/env python3
"""Development-only actual cold resolver/acquisition/encoding composition.

Private pinned bodies; APIs and comparisons are authored responses. Counts/RVAs
only. No Windows services, full CPU ABI, concurrency, ownership or startup proof.
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
import encoded_cache_probe as c
import module_acquisition_probe as m
r = c.r
require = r.require
ENCODER, ENCODER_SIZE = r.BASE+0x82F3EC, 31


def oracle(cookie, modules, responses, export, length=2):
    require(type(cookie) is int and 0 <= cookie <= r.NEG)
    require(type(export) is int and 0 <= export < r.NEG)
    acquired = m.oracle(modules, responses, length)
    # Resolver saves four words, pushes two range pointers, then CALLs helper.
    events = [(kind,args,ret,sp-28) for kind,args,ret,sp in acquired['events']]
    value = export if acquired['eax'] else 0
    if acquired['eax']:
        events.append(('export',[acquired['eax'],r.NAME],0x847EC0,r.SP-28))
    return dict(events=events, eax=value, esp=r.SP+4,
                modules=acquired['modules'], cache=c.encode(value or r.NEG,cookie))


def exercise(resolver, helper, encoder, cookie, modules, responses, export,
             length=2, index=33, salt=0, *, reenter=True):
    expected = oracle(cookie,modules,responses,export,length)  # Validate inputs only.
    regs, stack = c.inputs(index,salt)
    struct.pack_into('<I',stack,r.SP-r.STACK+16,r.ARRAY+4*length)
    bodies = ((c.ENTRY,resolver,256),(m.ENTRY,helper,512),(ENCODER,encoder,64))
    starts = set()
    for address, code, limit in bodies:
        require(0 < len(code) <= limit)
        decoded = list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,address))
        require(sum(i.size for i in decoded) == len(code))
        starts.update(i.address for i in decoded)
    u = Uc(UC_ARCH_X86,UC_MODE_32)
    mutable = m.MODULES & ~4095  # The encoded function cache shares this page.
    pages = {a & ~4095 for a,_,_ in bodies} | {mutable,c.COOKIE & ~4095,
             m.NAMES & ~4095,m.IAT,m.COMPARE & ~4095,r.TRAPS,r.STACK,r.RETURN,r.ARRAY}
    for page in pages: u.mem_map(page,4096)
    for address,code,_ in bodies: u.mem_write(address,code)
    u.mem_write(c.COOKIE,struct.pack('<I',cookie))
    page = bytearray(b'\x96'*4096)
    for slot,value,name in zip(m.INDICES,modules,m.NAME_VALUES):
        struct.pack_into('<I',page,m.MODULES+4*slot-mutable,value)
        u.mem_write(m.NAMES+4*slot,struct.pack('<I',name))
    struct.pack_into('<I',page,c.CACHE+4*index-mutable,c.encode(0,cookie))
    u.mem_write(mutable,bytes(page))
    u.mem_write(r.ARRAY,struct.pack('<2I',*m.INDICES))
    for offset,target in ((0x2D4,r.TRAPS),(0x118,r.TRAPS+16),(0x124,r.TRAPS+32)):
        u.mem_write(m.IAT+offset,struct.pack('<I',target))
    immutable = {p:bytes(u.mem_read(p,4096)) for p in pages if p not in (mutable,r.STACK)}
    events,loads,comparisons,active = [],[0,0],[0,0],None

    def reset():
        u.mem_write(r.STACK,bytes(stack))
        for reg,word in zip(r.REGS,regs): u.reg_write(reg,word)
        u.reg_write(UC_X86_REG_EFLAGS,0x602)
        u.reg_write(UC_X86_REG_EIP,c.ENTRY)

    reset()
    for _ in range(1000):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN: break
        if ip in (r.TRAPS,r.TRAPS+16,r.TRAPS+32,m.COMPARE):
            kind,count,cleanup = {r.TRAPS:('load',3,12),r.TRAPS+16:('error',0,0),
                r.TRAPS+32:('export',2,8),m.COMPARE:('compare',3,0)}[ip]
            sp = u.reg_read(UC_X86_REG_ESP)
            ret,*args = struct.unpack('<'+'I'*(count+1),u.mem_read(sp,4*(count+1)))
            events.append((kind,args,ret-r.BASE,sp))
            if kind == 'load':
                require(args[0] in m.NAME_VALUES)
                active = m.NAME_VALUES.index(args[0])
                require(active < length and loads[active] < 2)
                value = responses[active][0 if loads[active] == 0 else 4]
                loads[active] += 1
            elif kind == 'export': value = export
            else:
                require(active is not None)
                if kind == 'error': value = responses[active][1]
                else:
                    require(comparisons[active] < 2)
                    value = responses[active][2+comparisons[active]]
                    comparisons[active] += 1
            u.reg_write(UC_X86_REG_EAX,value)
            u.reg_write(UC_X86_REG_ESP,sp+4+cleanup)
            u.reg_write(UC_X86_REG_EIP,ret)
        else:
            require(ip in starts)
            u.emu_start(ip,r.RETURN,count=1)
    else: raise ValueError('instruction budget exceeded')
    require(all(u.reg_read(r.REGS[n]) == regs[n] for n in (1,4,5,6)))
    require(all(bytes(u.mem_read(p,4096)) == before for p,before in immutable.items()))
    after = bytes(u.mem_read(r.STACK,4096)); offset = r.SP-r.STACK
    # Lowest observed nested frame is helper SP-36, itself entered at SP-28.
    require(after[:offset-64] == stack[:offset-64] and after[offset:] == stack[offset:])
    updated = [struct.unpack('<I',u.mem_read(m.MODULES+4*i,4))[0] for i in m.INDICES]
    cached = struct.unpack('<I',u.mem_read(c.CACHE+4*index,4))[0]
    for slot,value in zip(m.INDICES,updated):
        struct.pack_into('<I',page,m.MODULES+4*slot-mutable,value)
    struct.pack_into('<I',page,c.CACHE+4*index-mutable,cached)
    require(bytes(u.mem_read(mutable,4096)) == bytes(page))
    observed = dict(events=events,eax=u.reg_read(UC_X86_REG_EAX),
                    esp=u.reg_read(UC_X86_REG_ESP),modules=updated,cache=cached)
    if reenter:
        # Keep the SAME cache; remove cold dependencies and reset only CPU/stack.
        u.mem_unmap(r.ARRAY,4096); u.mem_unmap(m.NAMES & ~4095,4096)
        u.mem_unmap(m.IAT,4096)
        reset()
        hot_starts = {i.address for i in Cs(CS_ARCH_X86,CS_MODE_32).disasm(resolver,c.ENTRY)}
        for _ in range(100):
            ip = u.reg_read(UC_X86_REG_EIP)
            if ip == r.RETURN: break
            require(ip in hot_starts)
            u.emu_start(ip,r.RETURN,count=1)
        else: raise ValueError('hot instruction budget exceeded')
        hot = dict(registers=[u.reg_read(reg) for reg in r.REGS],
                   flags=u.reg_read(UC_X86_REG_EFLAGS)&c.MASK,
                   stack=bytes(u.mem_read(r.STACK,4096)))
        # Empty/truncated ranges retain their original caller input on reentry.
        hot_expected = c.oracle(expected['eax'] or r.NEG,cookie,index,salt)
        hot_stack = bytearray(hot_expected['stack'])
        struct.pack_into('<I',hot_stack,offset+16,r.ARRAY+4*length)
        hot_expected['stack'] = bytes(hot_stack)
        r.verify(hot,hot_expected)
        require(bytes(u.mem_read(mutable,4096)) == bytes(page))
        removed = {r.ARRAY,m.NAMES & ~4095,m.IAT}
        require(all(bytes(u.mem_read(p,4096)) == before
                    for p,before in immutable.items() if p not in removed))
    return observed


def compare_encoder_index(code, doc):
    require(doc['program']['executableSha256'].lower() == r.PIN)
    require(int(doc['program']['imageBaseVa'],16) == r.BASE)
    require(int(doc['function']['entryRva'],16) == ENCODER-r.BASE)
    require(not any(doc['truncation'][k] for k in ('instructions','references','callers','callees')))
    decoded = list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,ENCODER))
    items = doc['function']['disassembly']['items']
    require(len(items) == len(decoded) == 13)
    for item,ins in zip(items,decoded):
        require(int(item['rva'],16) == ins.address-r.BASE)
        require(item['text'].split()[0].lower() == ins.mnemonic)
    return len(items)


def probe(pe, doc=None):
    bodies = (pe.get_data(c.RVA,c.SIZE),pe.get_data(m.RVA,m.SIZE),
              pe.get_data(ENCODER-r.BASE,ENCODER_SIZE))
    require(tuple(map(len,bodies)) == (c.SIZE,m.SIZE,ENCODER_SIZE))
    indexed = compare_encoder_index(bodies[2],doc) if doc is not None else 0
    scenarios = ((r.H1,0,0,0,0),(0,5,1,1,r.H2),(0,87,0,1,r.H2),
                 (0,87,1,0,r.H2),(0,87,1,1,r.H2),(0,87,1,1,0))
    cases = 0
    for cookie,modules,a,b,export,length in itertools.product(
            (0,1,31,0x12345678,r.NEG),((0,0),(r.NEG,0),(r.H1,0),(0,r.H2),(r.NEG,r.NEG)),
            scenarios,scenarios,(0,0x80000000),range(3)):
        responses = (a,b)
        r.verify(exercise(*bodies,cookie,modules,responses,export,length),
                 oracle(cookie,modules,responses,export,length))
        cases += 1
    # Exercise every rotation count with edge indices and varied incoming state.
    for count,index,salt,export in itertools.product(range(32),(0,63),(0,7),(0,0x80000001)):
        cookie = 0x12345660 | count
        responses = ((0,87,1,1,r.H1),(r.H2,0,0,0,0))
        r.verify(exercise(*bodies,cookie,(0,0),responses,export,index=index,salt=salt),
                 oracle(cookie,(0,0),responses,export))
        cases += 1
    # Reject policy substitutions against executed original bodies, not self-match.
    cookie,modules,responses = 31,(r.H1,0),((0,0,0,0,0),)*2
    observed = exercise(*bodies,cookie,modules,responses,0)
    wrong = []
    for replacement in (0,r.NEG,c.encode(0,cookie)):
        model = oracle(cookie,modules,responses,0)
        model['cache'] = replacement
        wrong.append(model)
    model = oracle(cookie,modules,responses,0)
    model['modules'][1] = r.H2  # Export failure must not load the next module.
    wrong.append(model)
    rejected = 0
    for model in wrong:
        try: r.verify(observed,model)
        except ValueError: rejected += 1
    require(rejected == 4)
    return dict(resolverRva=hex(c.RVA),moduleHelperRva=hex(m.RVA),encoderRva=hex(ENCODER-r.BASE),
                cases=cases,sameMemoryReentries=cases+1,wrongPolicyModelsRejected=rejected,
                indexedEncoderBoundariesCompared=indexed,
                windowsServicesExecuted=False,originalComparatorsExecuted=False,
                fullColdStackFlagsVolatileCompared=False,racesTested=False,
                arm64Executed=False,startupExecuted=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--encoder-index',type=Path)
    args = parser.parse_args(argv)
    pe = None
    try:
        doc = None
        if args.encoder_index is not None:
            require(args.encoder_index.stat().st_size <= 1024*1024)
            doc = json.loads(args.encoder_index.read_text())
        pe = r.load_image()
        print(json.dumps(probe(pe,doc),sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,struct.error,UcError,pefile.PEFormatError):
        print('Pinned encoded resolver composition failed; private details suppressed.',file=sys.stderr)
        return 2
    finally:
        if pe is not None: pe.close()


if __name__ == '__main__': raise SystemExit(main())
