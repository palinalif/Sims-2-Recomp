#!/usr/bin/env python3
"""Bounded selector/cold resolver/module reference; development only.

Original bodies and states remain private. API/guard/storage/comparison replies
are authored, NOT Windows. Cold volatile registers/flags/scratch are unverified.
"""
import argparse
import itertools
import json
from pathlib import Path
import struct
import sys
import time

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_32
from unicorn.x86_const import UC_X86_REG_EIP, UC_X86_REG_EFLAGS
import encoded_resolver_composed_probe as cold
import ptd_query_probe as query

r, c, m = cold.r, cold.c, cold.m
require = r.require
LOAD, ERROR, EXPORT = (r.TRAPS+n for n in (128,144,160))
BODIES = ((query.ENTRY,query.SIZE),(c.ENTRY,c.SIZE),(m.ENTRY,m.SIZE),
          (cold.ENCODER,cold.ENCODER_SIZE))


def oracle(cookie, modules, responses, export, result, index):
    require(export in (0,query.FLS) and type(result) is int and 0 <= result <= r.NEG)
    query.free.inputs(index,0)  # Validate caller's storage index independently.
    acquired = cold.oracle(cookie,modules,responses,export)
    target = acquired['eax']
    events = [('resolve',[33,query.NAME,query.BEGIN,query.END],0x8480DB,r.SP-28)]
    for kind,args,ret,sp in acquired['events']:
        if kind == 'export': args = [args[0],query.NAME]
        events.append((kind,args,ret,sp-28))
    if target:
        events += [('guard',[],0x8480EF,r.SP-16),
                   ('fls',[index],0x8480F1,r.SP-16)]
    else:
        events += [('tls',[index],r.RETURN-r.BASE,r.SP)]
    return dict(eax=result,esp=r.SP+8,modules=acquired['modules'],
                cache=acquired['cache'],events=events)


def exercise(codes,cookie,modules,responses,export,result,index,salt=0,*,
             provider_pop=4,budget=1000):
    oracle(cookie,modules,responses,export,result,index)  # Input validation only.
    require(set(codes) == {a for a,_ in BODIES} and provider_pop in (0,4))
    require(type(budget) is int and 0 < budget <= 1000)
    starts = set()
    for address,size in BODIES:
        code = codes[address]
        require(0 < len(code) <= (256 if address == c.ENTRY else size))
        decoded = list(Cs(CS_ARCH_X86,CS_MODE_32).disasm(code,address))
        require(sum(i.size for i in decoded) == len(code))
        starts.update(i.address for i in decoded)
    regs,stack = query.free.inputs(index,salt)
    u = Uc(UC_ARCH_X86,UC_MODE_32)
    mutable = m.MODULES & ~4095
    pages = {a & ~4095 for a,_ in BODIES} | {mutable,c.COOKIE & ~4095,
        m.NAMES & ~4095,m.IAT,m.COMPARE & ~4095,r.TRAPS,r.STACK,r.RETURN,
        query.BEGIN & ~4095}
    for page in pages: u.mem_map(page,4096)
    for address,code in codes.items(): u.mem_write(address,code)
    u.mem_write(c.COOKIE,struct.pack('<I',cookie))
    page = bytearray(b'\x96'*4096)
    for slot,value,name in zip(m.INDICES,modules,m.NAME_VALUES):
        struct.pack_into('<I',page,m.MODULES+4*slot-mutable,value)
        u.mem_write(m.NAMES+4*slot,struct.pack('<I',name))
    struct.pack_into('<I',page,c.CACHE+4*33-mutable,c.encode(0,cookie))
    u.mem_write(mutable,bytes(page))
    u.mem_write(query.BEGIN,struct.pack('<2I',*m.INDICES))
    for address,target in ((m.IAT+0x2D4,LOAD),(m.IAT+0x118,ERROR),
            (m.IAT+0x124,EXPORT),(query.GUARD_SLOT,query.GUARD),
            (query.TLS_SLOT,query.TLS)):
        u.mem_write(address,struct.pack('<I',target))
    u.mem_write(r.STACK,bytes(stack))
    immutable = {p:bytes(u.mem_read(p,4096)) for p in pages if p not in (mutable,r.STACK)}
    for reg,value in zip(r.REGS,regs): u.reg_write(reg,value)
    u.reg_write(UC_X86_REG_EFLAGS,0xCD7)
    u.reg_write(UC_X86_REG_EIP,query.ENTRY)
    events,loads,comparisons,active = [],[0,0],[0,0],None
    entered = {a:0 for a,_ in BODIES}
    endpoints = {LOAD:('load',3,12),ERROR:('error',0,0),EXPORT:('export',2,8),
        m.COMPARE:('compare',3,0),query.GUARD:('guard',0,0),
        query.FLS:('fls',1,provider_pop),query.TLS:('tls',1,provider_pop)}
    for _ in range(budget):
        ip = u.reg_read(UC_X86_REG_EIP)
        if ip == r.RETURN: break
        if ip in entered: entered[ip] += 1
        if ip == c.ENTRY or ip in endpoints:
            kind,count,cleanup = ('resolve',4,0) if ip == c.ENTRY else endpoints[ip]
            sp = u.reg_read(r.REGS[7])
            ret,*args = struct.unpack('<'+'I'*(count+1),u.mem_read(sp,4*(count+1)))
            require(len(events) < 15)
            events.append((kind,args,ret-r.BASE,sp))
            if ip != c.ENTRY:
                if kind == 'load':
                    require(args[0] in m.NAME_VALUES)
                    active = m.NAME_VALUES.index(args[0])
                    require(loads[active] < 2)
                    value = responses[active][0 if loads[active] == 0 else 4]
                    loads[active] += 1
                elif kind == 'export': value = export
                elif kind in ('guard','fls','tls'):
                    if kind != 'tls': require(u.reg_read(r.REGS[2]) == query.FLS)
                    value = u.reg_read(r.REGS[0]) if kind == 'guard' else result
                else:
                    require(active is not None)
                    if kind == 'error': value = responses[active][1]
                    else:
                        require(comparisons[active] < 2)
                        value = responses[active][2+comparisons[active]]
                        comparisons[active] += 1
                u.reg_write(r.REGS[0],value)
                u.reg_write(r.REGS[7],sp+4+cleanup)
                u.reg_write(UC_X86_REG_EIP,ret)
                continue
        require(ip in starts)
        u.emu_start(ip,r.RETURN,count=1)
    else: raise ValueError('instruction budget exceeded')
    # These must be actual nested bodies, never opaque value-only endpoints.
    require(all(entered[a] == 1 for a in (query.ENTRY,c.ENTRY,m.ENTRY)))
    require(entered[cold.ENCODER] <= 1)  # Failure may publish sentinel without a CALL.
    require(all(u.reg_read(r.REGS[n]) == regs[n] for n in (1,4,5,6)))
    require(all(bytes(u.mem_read(p,4096)) == before for p,before in immutable.items()))
    after = bytes(u.mem_read(r.STACK,4096)); offset = r.SP-r.STACK
    require(after[:offset-92] == stack[:offset-92] and after[offset:] == stack[offset:])
    updated = [struct.unpack('<I',u.mem_read(m.MODULES+4*i,4))[0] for i in m.INDICES]
    cached = struct.unpack('<I',u.mem_read(c.CACHE+4*33,4))[0]
    for slot,value in zip(m.INDICES,updated):
        struct.pack_into('<I',page,m.MODULES+4*slot-mutable,value)
    struct.pack_into('<I',page,c.CACHE+4*33-mutable,cached)
    require(bytes(u.mem_read(mutable,4096)) == bytes(page))
    return dict(eax=u.reg_read(r.REGS[0]),esp=u.reg_read(r.REGS[7]),
                modules=updated,cache=cached,events=events)


def cases():
    scenarios = ((r.H1,0,0,0,0),(0,5,1,1,r.H2),(0,87,0,1,r.H2),
                 (0,87,1,0,r.H2),(0,87,1,1,r.H2),(0,87,1,1,0))
    for modules,a,b,export,result,index in itertools.product(
            ((0,0),(r.NEG,0),(r.H1,0),(0,r.H2),(r.NEG,r.NEG)),
            scenarios,scenarios,(0,query.FLS),(0,0x80000000),(0,r.NEG)):
        yield 0x12345678,modules,(a,b),export,result,index,7
    for count,index in itertools.product(range(32),(0,r.NEG)):
        yield 0x12345660|count,(0,0),((0,87,1,1,r.H1),(r.H2,0,0,0,0)),query.FLS,r.NEG,index,0


def probe(pe,docs=(None,None,None)):
    start = time.monotonic()
    codes = {a:pe.get_data(a-r.BASE,size) for a,size in BODIES}
    require(all(len(codes[a]) == size for a,size in BODIES))
    require(len(docs) == 3)
    indexed = [p.compare_index(codes[p.ENTRY],doc) if doc is not None else 0
               for p,doc in zip((query,c,m),docs)]
    count = 0
    for cookie,modules,responses,export,result,index,salt in cases():
        r.verify(exercise(codes,cookie,modules,responses,export,result,index,salt),
                 oracle(cookie,modules,responses,export,result,index))
        count += 1
    rejected = 0
    args = (31,(r.H1,0),((0,0,0,0,0),)*2,query.FLS,1,0)
    for dynamic in (True,False):
        variant = list(args); variant[3] = query.FLS if dynamic else 0
        actual = exercise(codes,*variant)
        wrong = dict(actual); wrong['cache'] ^= 1
        try: r.verify(actual,wrong)
        except ValueError: rejected += 1
        try: r.verify(exercise(codes,*variant,provider_pop=0),oracle(*variant))
        except (ValueError,UcError): rejected += 1
    require(rejected == 4)
    return dict(cases=count,originalReferenceBodies=4,selectedBodies=3,
        indexedBoundariesMnemonicsCompared=indexed,seconds=time.monotonic()-start,
        encoderReferenceOnly=True,rejectedControls=rejected,
        compared=['EAX/ESP/nonvolatiles','ordered endpoint args/returnRva/SP',
                  'module/cache page','immutable pages/stack outside92-byte scratch'],
        fullColdVolatileFlagsScratchCompared=False,nativeCompared=False,
        windowsServicesExecuted=False,runtimeBound=False,androidExecuted=False,startupExecuted=False)


def load_index(path):
    require(path.stat().st_size <= 1024*1024)
    doc = json.loads(path.read_text())
    require(doc['schema'] == 'sims2-ghidra-query-envelope/1')
    provenance = doc['provenance']
    require(provenance['sourceImageSha256'] == r.PIN and
            provenance['mode'] == 'readOnly' and provenance['analysisPerformed'] is False and
            type(provenance['headlessExitCode']) is int and provenance['headlessExitCode'] == 0 and
            provenance['outputParseError'] is None)
    return doc['result']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selector','resolver','module'):
        parser.add_argument('--'+name+'-index',type=Path)
    args = parser.parse_args(argv)
    pe = None
    try:
        docs = []
        for path in (args.selector_index,args.resolver_index,args.module_index):
            docs.append(load_index(path) if path is not None else None)
        pe = r.load_image()
        print(json.dumps(probe(pe,docs),sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,IndexError,struct.error,UcError,query.pefile.PEFormatError):
        print('Pinned cold storage composition failed; private details suppressed.',file=sys.stderr)
        return 2
    finally:
        if pe is not None: pe.close()


if __name__ == '__main__': raise SystemExit(main())
