#!/usr/bin/env python3
"""Continuous bounded original-x86 3C50 success reference, NOT native execution.

One CPU/stack/heap from actual entry to sentinel; no saved segment resumption.
Original code, index contents and states stay in ignored work/.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_value_continuation as tail
c, b, value = tail.c, tail.g.b, tail.value
heap = value.heap
calloc = tail.g.p.node.a.calloc
UNITS = {**tail.g.p.node.p.UNITS, **tail.UNITS,
    calloc.RVA:(calloc.SIZE,calloc.COUNT,calloc.PIN),
    calloc.WRAPPER:(calloc.WRAPPER_SIZE,calloc.WRAPPER_COUNT,calloc.WRAPPER_PIN)}
ORDER, EXTRA, SIZE = value.PAGES, tail.g.EXTRA, tail.g.SIZE
# Separate declared corpus: inherited 191-byte case exceeds the fixed4096-step
# bound when run continuously. Never silently retry/drop that original domain.
SOURCE_LENGTHS = (0,1,7,15,31,55,63,127)


class ArenaModel:
    """Independent occupied-cell first-fit service with explicit zero flag.

    No scripted request/response sequence. Guest supplies size/flags; arithmetic
    and ownership determine allocation and zeroing. NOT Windows HeapAlloc.
    """
    target = heap.SERVICE

    def __init__(self):
        self.cells = [False]*(SIZE//8)
        self.requests = []

    def invoke(self, cpu, ids, return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4080 and sp%4 == 0)
        ret, handle, flags, size = struct.unpack('<4I',bytes(cpu.mem_read(sp,16)))
        c.require(ret == return_pc and handle == heap.HANDLE and flags in (0,8))
        c.require(0 < size <= 4096 and len(self.requests) < 16)
        units = (size+7)//8
        start = next((i for i in range(len(self.cells)-units+1)
                      if not any(self.cells[i:i+units])), None)
        c.require(start is not None)
        self.cells[start:start+units] = [True]*units
        address = heap.ARENA+start*8
        if flags == 8:
            cpu.mem_write(address, bytes(units*8))
        cpu.reg_write(ids['eax'], address)
        cpu.reg_write(ids['esp'], sp+16)
        cpu.reg_write(x.UC_X86_REG_EIP, ret)
        self.requests.append((flags,size))


def state(n, mode_page):
    regs,pages = b.state(n)
    c.require(len(mode_page) == 4096 and EXTRA not in pages)
    # Retain the original random prefix, but explicitly terminate this shorter
    # input domain before execution (not a response or mid-execution mutation).
    pages[c.DATA_PAGES[3]][b.t.SOURCE_OFFSET+SOURCE_LENGTHS[n%8]] = 0
    pages[b.MODE_PAGE] = bytearray(mode_page)
    pages[EXTRA] = bytearray([0xa5])*4096
    return regs,pages


def load_units(pe,indexes):
    # The calloc thunk has an original tail JMP, not an ordinary decoded CALL.
    # Reuse the pinned two-hop wrapper decoder, never approximate its return.
    units = {r:u for r,u in UNITS.items() if r != calloc.WRAPPER}
    nodes,code,metadata = b.load_units(pe,indexes,units)
    body = pe.get_data(calloc.WRAPPER,calloc.WRAPPER_SIZE)
    _,ns,flow = heap.decode_wrapper(body,lambda i:i,rva=calloc.WRAPPER,
        size=calloc.WRAPPER_SIZE,count=calloc.WRAPPER_COUNT,
        pin=calloc.WRAPPER_PIN,target=calloc.RVA)
    metadata[hex(calloc.WRAPPER)] = b.crosscheck_index(
        json.loads(indexes[calloc.WRAPPER].read_text()),flow,calloc.WRAPPER)
    c.require(not set(nodes)&set(ns)); nodes.update(ns)
    page = c.BASE+(calloc.WRAPPER//4096)*4096
    code.setdefault(page,bytearray(4096))[calloc.WRAPPER%4096:
        calloc.WRAPPER%4096+len(body)] = body
    return nodes,code,metadata


def advance(regs,pages,nodes,code):
    service = ArenaModel()
    result,seen = c.reference(nodes,code,c.BASE+0x3c50,regs,pages,
        image_pages=b.IMAGES,extra_data_pages=(EXTRA,),budget=4096,
        heap_service=service,checked_repeat_copy=True,
        checked_integer_multiply=True,checked_calloc_arithmetic=True)
    return result,seen,service


def contract(n,regs,pages,result,service):
    """Independent bounded ABI, ownership, key/value/topology and slack subset.

    Not an oracle for all handle bytes, volatile GPRs or stack scratch.
    """
    c.require(type(n) is int and 0 <= n < 64)
    c.require(set(result) == {'regs','pages'} and len(result['regs']) == 8)
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == len(ORDER)*4096)
    after = {p:raw[i*4096:(i+1)*4096] for i,p in enumerate(ORDER)}
    for p in set(ORDER)-{c.DATA_PAGES[0],heap.ARENA,EXTRA}:
        c.require(after[p] == pages[p])
    out = dict(zip(c.REGS,result['regs']))
    c.require(out['eax'] == heap.ARENA and out['esp'] == regs['esp']+4)
    for r in ('ebx','ebp','esi','edi'): c.require(out[r] == regs[r])
    sp = regs['esp']-c.DATA_PAGES[0]
    c.require(after[c.DATA_PAGES[0]][sp:] == pages[c.DATA_PAGES[0]][sp:])
    arena = after[heap.ARENA]+after[EXTRA]
    old = pages[heap.ARENA]+pages[EXTRA]
    word = lambda offset:struct.unpack_from('<I',arena,offset)[0]
    source = pages[c.DATA_PAGES[3]]
    end = source.index(0,b.t.SOURCE_OFFSET)
    sample = source[b.t.SOURCE_OFFSET:end+1]
    text = sum(b.t.opener.REQUESTS)+8
    key = text+len(sample)
    literal = pages[b.MODE_PAGE][b.MODE_TEXT-b.MODE_PAGE:]
    end = literal.index(0)
    c.require(end > 4 and literal[3] == ord('=') and 0 not in literal[:3])
    marker = b.MODE_BYTES[n%8]
    payload_text = literal[4:end]+(bytes([marker]) if marker else b'')
    requests = [(0,s) for s in b.t.REQUESTS]+[(8,256),(8,8),(0,1032),
                                           (0,28),(0,24+len(payload_text))]
    c.require(service.requests == requests)
    used = sum((s+7)//8 for _,s in requests)
    c.require(service.cells == [True]*used+[False]*(SIZE//8-used))
    node = tail.g.p.node.START
    owned = tail.g.p.OCCUPIED+8
    record, payload = value.OCCUPIED,value.OCCUPIED+32
    c.require(arena[text:text+len(sample)] == sample)
    c.require(word(0xd0) == heap.ARENA+text and word(0x204)&255 == marker)
    c.require(word(0x1dc) == heap.ARENA+key and word(0x1e0) == heap.ARENA+key)
    c.require(arena[owned:owned+4] == literal[:3]+b'\0')
    c.require(arena[key:key+end-3] == literal[4:end+1])
    c.require(struct.unpack_from('<II',arena,node) == (heap.ARENA+owned,heap.ARENA+record))
    c.require(word(0x1b0) == heap.ARENA+record)
    c.require(struct.unpack_from('<7I',arena,record) ==
              (heap.ARENA+node,0,0,0,heap.ARENA+payload,len(payload_text),24+len(payload_text)))
    c.require(arena[payload:payload+len(payload_text)] == payload_text)
    slots = sum(b.t.REQUESTS)
    c.require(struct.unpack_from('<3I',arena,0x160) == (heap.ARENA+slots,64,1))
    buckets = struct.unpack_from('<64I',arena,slots)
    c.require(buckets.count(heap.ARENA+node) == 1 and buckets.count(0) == 63)
    c.require(arena[used*8:] == old[used*8:])


def reject_controls(n,regs,pages,result,service):
    kinds = ('eax','esp','ebx','ebp','esi','edi','key','node','head','payload',
             'bucket','cursor','record-size','slack','image','frame')
    for kind in kinds:
        bad = copy.deepcopy(result)
        if kind in c.REGS: bad['regs'][c.REGS.index(kind)] ^= 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            address = {'key':heap.ARENA+tail.g.p.OCCUPIED+8,
                'node':heap.ARENA+tail.g.p.node.START,
                'head':heap.ARENA+0x1b0,
                'bucket':heap.ARENA+sum(b.t.REQUESTS),
                'cursor':heap.ARENA+0x1dc,
                'record-size':heap.ARENA+value.OCCUPIED+24,
                'payload':heap.ARENA+value.OCCUPIED+32,
                'slack':heap.ARENA+SIZE-1}.get(kind)
            if kind == 'image': offset = len(raw)-1
            elif kind == 'frame': offset = regs['esp']-c.DATA_PAGES[0]+4
            else: offset = ORDER.index(address&~4095)*4096+(address&4095)
            raw[offset] ^= 1; bad['pages'] = raw.hex()
        try: contract(n,regs,pages,bad,service)
        except ValueError: continue
        raise ValueError('Continuous reference mutation accepted')
    return len(kinds)


def run(indexes,output):
    output = c.private_output(output)
    # Pin every local Python dependency already loaded, not just the root module.
    sources = {Path(__file__).resolve()}
    directory = Path(__file__).resolve().parent
    for module in tuple(sys.modules.values()):
        path = getattr(module,'__file__',None)
        if path and Path(path).resolve().parent == directory:
            sources.add(Path(path).resolve())
    row = dict(schema='ts2-continuous-opener-reference/1',success=False,stub=False,
        invocation=[sys.executable,*sys.argv],image_sha256=c.IMAGE_SHA,
        source_sha256={str(p):c.digest(p) for p in sources},
        index_sha256={hex(r):c.digest(indexes[r]) for r in UNITS},
        lifted=False,host_native_executed=False,arm64_executed=False,
        android_executed=False,whole_function_verified=False,
        dependencies_newly_resolved=0,
        source_lengths=list(SOURCE_LENGTHS),
        limits=['Continuous original x86 actual3C50 entry to sentinel, fixed single key=value mode; input0..127 bytes',
            'Portable occupied-cell heap MODEL with explicit dirty/zero services, NOT Windows',
            'EFLAGS initialized once0x202; no segment resets; flags/FP/PC/transient writes not compared',
            'Independent ABI/ownership/topology/key/value/slack subset, NOT every handle byte/volatile/scratch',
            'No fresh lift/native host/AArch64/Android/E3/E4/gameplay'])
    results,visited,negative = [],set(),0
    try:
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        nodes,code,row['functions'] = load_units(pe,indexes)
        mode = pe.get_data(b.MODE_PAGE-c.BASE,4096)
        start = time.monotonic()
        for n in range(64):
            regs,pages = state(n,mode)
            result,seen,service = advance(regs,pages,nodes,code)
            contract(n,regs,pages,result,service)
            negative += reject_controls(n,regs,pages,result,service)
            results.append(dict(case=n,initial_regs=regs,
                initial_pages=b''.join(pages[p] for p in ORDER).hex(),
                after=result,service_requests=service.requests))
            visited |= seen
        c.require(c.digest(image) == c.IMAGE_SHA)
        tail.verify_sources(row['source_sha256'])
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row.update(success=True,continuous_reference_cases=64,subset_matches=64,
            negative_controls_rejected=negative,reference_seconds=time.monotonic()-start,
            coverage={hex(r):dict(visited=sum(c.BASE+r<=pc<c.BASE+r+s for pc in visited),total=count)
                      for r,(s,count,_) in UNITS.items()})
    except Exception as exc:
        row.update(error_type=type(exc).__name__,failed_case=locals().get('n'))
        raise
    finally:
        (output/'states.json').write_text(json.dumps(results)+'\n')
        row['states_sha256'] = c.digest(output/'states.json')
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indexes',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    try: run({int(r,16):Path(p) for r,p in json.loads(args.indexes.read_text()).items()},args.output)
    except Exception: parser.exit(1,'Continuous reference rejected; inspect private receipt.\n')
    print('Continuous original-x86 opener reference64/64; NOT native/Android/whole-path verification.')


if __name__ == '__main__': main()
