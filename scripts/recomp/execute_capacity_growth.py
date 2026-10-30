#!/usr/bin/env python3
"""Nonempty capacity extension through original chunk linking; NOT Windows.

Fixtures declare two owned 64-byte blocks, never original producer ownership.
All lifted code, original reference states and comparison artifacts stay private.
"""
import argparse
from pathlib import Path
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import execute_capacity_success as capacity
heap = capacity.heap
c = capacity.c
RVA, WRAPPER = heap.RVA, heap.WRAPPER
UNITS = capacity.UNITS
SCHEMA = 'ts2-capacity-growth-native/1'
BEHAVIOUR = '2790/26B0/1AF0 nonempty null-field chunk linking through 831A6F/8461F2'
LIMITS = [
    'Synthetic owned 64-byte descriptor and 64-byte blocking allocation; no original producer/lifetime proof',
    'Nonempty old buffer, null descriptor+4, successful chunk linking only; unknown callees reject',
    'Independent x86 allocation model vs production GuestHeap; NOT Windows HeapAlloc or realloc composition',
    'Eight final GPRs/six pages; not flags/FP/PC/native transient writes',
    'No full capacity/opener/1AB665/E3/E4/global startup/Android/gameplay']
COVERAGE = {'0x2790':13,'0x26b0':26,'0x1af0':48,'0x831a6f':5,'0x8461f2':19}


def state(n):
    regs,pages = capacity.state(n)
    sp = regs['esp']-c.DATA_PAGES[0]
    obj = struct.unpack_from('<I',pages[c.DATA_PAGES[0]],sp+4)[0]
    off = obj-c.DATA_PAGES[1]
    # Header + usable56 bytes fill the explicitly owned old64-byte allocation.
    # Both descriptor cursors point just past this existing payload.
    struct.pack_into('<5I',pages[c.DATA_PAGES[1]],off+0x1d0,
        heap.ARENA,0,heap.ARENA+64,heap.ARENA+64,heap.ARENA+64)
    struct.pack_into('<I',pages[c.DATA_PAGES[1]],off+0xd0,heap.ARENA+8)
    struct.pack_into('<II',pages[heap.ARENA],0,0,56)
    return regs,pages


def model():
    service = heap.HeapModel(1032)
    service.occupied[:16] = [True]*16
    return service


def contract(regs,pages,result,service):
    """Independent chunk link, old-block retention and new-string contract."""
    c.require(service.calls == 1 and service.expected_size == 1032)
    sp = regs['esp']-c.DATA_PAGES[0]
    ret,obj,source = struct.unpack_from('<III',pages[c.DATA_PAGES[0]],sp)
    c.require(ret == c.RETURN)
    off = obj-c.DATA_PAGES[1]
    c.require(struct.unpack_from('<5I',pages[c.DATA_PAGES[1]],off+0x1d0) ==
        (heap.ARENA,0,heap.ARENA+64,heap.ARENA+64,heap.ARENA+64))
    src = source-c.DATA_PAGES[3]
    c.require(0 <= src < 4096)
    end = bytes(pages[c.DATA_PAGES[3]]).find(b'\0',src)
    c.require(end >= src)
    sample = pages[c.DATA_PAGES[3]][src:end+1]
    after = {p:bytearray(b) for p,b in pages.items()}
    raw = heap.ARENA+128
    struct.pack_into('<II',after[heap.ARENA],128,heap.ARENA,1024)
    after[heap.ARENA][136:136+len(sample)] = sample
    struct.pack_into('<I',after[c.DATA_PAGES[1]],off+0xd0,raw+8)
    struct.pack_into('<I',after[c.DATA_PAGES[1]],off+0x1d0,raw)
    struct.pack_into('<III',after[c.DATA_PAGES[1]],off+0x1d8,
        raw+1032,raw+8+len(sample),raw+8+len(sample))
    c.require(result['regs'][0] == 1 and result['regs'][7] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    data = bytes.fromhex(result['pages'])
    c.require(len(data) == len(heap.PAGES)*4096)
    c.require(data[4096:] == b''.join(after[p] for p in heap.PAGES[1:]))


def assemble(bodies,direct_returns,indirect_return):
    return capacity.assemble(bodies,direct_returns,indirect_return)


def bridge_source(mode):
    c.require(mode in capacity.MODES)
    # Seed production ownership independently; allocation never changes bytes.
    text = capacity.bridge_source(mode)
    old = f'    if(!heap) heap=std::make_unique<ts2::GuestHeap>(*memory,0x{heap.HANDLE:08X}u,0x{heap.ARENA:08X}u,4096);'
    setup = f'''    if(!heap) {{
        heap=std::make_unique<ts2::GuestHeap>(*memory,0x{heap.HANDLE:08X}u,0x{heap.ARENA:08X}u,4096);
        if(heap->allocate(0x{heap.HANDLE:08X}u,0,64)!=0x{heap.ARENA:08X}u ||
           heap->allocate(0x{heap.HANDLE:08X}u,0,64)!=0x{heap.ARENA+64:08X}u)
            throw std::runtime_error("ownership setup");
    }}'''
    c.require(text.count(old) == 1)
    return text.replace(old,setup)


def main():
    import json
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    try:
        capacity.run({int(k,16):Path(v) for k,v in json.loads(a.indexes.read_text()).items()},
            a.output,scenario=sys.modules[__name__])
    except Exception:p.exit(1,'Nonempty capacity comparison rejected; inspect private receipt.\n')
    print('Nonempty capacity growth compared host/AArch64; NOT Windows/Android/full closure.')


if __name__ == '__main__':main()
