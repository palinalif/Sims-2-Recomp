#!/usr/bin/env python3
"""Verify pointer-backed spare chunk consumption; no allocator responses.

Descriptor+4 is a linked chunk pointer, NOT an allocator policy selector.
Owned chunk fixtures do not establish original upstream lifetime/ownership.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_capacity_growth as growth
capacity, heap, c = growth.capacity, growth.heap, growth.c
RVA, WRAPPER, UNITS = growth.RVA, growth.WRAPPER, growth.UNITS
SCHEMA = 'ts2-capacity-reuse-native/1'
HELPERS = (Path(growth.__file__),)
SERVICE_BOUNDARY = dict(x86='allocator calls reject', native='allocator calls reject',
                        original_windows_import_executed=False, expected_calls_per_case=0)
BEHAVIOUR = '2790/26B0/1AF0 pointer-backed spare chunk promotion without allocator calls'
LIMITS = [
    'Synthetic owned chunk chain; no original upstream producer/lifetime proof',
    'Nonnull descriptor+4 is a mapped linked chunk pointer, not an allocator selector',
    'No allocation service calls permitted on this path; NOT realloc or Windows heap verification',
    'Eight final GPRs/six pages; not flags/FP/PC/native transient writes',
    'No full capacity/opener/1AB665/E3/E4/global startup/Android/gameplay']
COVERAGE = {'0x2790':13, '0x26b0':26, '0x1af0':24, '0x831a6f':0, '0x8461f2':0}


def state(n):
    regs, pages = growth.state(n)
    sp = regs['esp']-c.DATA_PAGES[0]
    obj = struct.unpack_from('<I', pages[c.DATA_PAGES[0]], sp+4)[0]
    off = obj-c.DATA_PAGES[1]
    # No active chunk: two explicitly owned spare chunks with actual 8-byte
    # link/usable-size headers. Both came from the established chunk layout;
    # no assertion that an original upstream producer made this initial state.
    struct.pack_into('<5I', pages[c.DATA_PAGES[1]], off+0x1d0,
                     0, heap.ARENA, 0, 0, 0)
    struct.pack_into('<II', pages[heap.ARENA], 0, heap.ARENA+64, 56)
    struct.pack_into('<II', pages[heap.ARENA], 64, 0, 56)
    return regs, pages


class NoAllocation:
    target = heap.SERVICE
    calls = 0

    def invoke(self, *args):
        raise ValueError('Unexpected allocator call on spare consumption path')


def model():
    return NoAllocation()


def contract(regs, pages, result, service):
    """Independent spare-chain pop, publication and text-copy contract."""
    c.require(service.calls == 0)
    sp = regs['esp']-c.DATA_PAGES[0]
    ret, obj, source = struct.unpack_from('<III', pages[c.DATA_PAGES[0]], sp)
    c.require(ret == c.RETURN)
    off = obj-c.DATA_PAGES[1]
    c.require(struct.unpack_from('<5I', pages[c.DATA_PAGES[1]], off+0x1d0) ==
              (0, heap.ARENA, 0, 0, 0))
    c.require(struct.unpack_from('<II', pages[heap.ARENA], 0) == (heap.ARENA+64, 56))
    c.require(struct.unpack_from('<II', pages[heap.ARENA], 64) == (0, 56))
    src = source-c.DATA_PAGES[3]
    c.require(0 <= src < 4096)
    end = bytes(pages[c.DATA_PAGES[3]]).find(b'\0', src)
    c.require(src <= end < src+56)
    sample = pages[c.DATA_PAGES[3]][src:end+1]
    after = {p:bytearray(b) for p,b in pages.items()}
    # Pop only the head; clear its link before making it active. The retained
    # second spare, all unused payload and immutable pages must be unchanged.
    struct.pack_into('<I', after[heap.ARENA], 0, 0)
    after[heap.ARENA][8:8+len(sample)] = sample
    struct.pack_into('<I', after[c.DATA_PAGES[1]], off+0xd0, heap.ARENA+8)
    struct.pack_into('<5I', after[c.DATA_PAGES[1]], off+0x1d0,
        heap.ARENA, heap.ARENA+64, heap.ARENA+64,
        heap.ARENA+8+len(sample), heap.ARENA+8+len(sample))
    c.require(len(result['regs']) == 8 and result['regs'][0] == 1)
    c.require(result['regs'][7] == regs['esp']+4)
    for r in ('ebx', 'esi', 'edi', 'ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == len(heap.PAGES)*4096)
    c.require(raw[4096:] == b''.join(after[p] for p in heap.PAGES[1:]))


def assemble(bodies, direct_returns, indirect_return):
    return capacity.assemble(bodies, direct_returns, indirect_return)


def bridge_source(mode):
    c.require(mode in capacity.MODES)
    text = growth.bridge_source('valid' if mode == 'wrong-result' else mode)
    # Reject even a known heap target if the supposedly allocation-free path
    # accidentally reaches it. No native service response can hide that error.
    old = '    heap->invoke_allocate(r);'
    c.require(text.count(old) == 1)
    text = text.replace(old, '    throw std::runtime_error("unexpected allocation");')
    if mode == 'wrong-result':
        old = '    current(s.data());'
        c.require(text.count(old) == 1)
        text = text.replace(old, old+'\n    if(depth==1) s[0]+=8;')
    return text


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        capacity.run({int(k,16):Path(v) for k,v in json.loads(a.indexes.read_text()).items()},
                     a.output, scenario=sys.modules[__name__])
    except Exception:
        p.exit(1, 'Spare chunk comparison rejected; inspect private receipt.\n')
    print('Spare chunk consumption compared host/AArch64; NOT realloc/Android/full closure.')


if __name__ == '__main__':
    main()
