#!/usr/bin/env python3
"""Compose owned-empty capacity growth with original realloc; NOT Windows.

Synthetic ownership is explicit, not evidence of original producer/lifetime.
Generated bodies and reference states are restricted to ignored work/.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_capacity_growth as growth
import execute_reallocate_success as realloc
capacity, heap, c = growth.capacity, growth.heap, growth.c
RVA, WRAPPER = realloc.RVA, realloc.WRAPPER
UNITS = {**capacity.prefix.UNITS,
         WRAPPER: (11, 5, realloc.WRAPPER_PIN),
         RVA: (realloc.SIZE, realloc.COUNT, realloc.PIN)}
SCHEMA = 'ts2-capacity-reallocate-native/1'
HELPERS = (Path(growth.__file__), Path(realloc.__file__))
SERVICE_BOUNDARY = dict(x86='independent realloc occupancy/copy model',
    native='production GuestHeap reallocate', expected_calls_per_case=1,
    original_windows_import_executed=False)
BEHAVIOUR = '2790/26B0/1AF0 owned-empty chunk growth through 8413B0/85217F'
LIMITS = [
    'Synthetic empty owned 64-byte chunk and blocking allocation; no original producer/lifetime proof',
    'Successful moving realloc only, with explicit flags0 portable service; NOT Windows HeapReAlloc',
    'Eight final GPRs/six pages; not flags/FP/PC/native transient stores',
    'No full capacity/openers/1AB665/E3/E4/global startup/Android/gameplay']
COVERAGE = {'0x2790':13, '0x26b0':26, '0x1af0':42, '0x8413b0':5, '0x85217f':25}


def state(n):
    regs, pages = growth.state(n)
    sp = regs['esp']-c.DATA_PAGES[0]
    _, obj, source = struct.unpack_from('<III', pages[c.DATA_PAGES[0]], sp)
    off = obj-c.DATA_PAGES[1]
    # Empty active chunk: published start and both cursors equal active+8.
    struct.pack_into('<5I', pages[c.DATA_PAGES[1]], off+0x1d0,
                     heap.ARENA, 0, heap.ARENA+64, heap.ARENA+8, heap.ARENA+8)
    src = source-c.DATA_PAGES[3]
    sample = bytes(65+(i+n)%26 for i in range(64+n%32))+b'\0'
    pages[c.DATA_PAGES[3]][src:src+len(sample)] = sample
    struct.pack_into('<I', pages[heap.IMAGES[0]], realloc.IAT-heap.IMAGES[0], heap.SERVICE)
    return regs, pages


def model():
    return realloc.ReallocateModel(120)


def contract(regs, pages, result, service):
    """Independent moved-chunk publication, header, text and retention check."""
    c.require(service.calls == 1 and service.expected_size == 120)
    sp = regs['esp']-c.DATA_PAGES[0]
    ret, obj, source = struct.unpack_from('<III', pages[c.DATA_PAGES[0]], sp)
    c.require(ret == c.RETURN)
    off = obj-c.DATA_PAGES[1]
    c.require(struct.unpack_from('<5I', pages[c.DATA_PAGES[1]], off+0x1d0) ==
              (heap.ARENA, 0, heap.ARENA+64, heap.ARENA+8, heap.ARENA+8))
    src = source-c.DATA_PAGES[3]
    c.require(0 <= src < 4096)
    end = bytes(pages[c.DATA_PAGES[3]]).find(b'\0', src)
    c.require(src+64 <= end < src+96)
    sample = pages[c.DATA_PAGES[3]][src:end+1]
    after = {p:bytearray(b) for p,b in pages.items()}
    raw = heap.ARENA+128
    # The original writer fills the old usable region before asking for growth.
    # Realloc preserves that prefix; the caller resumes copying at its end.
    after[heap.ARENA][8:64] = sample[:56]
    after[heap.ARENA][128:192] = after[heap.ARENA][:64]
    struct.pack_into('<II', after[heap.ARENA], 128, 0, 112)
    after[heap.ARENA][136:136+len(sample)] = sample
    struct.pack_into('<I', after[c.DATA_PAGES[1]], off+0xd0, raw+8)
    struct.pack_into('<5I', after[c.DATA_PAGES[1]], off+0x1d0,
                     raw, 0, raw+120, raw+8+len(sample), raw+8+len(sample))
    c.require(len(result['regs']) == 8 and result['regs'][0] == 1)
    c.require(result['regs'][7] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    data = bytes.fromhex(result['pages'])
    c.require(len(data) == len(heap.PAGES)*4096)
    c.require(data[4096:] == b''.join(after[p] for p in heap.PAGES[1:]))


def assemble(bodies, direct_returns, indirect_return):
    return capacity.assemble(bodies, direct_returns, indirect_return,
                             units=UNITS, tail_wrapper=WRAPPER, tail_body=RVA)


def bridge_source(mode):
    c.require(mode in capacity.MODES)
    text = growth.bridge_source(mode)
    old = 'heap->invoke_allocate(r);'
    c.require(text.count(old) == 1)
    text = text.replace(old, 'heap->invoke_reallocate(r);')
    old = 'constexpr std::array<uint32_t,6> targets{'+','.join(
        f'0x{a:08X}u' for a in [c.BASE+r for r in capacity.UNITS]+[heap.SERVICE])+'};'
    targets = [c.BASE+r for r in UNITS]+[heap.SERVICE]
    c.require(text.count(old) == 1)
    return text.replace(old, f'constexpr std::array<uint32_t,{len(targets)}> targets{{'+
                        ','.join(f'0x{a:08X}u' for a in targets)+'};')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        capacity.run({int(k,16):Path(v) for k,v in json.loads(a.indexes.read_text()).items()},
                     a.output, scenario=sys.modules[__name__])
    except Exception:
        p.exit(1, 'Capacity realloc comparison rejected; inspect private receipt.\n')
    print('Capacity realloc compared host/Linux-AArch64; NOT Windows/Android/full closure.')


if __name__ == '__main__':
    main()
