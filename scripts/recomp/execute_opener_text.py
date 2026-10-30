#!/usr/bin/env python3
"""Compose original 3A50 nonnull text input with actual allocation and producer.

Authored transport/contracts only. Original bodies and reference states stay private.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_opener_success as opener
rig, c, heap = opener.rig, opener.c, opener.heap
ROOT_RVA, RVA, WRAPPER = opener.ROOT_RVA, opener.RVA, opener.WRAPPER
UNITS = {**opener.UNITS, **{r: rig.prefix.UNITS[r] for r in (0x26b0, 0x1af0)}}
REQUESTS = (*opener.REQUESTS, 1032)
SCHEMA = 'ts2-opener-text-success-native/1'
BEHAVIOUR = '3A50 nonnull input through original initialization, 26B0 and 1AF0'
HELPERS = (Path(opener.__file__), *opener.HELPERS)
SERVICE_BOUNDARY = opener.SERVICE_BOUNDARY
LIMITS = [
    '3A50 nonnull input/zero-options success only; four successful allocations',
    'Original allocator caller bodies, independent occupancy model vs production GuestHeap; NOT Windows heap',
    'Text lengths 0..255 sampled; 511-byte exploratory case exceeded unchanged 4096-step x86 bound',
    'No allocation failure, realloc, cleanup, callbacks, process-global startup or general lifetime proof',
    'Eight final GPRs/six full pages vs original x86; independent publication/copy/ABI subset contract',
    'No flags/FP/PC/native transient writes, full opener/1AB665/E3/E4/Android/game startup',
]
# Measured original-x86 path inventory, asserted before native compilation.
COVERAGE = {**opener.COVERAGE, '0x3a50': 124, '0x26b0': 26, '0x1af0': 44}
SOURCE_OFFSET = 128


def state(n):
    regs, pages = opener.state(n)
    rng = random.Random(0x3a5026+n)
    # Include empty nonnull input and bounded short text. No NUL
    # occurs before the terminator; no source byte aliases the owned heap.
    length = (0, 1, 7, 55, 63, 127, 191, 255)[n % 8]
    sample = bytes(rng.randrange(1, 256) for _ in range(length))+b'\0'
    pages[c.DATA_PAGES[3]][SOURCE_OFFSET:SOURCE_OFFSET+len(sample)] = sample
    struct.pack_into('<I', pages[c.DATA_PAGES[0]],
                     regs['esp']-c.DATA_PAGES[0]+4, c.DATA_PAGES[3]+SOURCE_OFFSET)
    return regs, pages


def model():
    return opener.AllocationModel(REQUESTS)


def contract(regs, pages, result, service):
    """Independent bounded ownership/publication/copy and outer ABI subset."""
    c.require(service.calls == len(REQUESTS) and
              sum(service.occupied)*8 == sum(REQUESTS))
    c.require(len(result['regs']) == 8 and result['regs'][0] == heap.ARENA and
              result['regs'][7] == regs['esp']+4)
    for r in ('ebx', 'esi', 'edi', 'ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == len(heap.PAGES)*4096)
    after = {p: raw[i*4096:(i+1)*4096] for i, p in enumerate(heap.PAGES)}
    for p in set(heap.PAGES)-{c.DATA_PAGES[0], heap.ARENA}:
        c.require(after[p] == pages[p])
    arena = after[heap.ARENA]
    word = lambda off: struct.unpack_from('<I', arena, off)[0]
    for off in (0, 4, 0x74, 0xe4, 0xf0):
        c.require(word(off) == 0)
    for off, value in ((0xe8, c.OPENER_MEMBER_TABLE), (0xf4, 1),
            (0x78, heap.ARENA+0x7c), (0xc8, heap.ARENA+0x78),
            (0x7c, c.BASE+0x10970), (0x80, c.BASE+0x109a0),
            (0xb0, c.BASE+0xfcf0)):
        c.require(word(off) == value)
    c.require(arena[0xec:0xf0] == pages[heap.ARENA][0xec:0xf0] and arena[0xc5] == 6)
    source = pages[c.DATA_PAGES[3]]
    end = source.index(0, SOURCE_OFFSET)
    sample = source[SOURCE_OFFSET:end+1]
    chunk = sum(opener.REQUESTS)
    text = heap.ARENA+chunk+8
    c.require(word(0xd0) == text and word(0x1d0) == heap.ARENA+chunk)
    c.require(word(0x1d4) == 0)
    c.require(tuple(word(off) for off in (0x1d8, 0x1dc, 0x1e0)) ==
              (heap.ARENA+sum(REQUESTS), text+len(sample), text+len(sample)))
    c.require(struct.unpack_from('<II', arena, chunk) == (0, 1024))
    c.require(arena[chunk+8:chunk+8+len(sample)] == sample)
    # Writer must preserve all slack in its fresh dirty allocation and all
    # memory beyond the allocated extents, not just the copied text itself.
    c.require(arena[chunk+8+len(sample):] == pages[heap.ARENA][chunk+8+len(sample):])


def assemble(bodies, edges, indirect_return):
    return opener.assemble(bodies, edges, indirect_return, units=UNITS)


def bridge_source(mode):
    return opener.bridge_source(mode, units=UNITS)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        rig.run({int(r, 16): Path(path) for r, path in json.loads(a.indexes.read_text()).items()},
                a.output, scenario=sys.modules[__name__])
    except Exception:
        p.exit(1, 'Opener text comparison rejected; inspect private receipt.\n')
    print('3A50 text success compared host/Linux-AArch64; NOT full opener or Android.')


if __name__ == '__main__':
    main()
