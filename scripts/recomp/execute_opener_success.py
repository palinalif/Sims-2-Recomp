#!/usr/bin/env python3
"""Compose original 3A50 null-input success with real initialization/heap callees.

Authored transport only; generated bodies and reference states remain private.
This bounded domain excludes text input, allocation failure and teardown.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_capacity_success as rig
import execute_opener_init as init
import execute_initialization_producer as producer
c, heap = rig.c, rig.heap
ROOT_RVA = 0x3a50
RVA, WRAPPER = heap.RVA, heap.WRAPPER
UNITS = {
    ROOT_RVA: (508, 137, 'f1033a0d3c7405cd2aa6b7db0243540f24a542b29c8098613dff88265787e2b8'),
    heap.WRAPPER: (heap.WRAPPER_SIZE, heap.WRAPPER_COUNT, heap.WRAPPER_PIN),
    heap.RVA: (heap.SIZE, heap.COUNT, heap.PIN),
    **init.UNITS,
    c.OPENER_MEMBER: (25, 5, c.OPENER_MEMBER_SHA),
    c.DESCRIPTOR: (6, 2, c.DESCRIPTOR_SHA),
    producer.RVA: (producer.SIZE, producer.COUNT, producer.FUNCTION_SHA),
    c.CLASSIFIER: (49, 21, c.CLASSIFIER_SHA),
}
SCHEMA = 'ts2-opener-null-success-native/1'
BEHAVIOUR = '3A50 null-input success through three real allocations and initialization callees'
LIMITS = [
    '3A50 null-input/zero-options success only; three successful allocations',
    'Original 26B0/27D0, text input, failure, callbacks and teardown NOT executed',
    'Independent occupancy model vs production GuestHeap, NOT Windows HeapAlloc',
    'Synthetic immutable IAT/global/token and owned arena, NOT startup/lifetime proof',
    'Eight final GPRs/six full pages vs x86; independent publication/ABI subset contract',
    'No flags/FP/PC/native transient-write comparison or whole-function path coverage',
    'No 1AB665/E3/E4 production integration, Android or game startup evidence',
]
HELPERS = (Path(init.__file__), Path(producer.__file__))
SERVICE_BOUNDARY = dict(target=hex(heap.SERVICE), x86='independent persistent occupancy model',
    native='production GuestHeap', original_windows_import_executed=False)
# Exact null-input success path, measured independently on original x86.
COVERAGE = {hex(r): count for r, count in (
    (ROOT_RVA, 119), (heap.WRAPPER, 5), (heap.RVA, 19),
    (init.ROOT_RVA, 18), (c.ZERO_INIT, 7), (c.BUFFER_INIT, 6),
    (c.OPENER_MEMBER, 5), (c.DESCRIPTOR, 2), (producer.RVA, 16),
    (c.CLASSIFIER, 4))}
REQUESTS = (528, 256, 1024)


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random(0x3a5000+n)
    regs = {r: rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    pages = {p: bytearray(rng.randbytes(4096)) for p in heap.PAGES}
    # Arguments are explicit null input/zero options, not behavior responses.
    struct.pack_into('<8I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0],
                     c.RETURN, *([0]*7))
    struct.pack_into('<I', pages[heap.IMAGES[0]], heap.IAT-heap.IMAGES[0], heap.SERVICE)
    struct.pack_into('<I', pages[heap.IMAGES[1]], heap.GLOBAL-heap.IMAGES[1], heap.HANDLE)
    return regs, pages


class AllocationModel:
    """Unit occupancy, persistent across the three real allocation calls."""
    target = heap.SERVICE

    def __init__(self, requests=REQUESTS):
        c.require(type(requests) is tuple and requests and
                  all(type(size) is int and 0 < size <= 4096 for size in requests))
        self.requests = requests
        self.occupied = [False]*512
        self.calls = 0

    def invoke(self, cpu, ids, return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4096-16 and sp % 4 == 0)
        ret, handle, flags, size = struct.unpack('<4I', bytes(cpu.mem_read(sp, 16)))
        c.require(ret == return_pc and handle == heap.HANDLE and flags == 0)
        c.require(self.calls < len(self.requests) and size == self.requests[self.calls])
        count = (size+7)//8
        start = next((i for i in range(513-count) if not any(self.occupied[i:i+count])), None)
        c.require(start is not None)
        self.occupied[start:start+count] = [True]*count
        cpu.reg_write(ids['eax'], heap.ARENA+start*8)
        cpu.reg_write(ids['esp'], sp+16)
        cpu.reg_write(x.UC_X86_REG_EIP, ret)
        self.calls += 1


def model():
    return AllocationModel()


def contract(regs, pages, result, service):
    """Independent subset: allocation ownership, publication, members and ABI.

    Volatile registers, stack scratch and unasserted handle fields use the
    independent original x86 reference, not an invented full-state oracle.
    """
    c.require(service.calls == 3 and sum(service.occupied) == sum(REQUESTS)//8)
    c.require(result['regs'][0] == heap.ARENA and result['regs'][7] == regs['esp']+4)
    for r in ('ebx', 'esi', 'edi', 'ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == 6*4096)
    after = {p: raw[i*4096:(i+1)*4096] for i, p in enumerate(heap.PAGES)}
    for p in set(heap.PAGES)-{c.DATA_PAGES[0], heap.ARENA}:
        c.require(after[p] == pages[p])
    obj = after[heap.ARENA]
    word = lambda off: struct.unpack_from('<I', obj, off)[0]
    for off in (0, 4, 0x74, 0xe4):
        c.require(word(off) == 0)
    c.require(word(0xe8) == c.OPENER_MEMBER_TABLE and word(0xf0) == 0 and word(0xf4) == 1)
    c.require(obj[0xec:0xf0] == pages[heap.ARENA][0xec:0xf0])
    c.require(word(0x78) == heap.ARENA+0x7c and word(0xc8) == heap.ARENA+0x78)
    for off, value in ((0x7c, c.BASE+0x10970), (0x80, c.BASE+0x109a0), (0xb0, c.BASE+0xfcf0)):
        c.require(word(off) == value)
    c.require(obj[0xc5] == 6)
    # No allocation or store may escape the three owned extents.
    c.require(obj[sum(REQUESTS):] == pages[heap.ARENA][sum(REQUESTS):])


def return_schedule(edges, *, units=None):
    """Per caller/target occurrence counts: repeated real call sites are distinct.

    Return PCs are decoded static metadata, never callee responses. An exhausted
    or unknown edge fails closed. Counters are reset before every outer call.
    """
    units = UNITS if units is None else units
    groups = defaultdict(list)
    for caller, target, ret in edges:
        c.require(type(caller) is type(target) is type(ret) is int)
        c.require(caller-c.BASE in units and target-c.BASE in units)
        size = units[caller-c.BASE][0]
        c.require(caller < ret <= caller+size)
        groups[caller, target].append(ret)
    c.require(groups)
    counters, cases, resets = [], [], []
    for n, ((caller, target), returns) in enumerate(sorted(groups.items())):
        c.require(returns == sorted(set(returns)))
        counters.append(f'static unsigned edge_{n}=0;')
        resets.append(f'edge_{n}=0;')
        cases.append(f'if(caller==0x{caller:08X}u && target==0x{target:08X}u) {{ switch(edge_{n}++) {{'+
                     ''.join(f'case {k}:return 0x{ret:08X}u;' for k, ret in enumerate(returns))+
                     'default:reject();} }')
    return '\n'.join(counters), '\n'.join(cases), ''.join(resets)


def assemble(bodies, edges, indirect_return, *, units=None):
    units = UNITS if units is None else units
    c.require(set(bodies) == set(units))
    text = rig.assemble(bodies, edges, indirect_return, units=units,
        entry_rva=ROOT_RVA, direct_targets=(0x122f0, 0x10960, 0x1a40, 0x1a00,
            0x2570, 0x26b0, 0x27d0, 0x109d0, 0x10700, 0xfcb0))
    declarations, cases, resets = return_schedule(edges, units=units)
    old = '\n'.join(f'if(caller==0x{caller:08X}u && target==0x{target:08X}u) return 0x{ret:08X}u;'
                    for caller, target, ret in edges)
    c.require(text.count(old) == 1)
    text = text.replace(old, cases)
    text = text.replace('static uint32_t direct_return(', declarations+'\nstatic uint32_t direct_return(')
    c.require(text.count('cache_reset(pages);') == 1)
    return text.replace('cache_reset(pages);', 'cache_reset(pages);'+resets)


def bridge_source(mode, *, units=None):
    units = UNITS if units is None else units
    # Retain production heap construction and outer-ABI fault controls.
    text = rig.bridge_source(mode)
    old_targets = [c.BASE+r for r in rig.UNITS]+[heap.SERVICE]
    old = f'constexpr std::array<uint32_t,{len(old_targets)}> targets{{'+','.join(f'0x{a:08X}u' for a in old_targets)+'};'
    targets = [c.BASE+r for r in units]+[heap.SERVICE]
    c.require(text.count(old) == 1)
    return text.replace(old, f'constexpr std::array<uint32_t,{len(targets)}> targets{{'+','.join(f'0x{a:08X}u' for a in targets)+'};')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indexes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    indexes = {int(r, 16): Path(p) for r, p in json.loads(a.indexes.read_text()).items()}
    try:
        rig.run(indexes, a.output, scenario=sys.modules[__name__])
    except Exception:
        parser.exit(1, 'Opener success failed; inspect private receipt.\n')
    print('3A50 null-input success: host + Linux/AArch64; NOT Android or whole opener coverage.')


if __name__ == '__main__':
    main()
