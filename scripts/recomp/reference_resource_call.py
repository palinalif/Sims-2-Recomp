#!/usr/bin/env python3
"""Bounded original caller/leaf reference; stop at the first nested return.

Raw-encoding prefix oracle, no callee stubs or later dependency execution.
Private inputs, states and output only. This does not establish a service ABI.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from execute_resource_leaf import REGS, PAGES, reference_case, require
from inspect_startup_dependency import crosscheck_index, first_direct_call, inspect_body
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE

RVA = 0x82A6D3
LEAF = 0x82A47B
# Encoding order, deliberately independent of Capstone's register identifiers.
ENC_REGS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
MASK = 0xFFFFFFFF


def prefix_plan(code, entry, regs, stack):
    """Tiny straight-line raw decoder; predicts EVERY prefix state independently.

    Register MOV, PUSH register/immediate, SUB ESP immediate, LEA reg,[EBP+disp]
    and terminal rel32 CALL only. No reads except register values, no segments,
    no arbitrary memory, no branches or calls followed speculatively.
    """
    require(0 < len(code) <= 64 and 0 <= entry <= MASK-len(code))
    require(set(regs) == set(REGS) and len(stack) == 4096)
    require(all(type(v) is int and 0 <= v <= MASK for v in regs.values()))
    state, memory, flags, offset, plan = dict(regs), bytearray(stack), 0x202, 0, []

    def immediate(size, signed=False):
        nonlocal offset
        require(offset+size <= len(code))
        value = int.from_bytes(code[offset:offset+size], 'little', signed=signed)
        offset += size
        return value

    def push(value):
        sp = state['esp']-4
        require(PAGES[0] <= sp <= PAGES[0]+4092 and sp % 4 == 0)
        struct.pack_into('<I', memory, sp-PAGES[0], value & MASK)
        state['esp'] = sp

    while offset < len(code):
        require(len(plan) < 32)
        start, op = offset, immediate(1)
        target = None
        if op in (0x89, 0x8B):
            modrm = immediate(1)
            require(modrm >> 6 == 3)
            low, high = ENC_REGS[modrm & 7], ENC_REGS[(modrm >> 3) & 7]
            dst, src = (low, high) if op == 0x89 else (high, low)
            require(dst != 'esp')
            state[dst] = state[src]
        elif 0x50 <= op <= 0x57:
            push(state[ENC_REGS[op-0x50]])
        elif op in (0x68, 0x6A):
            push(immediate(4 if op == 0x68 else 1, signed=True))
        elif op in (0x81, 0x83):
            require(immediate(1) == 0xEC)  # SUB ESP,imm, not any other group operation.
            rhs = immediate(4 if op == 0x81 else 1, signed=True) & MASK
            lhs = state['esp']
            result = (lhs-rhs) & MASK
            require(result % 4 == 0 and PAGES[0] <= result <= PAGES[0]+4092)
            bits = (int(lhs < rhs) | (int((result & 255).bit_count() % 2 == 0) << 2) |
                    (((lhs ^ rhs ^ result) >> 4 & 1) << 4) | (int(result == 0) << 6) |
                    ((result >> 31) << 7) | (((lhs ^ rhs) & (lhs ^ result) & 0x80000000) >> 20))
            flags = (flags & ~0x8D5) | bits
            state['esp'] = result
        elif op == 0x8D:
            modrm = immediate(1)
            mode, dst = modrm >> 6, ENC_REGS[(modrm >> 3) & 7]
            require(mode in (1, 2) and modrm & 7 == 5 and dst != 'esp')
            disp = immediate(1 if mode == 1 else 4, signed=True)
            state[dst] = (state['ebp']+disp) & MASK
        elif op == 0xE8:
            disp = immediate(4, signed=True)
            require(offset == len(code))
            push(entry+offset)
            target = (entry+offset+disp) & MASK
            require(not entry <= target < entry+len(code))
        else:
            raise ValueError('Unsupported caller prefix encoding')
        plan.append(dict(pc=entry+start, next_pc=target if target is not None else entry+offset,
                         regs=dict(state), stack=bytes(memory), flags=flags, flag_mask=0xCD5))
    require(op == 0xE8)
    return plan


def run(index, leaf_index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-resource-call-reference/1', success=False, caller_rva=hex(RVA),
        leaf_rva=hex(LEAF), image_sha256=IMAGE_SHA, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), completed_cases=0, selected_new=False,
        lifted=False, native_executed=False, android_executed=False,
        compared=['prefix: raw oracle vs x86 eight GPRs, PC, defined flags, full stack each step',
                  'prefix: immutable other data/code pages each step',
                  'leaf: checked x86 accesses, return PC/SP, full final data pages retained privately'],
        limits=['No independent leaf semantic oracle or native composition comparison',
                'No later caller instructions, dependencies, exceptions, FP/SIMD or transient-write trace',
                'Synthetic entry/globals, no runtime service identity or startup reachability'])
    start = time.monotonic()
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
        caller, leaf = pe.get_data(RVA, 55), pe.get_data(LEAF, 72)
        for name, code, rva, path in (('caller', caller, RVA, index), ('leaf', leaf, LEAF, leaf_index)):
            body = inspect_body(code, BASE+rva)
            row[name+'_index'] = crosscheck_index(json.loads(path.read_text()), body, rva)
            row[name+'_index_sha256'] = digest(path)
        site, target = first_direct_call(caller, BASE+RVA)
        require(target == BASE+LEAF)
        prefix = caller[:site+5-(BASE+RVA)]
        row.update(prefix_size_bytes=len(prefix), call_rva=hex(site-BASE), return_rva=hex(site+5-BASE))
        rng, coverage, states = random.Random(11818727), set(), []
        for n in range(64):
            regs = {r: rng.getrandbits(32) for r in REGS}
            regs['esp'] = PAGES[0]+(0x800 if n%2 else 0xC00)
            pages = {p: bytearray(4096) for p in PAGES}
            pages[PAGES[0]][:] = rng.randbytes(4096)
            plan = prefix_plan(prefix, BASE+RVA, regs, pages[PAGES[0]])
            result, seen = reference_case(leaf, BASE+LEAF, regs, pages, prefix=(prefix, BASE+RVA))
            require(result['regs'][-1] == plan[-1]['regs']['esp']+8)
            coverage.update(seen)
            states.append(dict(case=n, prefix_regs=plan[-1]['regs'], result=result))
            row['completed_cases'] += 1
        require(digest(image) == IMAGE_SHA)
        (output/'states.json').write_text(json.dumps(states))
        row.update(success=True, matched_prefix_cases=64, nested_returns=64,
                   leaf_visited_instructions=len(coverage), leaf_total_instructions=26,
                   returned_to_first_caller_continuation=True)
    except Exception as exc:
        row['error_type'] = type(exc).__name__
        raise
    finally:
        row['elapsed_seconds'] = time.monotonic()-start
        (output/'metrics.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--leaf-index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        run(args.index, args.leaf_index, args.output)
    except Exception:
        print('Caller/leaf reference rejected; inspect private metrics', file=sys.stderr)
        return 1
    print('64 original nested returns; caller continuation and later dependencies NOT executed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
