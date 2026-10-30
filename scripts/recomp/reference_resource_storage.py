#!/usr/bin/env python3
"""Bounded storage-dependency first-call frames, never substitute callee returns.

Independent raw-encoding oracle; public fixtures are authored, original states
and all detailed results stay private. This is NOT a native translation.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_resource_boundary import REGS, STACK, MASK, require
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, decode_flow, dependencies
from inspect_startup_dependency import crosscheck_index

RVA = 0x8460CF
SIZE = 163
SLOT = BASE+0x104F89C
BOUND = 192


def frame_plan(code, entry, regs, stack, flags, slot, value, *, budget=32):
    """Decode only register MOV/XOR/CMP, MOV EAX,moffs, PUSH, JE/JNE, CALL.

    The sole explicit memory operand is ONE declared read-only global word.
    CMP uses full independent subtraction flags; XOR AF alone is undefined.
    Execute CALL's frame push, stop at target entry without executing callee.
    Branch overlap, loops, other operands and all undeclared accesses reject.
    """
    require(0 < len(code) <= BOUND and 0 <= entry <= MASK-len(code))
    require(set(regs) == set(REGS) and len(stack) == 4096 and 0 < budget <= 32)
    require(all(type(v) is int and 0 <= v <= MASK for v in regs.values()))
    require(type(flags) is int and 0 <= flags <= MASK)
    require(type(value) is int and 0 <= value <= MASK)
    require(type(slot) is int and 0 <= slot <= MASK-3 and slot % 4 == 0)
    require(slot >> 12 not in (STACK >> 12, entry >> 12))
    state, memory, pc, plan, occupied = dict(regs), bytearray(stack), entry, [], set()
    flag_mask = 0xCD5
    while len(plan) < budget:
        require(entry <= pc < entry+len(code))
        start, off = pc, pc-entry

        def take(n, signed=False):
            nonlocal off
            require(off+n <= len(code))
            v = int.from_bytes(code[off:off+n], 'little', signed=signed)
            off += n
            return v

        def push(v):
            sp = state['esp']-4
            require(STACK <= sp <= STACK+4092 and sp % 4 == 0)
            struct.pack_into('<I', memory, sp-STACK, v & MASK)
            state['esp'] = sp

        op = take(1)
        target, call = None, False
        if op in (0x8B, 0x89, 0x31, 0x33):
            m = take(1)
            require(m >> 6 == 3)
            dst, src = (m >> 3) & 7, m & 7
            if op in (0x89, 0x31):
                dst, src = src, dst
            require(dst != 4)
            if op in (0x8B, 0x89):
                state[REGS[dst]] = state[REGS[src]]
            else:
                result = state[REGS[dst]] ^ state[REGS[src]]
                state[REGS[dst]] = result
                flags = ((flags & ~0x8C5) | ((int((result & 255).bit_count()%2 == 0)) << 2)
                         | (int(result == 0) << 6) | ((result >> 31) << 7))
                flag_mask &= ~0x10
        elif op == 0xA1:
            require(take(4) == slot)
            state['eax'] = value
        elif op == 0x83:
            m = take(1)
            require(m >> 6 == 3 and (m >> 3) & 7 == 7)
            a, b = state[REGS[m & 7]], take(1, True) & MASK
            result = (a-b) & MASK
            flags = ((flags & ~0x8D5) | int(a < b)
                     | (int((result & 255).bit_count()%2 == 0) << 2)
                     | ((a ^ b ^ result) & 0x10) | (int(result == 0) << 6)
                     | ((result >> 31) << 7) | (((a ^ b) & (a ^ result) & 0x80000000) >> 20))
            flag_mask |= 0x10  # CMP defines AF even after XOR.
        elif 0x50 <= op <= 0x57:
            push(state[REGS[op-0x50]])
        elif op in (0x68, 0x6A):
            push(take(4 if op == 0x68 else 1, True))
        elif op in (0x74, 0x75):
            displacement = take(1, True)
            if bool(flags & 0x40) == (op == 0x74):
                target = entry+off+displacement
        elif op == 0xE8:
            displacement = take(4, True)
            push(entry+off)
            target, call = (entry+off+displacement) & MASK, True
            require(not entry <= target < entry+len(code))
        else:
            raise ValueError('Unsupported storage-prefix encoding')
        span = set(range(start, entry+off))
        require(not occupied.intersection(span))
        occupied.update(span)
        pc = target if target is not None else entry+off
        plan.append(dict(pc=start, next_pc=pc, regs=dict(state), stack=bytes(memory),
                         flags=flags, flag_mask=flag_mask))
        if call:
            return plan
    raise ValueError('Storage-prefix budget exhausted')


def exercise(code, entry, regs, stack, flags, slot, value, *, budget=32):
    """Hook-free bounded original x86; compare EVERY step to the raw oracle."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    plan = frame_plan(code, entry, regs, stack, flags, slot, value, budget=budget)
    require(entry >> 12 == (entry+len(code)-1) >> 12)
    pages = {entry & ~4095, slot & ~4095, plan[-1]['next_pc'] & ~4095}
    require(STACK not in pages)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(STACK, 4096)
    u.mem_write(STACK, stack)
    for p in pages:
        u.mem_map(p, 4096)
    u.mem_write(entry, code)
    u.mem_write(slot, struct.pack('<I', value))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages}
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS:
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, flags)
    for step in plan:
        u.emu_start(step['pc'], 0, count=1)
        require(u.reg_read(x.UC_X86_REG_EIP) == step['next_pc'])
        require(all(u.reg_read(ids[r]) == step['regs'][r] for r in REGS))
        require((u.reg_read(x.UC_X86_REG_EFLAGS) ^ step['flags']) & step['flag_mask'] == 0)
        require(bytes(u.mem_read(STACK, 4096)) == step['stack'])
        require(all(bytes(u.mem_read(p, 4096)) == v for p, v in immutable.items()))
    return plan


def run(index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    start = time.monotonic()
    row = dict(schema='ts2-resource-storage-reference/1', success=False, rva=hex(RVA),
        image_sha256=IMAGE_SHA, harness_sha256=digest(Path(__file__)),
        invocation=[sys.executable, *sys.argv], completed_cases=0,
        selected_new=False, lift_attempted=False, lifted=False, arm64_compiled=False,
        matched_native=False, qemu_executed=False, android_executed=False,
        limits=['HYPOTHESIS: synthetic stack/global initialization, not live thread storage',
                'Only first CALL frame executed: no callee instruction, stub or return',
                'Normal-flow index assumes returning calls; names are not service contracts',
                'No native comparison, FP/SIMD/SEH, transient-write trace or game startup'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.FILE_HEADER.Machine == 0x14C and pe.OPTIONAL_HEADER.ImageBase == BASE)
        code = pe.get_data(RVA, SIZE)
        _, nodes, _, analysis = decode_flow(code, BASE+RVA, lambda i: i)
        row['analysis'] = analysis
        body = dict(analysis, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
        row['index'] = crosscheck_index(json.loads(index.read_text()), body, RVA)
        row['index_sha256'] = digest(index)
        row['dependencies'] = dependencies(nodes, pe)
        rng, coverage, cuts, states = random.Random(11818732), set(), {}, []
        for sp in (STACK+128, STACK+2048):
            for value in (0, 1, 0x7FFFFFFF, 0x80000000, MASK):
                for flags in (0x202, 0xED7):
                    regs = {r: rng.getrandbits(32) for r in REGS}
                    regs['esp'] = sp
                    plan = exercise(code, BASE+RVA, regs, rng.randbytes(4096), flags, SLOT, value)
                    require(all(s['pc'] in nodes for s in plan))
                    last = plan[-1]
                    key = hex(last['pc']-BASE)
                    frame = (hex(last['next_pc']-BASE), last['regs']['esp']-sp)
                    cuts.setdefault(key, set()).add(frame)
                    coverage.update(s['pc'] for s in plan)
                    states.append([dict(s, stack=s['stack'].hex()) for s in plan])
                    row['completed_cases'] += 1
        require(set(cuts) == {'0x8460e3', '0x8460fd'})
        require(digest(image) == IMAGE_SHA)
        (output/'states.json').write_text(json.dumps(states))
        row.update(success=True, executed_instruction_union=len(coverage),
                   first_call_frames={k: sorted(v) for k,v in cuts.items()},
                   compared=['eight GPRs, PC, defined integer/DF flags after EVERY step',
                             'full 4096-byte stack and immutable code/global/target pages every step'])
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
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        row = run(args.index, args.output)
    except Exception:
        print('Storage reference rejected; inspect private metrics', file=sys.stderr)
        return 1
    print('First-call frames matched %d cases; callee return remains unverified' % row['completed_cases'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
