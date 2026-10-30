#!/usr/bin/env python3
"""Bounded branch-to-first-call reference; no callee executes or returns.

Raw encoding oracle is independent of Capstone and Unicorn semantics. Private
original inputs/states only; public tests use authored encodings. Not a lift.
"""
import argparse
import itertools
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inspect_startup_dependency import crosscheck_index
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE
from reference_resource_boundary import REGS, STACK, MASK, require

RVA = 0x82A70A
BOUND = 256
SLOT = BASE+0xD9A71C
PAYLOAD = 0x71000000


def branch_plan(code, entry, regs, stack, slot, value, flags, *, budget=32, extra_words=None):
    """Predict every step until BEFORE first CALL, including either JZ/JNZ arm.

    Only MOV r32,r/m32 (no SIB), TEST r32,r32, PUSH r32/rm32,
    JZ/JNZ rel8 and terminal direct/indirect CALL recognition. Reads are limited
    to the stack page, ONE absolute word and up to two explicit payload words.
    No call target is read,
    resolved, stubbed or executed. All other encodings and loops reject.
    """
    require(0 < len(code) <= BOUND and 0 <= entry <= MASK-len(code))
    require(set(regs) == set(REGS) and len(stack) == 4096)
    require(all(type(v) is int and 0 <= v <= MASK for v in regs.values()))
    require(type(flags) is int and 0 <= flags <= MASK)
    require(type(value) is int and 0 <= value <= MASK)
    require(type(slot) is int and 0 <= slot <= MASK-3 and slot % 4 == 0)
    require(not STACK <= slot < STACK+4096 and 0 < budget <= 32)
    extra_words = {} if extra_words is None else dict(extra_words)
    require(len(extra_words) <= 2)
    for addr, word in extra_words.items():
        require(type(addr) is int and 0 <= addr <= MASK-3 and addr % 4 == 0)
        require(type(word) is int and 0 <= word <= MASK)
        require(addr >> 12 not in (STACK >> 12, entry >> 12, slot >> 12))
    state, memory, pc, plan, occupied = dict(regs), bytearray(stack), entry, [], set()
    flag_mask = 0xCD5
    reads = []
    while True:
        require(len(plan) < budget and entry <= pc < entry+len(code))
        start, off = pc, pc-entry

        def take(n, signed=False):
            nonlocal off
            require(off+n <= len(code))
            v = int.from_bytes(code[off:off+n], 'little', signed=signed)
            off += n
            return v

        def operand(modrm):
            mode, rm = modrm >> 6, modrm & 7
            if mode == 3:
                return state[REGS[rm]]
            require(rm != 4)  # SIB deliberately unsupported.
            if mode == 0 and rm == 5:
                addr = take(4)
            else:
                disp = take(1 if mode == 1 else 4, True) if mode else 0
                addr = (state[REGS[rm]]+disp) & MASK
            require(addr <= MASK-3)
            reads.append(addr)
            if STACK <= addr <= STACK+4092:
                return struct.unpack_from('<I', memory, addr-STACK)[0]
            require(addr == slot or addr in extra_words)
            return value if addr == slot else extra_words[addr]

        def push(v):
            sp = state['esp']-4
            require(STACK <= sp <= STACK+4092 and sp % 4 == 0)
            struct.pack_into('<I', memory, sp-STACK, v)
            state['esp'] = sp

        op = take(1)
        target, call = None, False
        if op == 0xE8:
            take(4, True)
            call = True
        elif op == 0xFF and off < len(code) and (code[off] >> 3) & 7 == 2:
            # Recognize length only. No indirect-target read or execution.
            modrm = take(1)
            mode, rm = modrm >> 6, modrm & 7
            require(rm != 4 or mode == 3)
            if mode == 0 and rm == 5:
                take(4)
            elif mode in (1, 2):
                take(1 if mode == 1 else 4)
            call = True
        elif op == 0x8B:
            modrm = take(1)
            dst = REGS[(modrm >> 3) & 7]
            require(dst != 'esp')
            state[dst] = operand(modrm)
        elif op == 0x85:
            modrm = take(1)
            require(modrm >> 6 == 3)
            result = state[REGS[modrm & 7]] & state[REGS[(modrm >> 3) & 7]]
            flags = ((flags & ~0x8C5) | (int((result & 255).bit_count() % 2 == 0) << 2)
                     | (int(result == 0) << 6) | ((result >> 31) << 7))
            flag_mask &= ~0x10  # TEST AF is undefined.
        elif 0x50 <= op <= 0x57:
            push(state[REGS[op-0x50]])
        elif op == 0xFF:
            modrm = take(1)
            require((modrm >> 3) & 7 == 6)
            push(operand(modrm))
        elif op in (0x74, 0x75):
            disp = take(1, True)
            zero = bool(flags & 0x40)
            if zero == (op == 0x74):
                target = entry+off+disp
        else:
            raise ValueError('Unsupported branch-prefix encoding')
        span = set(range(start, entry+off))
        require(not occupied.intersection(span))
        occupied.update(span)
        if call:
            return dict(plan=plan, stop_pc=start, regs=dict(state), stack=bytes(memory),
                        flags=flags, flag_mask=flag_mask, read_addresses=reads)
        next_pc = target if target is not None else entry+off
        plan.append(dict(pc=start, next_pc=next_pc, regs=dict(state), stack=bytes(memory),
                         flags=flags, flag_mask=flag_mask))
        pc = next_pc


def exercise(code, entry, regs, stack, slot, value, flags, *, budget=32, extra_words=None):
    """Hook-free x86 single steps checked against every independent oracle state."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    extra_words = {} if extra_words is None else dict(extra_words)
    expected = branch_plan(code, entry, regs, stack, slot, value, flags,
                           budget=budget, extra_words=extra_words)
    require(expected['plan'])
    require(entry >> 12 == (entry+len(code)-1) >> 12)
    require(slot >> 12 == (slot+3) >> 12)
    pages = {entry & ~4095, slot & ~4095}
    require(len(pages) == 2 and STACK not in pages)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(STACK, 4096)
    u.mem_write(STACK, stack)
    pages.update(addr & ~4095 for addr in extra_words)
    for p in pages:
        u.mem_map(p, 4096)
    u.mem_write(entry, code)
    u.mem_write(slot, struct.pack('<I', value))
    for addr, word in extra_words.items():
        u.mem_write(addr, struct.pack('<I', word))
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages}
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS:
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, flags)
    u.reg_write(x.UC_X86_REG_EIP, entry)
    for step in expected['plan']:
        require(u.reg_read(x.UC_X86_REG_EIP) == step['pc'])
        u.emu_start(step['pc'], 0, count=1)
        require(u.reg_read(x.UC_X86_REG_EIP) == step['next_pc'])
        require(all(u.reg_read(ids[r]) == step['regs'][r] for r in REGS))
        require((u.reg_read(x.UC_X86_REG_EFLAGS) ^ step['flags']) & step['flag_mask'] == 0)
        require(bytes(u.mem_read(STACK, 4096)) == step['stack'])
        require(all(bytes(u.mem_read(p, 4096)) == v for p, v in immutable.items()))
    require(u.reg_read(x.UC_X86_REG_EIP) == expected['stop_pc'])
    return expected


def run(index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    start = time.monotonic()
    row = dict(schema='ts2-resource-branch-reference/1', success=False, rva=hex(RVA),
        image_sha256=IMAGE_SHA, harness_sha256=digest(Path(__file__)),
        synthetic_sixth_argument_is_explicit_readable_word=True,
        synthetic_pointer_chain_field_offset=0x35C,
        invocation=[sys.executable, *sys.argv], completed_cases=0,
        selected_new=False, lift_attempted=False, lifted=False, arm64_compiled=False,
        matched_native=False, qemu_executed=False, android_executed=False,
        limits=['HYPOTHESIS: synthetic argument/global inputs, not recovered live initialization',
                'Stops BEFORE first call: no callee execution, return, service identity or ABI proof',
                'No native comparison, FP/SIMD/SEH, transient writes or startup reachability',
                'Original decoder/trap rejection and runtime bindings unchanged'])
    try:
        row['index_sha256'] = digest(index)
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
        envelope = json.loads(index.read_text())
        size = envelope['result']['function']['disassembly']['extentBytes']
        require(type(size) is int and 0 < size <= BOUND)
        code = pe.get_data(RVA, size)
        nodes = list(Cs(CS_ARCH_X86, CS_MODE_32).disasm(code, BASE+RVA))
        require(sum(i.size for i in nodes) == size)
        body = dict(size_bytes=size, instructions=len(nodes),
                    instruction_rvas=[hex(i.address-BASE) for i in nodes])
        row['index'] = crosscheck_index(envelope, body, RVA)
        boundaries = {i.address for i in nodes}
        rng, states, stops, coverage = random.Random(11818730), [], {}, set()
        deltas, slot_reads = {}, 0
        for spoff, words, value, pointee, field, flags in itertools.product(
                (128, 2048), itertools.product((0, 0x87654321), repeat=5),
                (0, 0xFEDCBA98), (0, PAYLOAD+0x100), (0, 0x87654321), (0x202, 0xED7)):
            regs = {r: rng.getrandbits(32) for r in REGS}
            regs['esp'] = STACK+spoff
            stack = bytearray(rng.randbytes(4096))
            struct.pack_into('<6I', stack, spoff+4, *words, PAYLOAD)
            result = exercise(code, BASE+RVA, regs, bytes(stack), SLOT, value, flags,
                              extra_words={PAYLOAD: pointee, PAYLOAD+0x100+0x35C: field})
            require(result['stop_pc'] in boundaries)
            require(all(s['pc'] in boundaries for s in result['plan']))
            stop = hex(result['stop_pc']-BASE)
            stops[stop] = stops.get(stop, 0)+1
            deltas.setdefault(stop, set()).add(result['regs']['esp']-regs['esp'])
            slot_reads += result['read_addresses'].count(SLOT)
            coverage.update(s['pc'] for s in result['plan'])
            states.append(dict(stop_pc=result['stop_pc'], regs=result['regs'],
                               stack=result['stack'].hex(), flags=result['flags'],
                               flag_mask=result['flag_mask']))
            row['completed_cases'] += 1
        require(set(stops) == {'0x82a71c', '0x82a740', '0x82a751'})
        require(digest(image) == IMAGE_SHA)
        (output/'states.json').write_text(json.dumps(states))
        row.update(success=True, matched_x86_oracle_cases=len(states), first_call_sites=stops,
                   executed_instruction_union=len(coverage), indexed_instructions=len(nodes),
                   first_call_stack_deltas={k: sorted(v) for k, v in deltas.items()},
                   pre_call_explicit_slot_reads=slot_reads,
                   compared=['eight GPRs, PC, defined integer/DF flags after every step',
                             'entire 4096-byte stack and immutable code/global/payload pages every step'])
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
        print('Branch reference rejected; inspect private metrics', file=sys.stderr)
        return 1
    print(f"First-call frames matched {row['completed_cases']}; no callees executed")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
