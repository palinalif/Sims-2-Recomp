#!/usr/bin/env python3
"""Private resource-boundary call-prefix reference, not a nonreturn implementation.

Stops BEFORE the first dependency executes. No service stubs, lift, PE launch,
exception dispatch or change to the resource decoder's returning-call policy.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE
from inspect_startup_dependency import first_direct_call, crosscheck_index

RVA = 0x82A797
BOUND = 96
STACK = 0x70000000
REGS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
MASK = 0xFFFFFFFF


def require(ok):
    if not ok:
        raise ValueError('Resource boundary contract rejected')


def prefix_plan(code, entry, regs, stack, flags):
    """Independent raw-encoding oracle, no Capstone/Unicorn semantics.

    Tiny straight-line subset: register self-MOV/self-XOR, register PUSH and one
    terminal rel32 CALL. Produces post-step states; NEVER follows a call. Rejects
    all memory operands, SP writes, branches and partially decoded input.
    """
    require(set(regs) == set(REGS) and len(stack) == 4096)
    require(0 < len(code) <= BOUND and 0 <= entry <= MASK-len(code))
    require(all(type(v) is int and 0 <= v <= MASK for v in regs.values()))
    state, memory, offset, plan = dict(regs), bytearray(stack), 0, []
    flag_mask = 0xCD5
    while offset < len(code):
        require(len(plan) < 32)
        start, op = offset, code[offset]
        pc = None
        if op in (0x89, 0x8B, 0x31, 0x33):
            require(offset+2 <= len(code))
            modrm = code[offset+1]
            dst, src = modrm & 7, (modrm >> 3) & 7
            require(modrm >> 6 == 3 and dst == src and dst != 4)
            if op in (0x31, 0x33):
                state[REGS[dst]] = 0
                flags = (flags & ~0x8C5) | 0x44
                flag_mask &= ~0x10  # AF undefined by XOR, not compared.
            size = 2
        elif 0x50 <= op <= 0x57 or op == 0xE8:
            size = 5 if op == 0xE8 else 1
            require(offset+size <= len(code))
            value = state[REGS[op-0x50]] if op != 0xE8 else entry+offset+size
            if op == 0xE8:
                require(offset+size == len(code))
                pc = (value+int.from_bytes(code[offset+1:offset+5], 'little', signed=True)) & MASK
            sp = state['esp']-4
            require(STACK <= sp <= STACK+4092)
            state['esp'] = sp
            struct.pack_into('<I', memory, sp-STACK, value)
        else:
            raise ValueError('Unsupported prefix encoding')
        offset += size
        plan.append(dict(pc=entry+start, next_pc=pc if pc is not None else entry+offset,
            regs=dict(state), stack=bytes(memory), flags=flags, flag_mask=flag_mask))
    require(code[plan[-1]['pc']-entry] == 0xE8)
    target = plan[-1]['next_pc']
    require(not entry <= target < entry+len(code))
    return plan


def exercise(code, entry, regs, stack, flags, *, budget=32):
    """Hook-free bounded original x86 steps, checked against raw-byte oracle.

    Complete stack and code/target pages checked after EVERY instruction; all
    eight GPRs, PC and defined integer/DF flags compared. Callee not executed.
    No FP/SIMD/SEH, transient-write trace, actual game reachability or ABI claim.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    plan = prefix_plan(code, entry, regs, stack, flags)
    require(0 < budget <= 32 and len(plan) <= budget)
    require((entry & ~4095) == ((entry+len(code)-1) & ~4095))
    pages = {entry & ~4095, plan[-1]['next_pc'] & ~4095}
    require(STACK not in pages)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    u.mem_map(STACK, 4096)
    u.mem_write(STACK, stack)
    for page in pages:
        u.mem_map(page, 4096)
    u.mem_write(entry, code)
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in pages}
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS:
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, flags)
    u.reg_write(x.UC_X86_REG_EIP, entry)
    for expected in plan:
        require(u.reg_read(x.UC_X86_REG_EIP) == expected['pc'])
        u.emu_start(expected['pc'], 0, count=1)
        require(u.reg_read(x.UC_X86_REG_EIP) == expected['next_pc'])
        require(all(u.reg_read(ids[r]) == expected['regs'][r] for r in REGS))
        require((u.reg_read(x.UC_X86_REG_EFLAGS) ^ expected['flags']) & expected['flag_mask'] == 0)
        require(bytes(u.mem_read(STACK, 4096)) == expected['stack'])
        require(all(bytes(u.mem_read(p, 4096)) == v for p, v in immutable.items()))
    return plan[-1]


def run(index, output):
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    if output.exists():
        raise FileExistsError('Exclusive output required')
    start = time.monotonic()
    image = ROOT/'work/interop-legacy-002/analysis-image.bin'
    require(digest(image) == IMAGE_SHA)
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL
    from capstone.x86 import X86_OP_IMM
    envelope = json.loads(index.read_text())
    size = envelope['result']['function']['disassembly']['extentBytes']
    require(type(size) is int and 0 < size <= BOUND)
    pe = pefile.PE(data=image.read_bytes())
    require(pe.FILE_HEADER.Machine == 0x14C and pe.OPTIONAL_HEADER.ImageBase == BASE)
    code = pe.get_data(RVA, size)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes = list(md.disasm(code, BASE+RVA))
    require(sum(i.size for i in nodes) == size)
    body = dict(instruction_rvas=[hex(i.address-BASE) for i in nodes],
                instructions=len(nodes), size_bytes=size)
    indexed = crosscheck_index(envelope, body, RVA)
    terminal = nodes[-1]
    require(terminal.group(CS_GRP_CALL) and terminal.operands[0].type == X86_OP_IMM)
    site, target = first_direct_call(code, BASE+RVA)
    first = next(i for i in nodes if i.address == site)
    prefix = code[:site+first.size-(BASE+RVA)]
    rng = random.Random(24024)
    cases = 0
    for sp in (STACK+128, STACK+2048):
        for esi in (0, 1, 0x80000000, MASK):
            for flags in (0x202, 0xED7):
                regs = {r: rng.getrandbits(32) for r in REGS}
                regs.update(esp=sp, esi=esi)
                stack = rng.randbytes(4096)
                result = exercise(prefix, BASE+RVA, regs, stack, flags)
                # Independent call-frame expectations, not merely self-comparison.
                require(result['next_pc'] == target and result['regs']['esp'] == sp-28)
                require(struct.unpack_from('<I', result['stack'], sp-28-STACK)[0] == site+5)
                require(result['stack'][sp-24-STACK:sp-4-STACK] == bytes(20))
                require(struct.unpack_from('<I', result['stack'], sp-4-STACK)[0] == esi)
                cases += 1
    require(digest(image) == IMAGE_SHA)
    row = dict(schema='ts2-resource-boundary-reference/1', image_sha256=IMAGE_SHA,
        invocation=[sys.executable, *sys.argv], dependency_rva=hex(RVA),
        size_bytes=size, instructions=len(nodes), index=indexed,
        indexed_no_return=envelope['result']['function']['noReturn'],
        indexed_no_return_is_behavioral_proof=False,
        terminal_call_rva=hex(terminal.address-BASE),
        terminal_target_rva=hex((terminal.operands[0].imm & MASK)-BASE),
        first_call_rva=hex(site-BASE), first_target_rva=hex(target-BASE),
        prefix_size_bytes=len(prefix), cases=cases, matched=cases,
        observed_argument_words=5, zero_arguments=True, prefix_stack_delta_bytes=-28,
        compared=['all eight GPRs', 'PC', 'defined integer/DF flags (XOR AF excluded)',
                  'entire 4096-byte stack each step', 'immutable code/target pages each step'],
        elapsed_seconds=time.monotonic()-start,
        selected_for_translation=False, lifted=False, arm64_executed=False,
        limits=['First callee entry only; neither dependency executed or stubbed',
                'Nonreturn/exception/service contract NOT established',
                'HYPOTHESIS: failure-reporting boundary from index metadata only',
                'No native comparison, FP/SIMD/SEH, transient writes or startup reachability',
                'Resource decoder policy and original rejection unchanged'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(row, stream, indent=2)
        stream.write('\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        row = run(args.index, args.output)
    except (OSError, ValueError, KeyError, TypeError):
        print('Boundary reference rejected; no nonreturn claim', file=sys.stderr)
        return 1
    print(f"First-callee entry matched {row['matched']}/{row['cases']}; nonreturn unverified")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
