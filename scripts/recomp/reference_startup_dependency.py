#!/usr/bin/env python3
"""Private bounded x86 helper reference versus an independent integer model.

Development only: no lift, runtime service, exception dispatch or PE launch.
The model executes a deliberately tiny straight-line instruction subset; it is
not inferred source, a shipping interpreter, or proof of the caller's ABI.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inspect_startup_dependency import DEPENDENCY, inspect_body, crosscheck_index
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE

MASK = 0xFFFFFFFF
GPRS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
STACK, GDT, RETURN = 0x70000000, 0x73000000, 0x71000000
COOKIE = BASE + 0x104F540
ENTRY = BASE + DEPENDENCY


def require(ok):
    if not ok:
        raise ValueError('Dependency reference contract rejected')


def descriptor(base, code=False):
    """32-bit ring-zero, 4-GiB limit, present code/data GDT descriptor."""
    require(0 <= base <= MASK)
    return struct.pack('<HHBBBB', 0xFFFF, base & 0xFFFF, (base >> 16) & 255,
                       0x9B if code else 0x93, 0xCF, base >> 24)


def nodes_for(code, entry):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes = list(md.disasm(code, entry))
    require(nodes and sum(i.size for i in nodes) == len(code) and len(nodes) <= 32)
    require(nodes[-1].mnemonic == 'ret' and not nodes[-1].operands)
    require(all(i.mnemonic in ('mov', 'lea', 'push', 'sub', 'xor') for i in nodes[:-1]))
    require(all(o.size == 4 for i in nodes for o in i.operands))
    return nodes


class Model:
    """Independent Python modular integer/data-memory oracle, excluding flags.

    No Unicorn calls. All word accesses must be inside declared windows; page
    mapping alone does not grant access. Only FS:[0] is admitted as segment data.
    """
    def __init__(self, regs, pages, fs, stack=STACK):
        self.regs = dict(regs)
        self.pages = {p: bytearray(v) for p, v in pages.items()}
        self.fs, self.stack = fs, stack
        self.pc = None

    def check(self, address, write=False):
        require(type(address) is int and 0 <= address <= MASK-3)
        require(self.stack <= address <= self.stack+4092 or address == self.fs or
                (address == COOKIE and not write))
        require(address & ~4095 in self.pages)

    def read(self, address):
        self.check(address)
        return struct.unpack_from('<I', self.pages[address & ~4095], address & 4095)[0]

    def write(self, address, value):
        self.check(address, True)
        struct.pack_into('<I', self.pages[address & ~4095], address & 4095, value & MASK)

    def address(self, insn, op, *, lea=False):
        mem = op.mem
        value = mem.disp
        if mem.base:
            require(insn.reg_name(mem.base) in GPRS)
            value += self.regs[insn.reg_name(mem.base)]
        if mem.index:
            require(insn.reg_name(mem.index) in GPRS)
            value += self.regs[insn.reg_name(mem.index)] * mem.scale
        value &= MASK
        if mem.segment:
            require(not lea and insn.reg_name(mem.segment) == 'fs' and value == 0)
            value = self.fs
        return value

    def value(self, insn, op):
        from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
        if op.type == X86_OP_IMM:
            return op.imm & MASK
        if op.type == X86_OP_REG:
            require(insn.reg_name(op.reg) in GPRS)
            return self.regs[insn.reg_name(op.reg)]
        require(op.type == X86_OP_MEM)
        return self.read(self.address(insn, op))

    def assign(self, insn, op, value):
        from capstone.x86 import X86_OP_REG, X86_OP_MEM
        if op.type == X86_OP_REG:
            require(insn.reg_name(op.reg) in GPRS)
            self.regs[insn.reg_name(op.reg)] = value & MASK
        else:
            require(op.type == X86_OP_MEM)
            self.write(self.address(insn, op), value)

    def step(self, insn):
        ops, name = insn.operands, insn.mnemonic
        self.pc = insn.address + insn.size
        if name == 'ret':
            self.pc = self.read(self.regs['esp'])
            self.regs['esp'] = (self.regs['esp']+4) & MASK
        elif name == 'push':
            require(len(ops) == 1)
            value = self.value(insn, ops[0])  # PUSH ESP reads old SP.
            self.regs['esp'] = (self.regs['esp']-4) & MASK
            self.write(self.regs['esp'], value)
        else:
            require(len(ops) == 2)
            if name == 'lea':
                value = self.address(insn, ops[1], lea=True)
            elif name == 'mov':
                value = self.value(insn, ops[1])
            elif name in ('sub', 'xor'):
                left, right = self.value(insn, ops[0]), self.value(insn, ops[1])
                value = left-right if name == 'sub' else left ^ right
            else:
                raise ValueError('Unsupported model instruction')
            self.assign(insn, ops[0], value)


def caller_plan(code, entry, target, regs, stack):
    """Independent raw-byte oracle: 1..4 immediate PUSHes then rel32 CALL.

    No Capstone semantics are used here. Sign extension, old SP, pushed return
    PC and target are computed from encodings. No caller continuation executes.
    Returns each expected post-step register/PC/stack snapshot.
    """
    require(0 <= entry <= MASK-len(code) and 0 < len(code) <= 25)
    state, memory, plan, offset = dict(regs), bytearray(stack), [], 0
    while offset < len(code):
        start, opcode = offset, code[offset]
        if opcode in (0x68, 0x6A):
            size = 5 if opcode == 0x68 else 2
            require(len(plan) < 4 and offset+size <= len(code))
            value = int.from_bytes(code[offset+1:offset+size], 'little', signed=True) & MASK
            pc = entry+offset+size
        else:
            require(opcode == 0xE8 and 1 <= len(plan) <= 4 and offset+5 == len(code))
            size = 5
            value = entry+offset+size
            pc = (value+int.from_bytes(code[offset+1:offset+5], 'little', signed=True)) & MASK
            require(pc == target)
        sp = state['esp']-4
        require(STACK <= sp <= STACK+4092)
        state['esp'] = sp
        struct.pack_into('<I', memory, sp-STACK, value)
        plan.append((entry+start, size, dict(state), pc, bytes(memory)))
        offset += size
    require(code[plan[-1][0]-entry] == 0xE8)
    return plan


def exercise(code, regs, stack_bytes, fs, chain, cookie, *, entry=ENTRY, budget=32,
             prefix=b'', prefix_entry=None):
    """Hook-free single steps; real nonzero FS descriptor, no zero-base alias.

    Before each x86 step validate explicit and implicit word accesses using the
    actual Unicorn registers. Compare every post-step GPR, PC and full pages
    against the separate model. Flags, FP and exception behavior are not compared.
    """
    from capstone import CS_AC_WRITE
    from capstone.x86 import X86_OP_MEM
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    require(fs in (0x74000000, 0x75000000) and len(stack_bytes) == 4096)
    require(set(regs) == set(GPRS) and 0 < budget <= 32)
    nodes = nodes_for(code, entry)
    require(len(nodes) <= budget and entry & ~4095 != COOKIE & ~4095)
    plan = caller_plan(prefix, prefix_entry, entry, regs, stack_bytes) if prefix else []
    require(not prefix or len(nodes)+len(plan) <= budget)
    continuation = prefix_entry+len(prefix) if prefix else RETURN
    pages = {STACK: bytes(stack_bytes), fs: bytes([0x6D])*4096,
             COOKIE & ~4095: bytes([0xB6])*4096}
    pages[fs] = struct.pack('<I', chain) + pages[fs][4:]
    data = bytearray(pages[COOKIE & ~4095])
    struct.pack_into('<I', data, COOKIE & 4095, cookie)
    pages[COOKIE & ~4095] = bytes(data)
    model = Model(regs, pages, fs)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, contents in pages.items():
        u.mem_map(p, 4096)
        u.mem_write(p, contents)
    code_page = entry & ~4095
    require((entry+len(code)-1) & ~4095 == code_page)
    code_pages = {code_page, GDT, RETURN}
    if prefix:
        prefix_page = prefix_entry & ~4095
        require((prefix_entry+len(prefix)-1) & ~4095 == prefix_page)
        require(prefix_page not in code_pages and prefix_page not in pages)
        code_pages.add(prefix_page)
    for p in code_pages:
        u.mem_map(p, 4096)
    u.mem_write(entry, code)
    if prefix:
        u.mem_write(prefix_entry, prefix)
    table = bytes(8)+descriptor(0, True)+descriptor(0)+descriptor(fs)
    u.mem_write(GDT, table)
    u.reg_write(x.UC_X86_REG_GDTR, (0, GDT, len(table)-1, 0))
    for reg, selector in ((x.UC_X86_REG_CS, 8), (x.UC_X86_REG_DS, 16),
            (x.UC_X86_REG_ES, 16), (x.UC_X86_REG_SS, 16), (x.UC_X86_REG_FS, 24)):
        u.reg_write(reg, selector)
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in GPRS}
    for r in GPRS:
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    u.reg_write(x.UC_X86_REG_EIP, entry)
    immutable = {p: bytes(u.mem_read(p, 4096)) for p in code_pages}
    # CALL and caller PUSH frames are checked by an encoding-level oracle,
    # independently of the helper's Capstone-based integer model.
    if plan:
        u.reg_write(x.UC_X86_REG_EIP, prefix_entry)
    for pc, _size, expected_regs, next_pc, expected_stack in plan:
        require(u.reg_read(x.UC_X86_REG_EIP) == pc)
        require(STACK <= u.reg_read(ids['esp'])-4 <= STACK+4092)
        u.emu_start(pc, 0, count=1)
        require(all(u.reg_read(ids[r]) == expected_regs[r] for r in GPRS))
        require(u.reg_read(x.UC_X86_REG_EIP) == next_pc)
        require(bytes(u.mem_read(STACK, 4096)) == expected_stack)
        require(all(bytes(u.mem_read(p, 4096)) == contents for p, contents in pages.items() if p != STACK))
        require(all(bytes(u.mem_read(p, 4096)) == contents for p, contents in immutable.items()))
    if plan:
        helper_pages = dict(pages)
        helper_pages[STACK] = plan[-1][4]
        model = Model(plan[-1][2], helper_pages, fs)
    for insn in nodes:
        require(u.reg_read(x.UC_X86_REG_EIP) == insn.address)
        # Separate guard state is built from actual x86 state, not oracle output.
        guard = Model({r: u.reg_read(ids[r]) for r in GPRS}, pages, fs)
        for op in insn.operands:
            if op.type == X86_OP_MEM and insn.mnemonic != 'lea':
                guard.check(guard.address(insn, op), bool(op.access & CS_AC_WRITE))
        if insn.mnemonic == 'push':
            guard.check((guard.regs['esp']-4) & MASK, True)
        elif insn.mnemonic == 'ret':
            guard.check(guard.regs['esp'])
        model.step(insn)
        u.emu_start(insn.address, 0, count=1)
        require(all(u.reg_read(ids[r]) == model.regs[r] for r in GPRS))
        require(u.reg_read(x.UC_X86_REG_EIP) == model.pc)
        require(all(bytes(u.mem_read(p, 4096)) == contents for p, contents in model.pages.items()))
        require(all(bytes(u.mem_read(p, 4096)) == contents for p, contents in immutable.items()))
    require(model.pc == continuation)
    return model


def run(output, index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    if output.exists():
        raise FileExistsError('Exclusive private output required')
    start = time.monotonic()
    image = ROOT/'work/interop-legacy-002/analysis-image.bin'
    require(digest(image) == IMAGE_SHA)
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
    window = pe.get_data(DEPENDENCY, 128)
    body = inspect_body(window, ENTRY)
    indexed = crosscheck_index(json.loads(index.read_text()), body)
    code = window[:body['size_bytes']]
    rng = random.Random(11818720)
    count = 0
    stack_deltas, fs_publications = set(), 0
    # Explicit synthetic helper-entry frames, NOT an observed tail/caller ABI.
    for n in range(64):
        fs = (0x74000000, 0x75000000)[n % 2]
        regs = {r: rng.getrandbits(32) for r in GPRS}
        regs['esp'] = STACK+0x800
        stack = bytearray([0xA5]*4096)
        struct.pack_into('<III', stack, 0x800, RETURN, (n % 8)*16, (n % 8)*16)
        chain = (MASK, 0x76000100)[(n//2) % 2]
        state = exercise(code, regs, stack, fs, chain,
                         (0, MASK, 0xBB40E64E, 0x12345678)[(n//4) % 4])
        stack_deltas.add(state.regs['esp']-regs['esp'])
        head = state.read(fs)
        fs_publications += int(head != chain and STACK <= head <= STACK+4092)
        count += 1
    require(digest(image) == IMAGE_SHA)
    result = dict(schema='ts2-startup-dependency-reference/1', image_sha256=IMAGE_SHA,
        dependency_rva=hex(DEPENDENCY), size_bytes=len(code), cases=count,
        per_instruction_comparison=True, compared=['eight GPRs', 'PC',
            'full stack page', 'full nonzero-FS page', 'full cookie page',
            'immutable code and GDT pages'], fs_bases_tested=2,
        stack_delta_min_bytes=min(stack_deltas), stack_delta_max_bytes=max(stack_deltas),
        distinct_stack_deltas=len(stack_deltas), fs_stack_publication_cases=fs_publications,
        index=indexed, elapsed_seconds=time.monotonic()-start,
        invocation=[sys.executable, *sys.argv], selected_for_translation=False,
        lifted=False, native_executed=False, caller_abi_established=False,
        limits=['synthetic helper-entry frames, not observed caller execution',
            'independent subset interpreter shares Capstone decoding with access guard',
            'no flags/FP/SIMD comparison, SEH dispatch/unwind, OS service or runtime binding',
            'reference cost, NOT translation throughput; no AArch64 execution'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        run(args.output, args.index)
    except Exception:
        print('Dependency reference rejected; no native verification claimed', file=sys.stderr)
        return 1
    print('Bounded helper x86/model reference matched; caller ABI/SEH unverified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
