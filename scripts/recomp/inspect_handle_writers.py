#!/usr/bin/env python3
"""Bounded handle-field writer inventory; static candidates, never runtime proof.

Decode seven dependency-directed bodies, crosscheck persistent index boundaries,
and propagate only register constants. Calls kill ALL constants: no guessed ABI,
callee responses, object identity, stack values or interprocedural effects.
"""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, decode_flow, dependencies
from inspect_startup_dependency import crosscheck_index

TARGETS = (0x20d0, 0x2120, 0x2790, 0x3a50, 0x3c50, 0x62b0, 0x62f0)
FIELDS = (0x74, 0xd0, 0xd4, 0xe0)
BOUND = 0x400
REGS = ('eax', 'ebx', 'ecx', 'edx', 'ebp', 'esi', 'edi', 'esp')


def transfer(insn, incoming):
    """Finite constant lattice: absent means unknown; never read guest memory."""
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_REG, X86_OP_IMM
    if insn.group(CS_GRP_CALL):
        return {}
    out = dict(incoming)
    _, writes = insn.regs_access()
    # Parent aliases must be invalidated even for AL/AH/AX writes.
    aliases = {a: p for p, names in (
        ('eax', ('eax', 'ax', 'al', 'ah')), ('ebx', ('ebx', 'bx', 'bl', 'bh')),
        ('ecx', ('ecx', 'cx', 'cl', 'ch')), ('edx', ('edx', 'dx', 'dl', 'dh')),
        ('esi', ('esi', 'si')), ('edi', ('edi', 'di')),
        ('ebp', ('ebp', 'bp')), ('esp', ('esp', 'sp'))) for a in names}
    for reg in writes:
        out.pop(aliases.get(insn.reg_name(reg), ''), None)
    ops = insn.operands
    if len(ops) != 2 or ops[0].type != X86_OP_REG or ops[0].size != 4:
        return out
    dest = insn.reg_name(ops[0].reg)
    if dest not in REGS:
        return out
    src = ops[1]
    if insn.mnemonic == 'mov':
        if src.type == X86_OP_IMM:
            out[dest] = src.imm & 0xffffffff
        elif src.type == X86_OP_REG and insn.reg_name(src.reg) in incoming:
            out[dest] = incoming[insn.reg_name(src.reg)]
    elif insn.mnemonic in ('xor', 'sub') and src.type == X86_OP_REG and src.reg == ops[0].reg:
        out[dest] = 0
    return out


def constants(nodes, edges, entry):
    """Intersect equal constants at joins; include all normal-flow successors."""
    states = {entry: {}}
    pending = deque([entry])
    steps = 0
    while pending:
        pc = pending.popleft()
        steps += 1
        if steps > len(nodes) * 128:
            raise ValueError('Dataflow budget exhausted')
        out = transfer(nodes[pc], states[pc])
        for succ in edges[pc]:
            if succ not in nodes:
                raise ValueError('Unbounded successor')
            previous = states.get(succ)
            merged = out if previous is None else {r:v for r,v in previous.items() if out.get(r) == v}
            if previous is None or merged != previous:
                states[succ] = dict(merged)
                pending.append(succ)
    if set(states) != set(nodes):
        raise ValueError('Unvisited decoded node')
    return states


def inventory(code, rva, pe):
    from capstone import CS_AC_WRITE
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
    if not 0 < len(code) <= BOUND:
        raise ValueError('Invalid body window')
    _, nodes, edges, flow = decode_flow(code, BASE+rva, lambda i:i)
    states = constants(nodes, edges, BASE+rva)
    writes = []
    for pc, insn in sorted(nodes.items()):
        for number, op in enumerate(insn.operands):
            if op.type != X86_OP_MEM or not op.access & CS_AC_WRITE or op.mem.disp not in FIELDS:
                continue
            src = insn.operands[1] if len(insn.operands) == 2 and number == 0 else None
            value, source = None, 'unknown'
            # A read-modify-write is not assignment of its source operand.
            if src is not None and insn.mnemonic == 'mov':
                if src.type == X86_OP_IMM:
                    value, source = src.imm & ((1 << (op.size*8))-1), 'immediate'
                elif src.type == X86_OP_REG:
                    source = 'register'
                    if src.size == 4:
                        value = states[pc].get(insn.reg_name(src.reg))
            writes.append(dict(site_rva=hex(pc-BASE), field_displacement=hex(op.mem.disp),
                size_bytes=op.size, base_register=insn.reg_name(op.mem.base) or None,
                indexed=bool(op.mem.index), segmented=bool(op.mem.segment),
                source_kind=source,
                source_register=insn.reg_name(src.reg) if src is not None and src.type == X86_OP_REG else None,
                constant=value, receiver_identity_verified=False))
    body = dict(flow, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
    return dict(body=body, writes=writes, dependencies=dependencies(nodes, pe),
                callee_effects_modeled=False, executed=False)


def inspect(index_dir, output):
    private = (ROOT/'work/recomp-bench').resolve()
    output = output.resolve()
    if output == private or not output.is_relative_to(private):
        raise ValueError('Private output required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-handle-writer-inventory/1', success=False,
        image_sha256=IMAGE_SHA, harness_sha256=digest(Path(__file__)),
        decoder_sha256=digest(Path(__file__).with_name('measure_startup.py')),
        index_helper_sha256=digest(Path(__file__).with_name('inspect_startup_dependency.py')),
        invocation=[sys.executable, *sys.argv], functions={}, bound_bytes=BOUND,
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, dependencies_newly_resolved=0,
        limits=['HYPOTHESIS: operand displacements are candidate fields, not proven handle aliases',
                'Normal-flow static inventory only; no original x86 or native execution',
                'Calls invalidate all register constants; callee/memory/stack effects unknown',
                'Explicit displacement writes only; implicit/callee/aliased writes are not excluded',
                'Fixed seven bodies only; absence is not whole-image absence',
                'No service target, allocation, lifetime, callbacks or whole 1AB665 proof'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Wrong PE mapping')
        for rva in TARGETS:
            index = index_dir/f'{rva:x}.json.env.json'
            code = pe.get_data(rva, BOUND)
            if len(code) != BOUND:
                raise ValueError('Short body window')
            result = inventory(code, rva, pe)
            result['index'] = crosscheck_index(json.loads(index.read_text()), result['body'], rva)
            result['index_sha256'] = digest(index)
            result['body_sha256'] = hashlib.sha256(code[:result['body']['size_bytes']]).hexdigest()
            row['functions'][hex(rva)] = result
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image changed')
        row['success'] = True
    except Exception as exc:
        row['error_type'] = type(exc).__name__
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        inspect(a.index_dir, a.output)
    except Exception:
        p.exit(1, 'Writer inspection rejected; inspect private receipt.\n')
    print('Seven bounded writer inventories crosschecked; static candidates, no execution')


if __name__ == '__main__':
    main()
