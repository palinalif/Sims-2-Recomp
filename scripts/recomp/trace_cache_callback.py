#!/usr/bin/env python3
"""Bounded static input provenance up to 1290's first call; NEVER execute it.

Expressions are syntactic input dependencies, not resolved pointers or a CPU/ABI
oracle. Explore both conditional edges; stop on every call/return. No other body
is read, lifted or dispatched, even if an expression looks like a known target.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inspect_cache_closure import CLOSURE, dependency_gate
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, decode_flow
from inspect_startup_dependency import crosscheck_index


def add(value, offset):
    if not offset:
        return value
    if value[0] == 'add':
        return add(value[1], value[2] + offset)
    return ('add', value, offset)


SP = ('entry', 'esp')


def trace_prefix(nodes, entry, max_steps=64, max_paths=16):
    """Small reject-by-default symbolic prefix, with explicitly nonaliasing stack.

    Only full-width integer MOV/LEA/INC, immediate stack ADD, PUSH/POP,
    TEST/CMP and normal branches are accepted. No callee effects or branch feasibility
    are modelled. Loops, holes, memory writes and unhandled instructions reject.
    """
    from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
    registers = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
    pending = [(entry, {r:('entry', r) for r in registers}, {}, [], None, ())]
    calls, returns, steps = [], 0, 0
    while pending:
        pc, regs, stack, conditions, predicate, visited = pending.pop()
        steps += 1
        if steps > max_steps or len(pending)+len(calls)+returns >= max_paths:
            raise ValueError('Prefix budget exceeded')
        if pc in visited or pc not in nodes:
            raise ValueError('Loop or missing boundary')
        visited = (*visited, pc)
        insn = nodes[pc]
        ops = insn.operands

        def address(op):
            m = op.mem
            if m.segment or m.index or not m.base:
                raise ValueError('Unsupported memory address')
            name = insn.reg_name(m.base)
            if name not in regs:
                raise ValueError('Unsupported address register')
            return add(regs[name], m.disp)

        def stack_offset(expr):
            if expr == SP:
                return 0
            if expr[0] == 'add' and expr[1] == SP:
                return expr[2]
            raise ValueError('Non-entry-relative stack')

        def value(op):
            if op.size != 4:
                raise ValueError('Only full-width inputs supported')
            if op.type == X86_OP_REG:
                name = insn.reg_name(op.reg)
                if name not in regs:
                    raise ValueError('Unsupported register')
                return regs[name]
            if op.type == X86_OP_IMM:
                return ('constant', op.imm & 0xffffffff)
            if op.type == X86_OP_MEM:
                addr = address(op)
                try:
                    offset = stack_offset(addr)
                except ValueError:
                    return ('load32', addr)
                return stack.get(offset, ('load32', addr))
            raise ValueError('Unsupported operand')

        if insn.group(CS_GRP_CALL):
            if len(ops) != 1:
                raise ValueError('Unsupported call')
            offset = stack_offset(regs['esp'])
            calls.append(dict(site_rva=hex(pc-BASE), target=value(ops[0]),
                pre_call_esp=regs['esp'],
                # These are candidate words, NOT an inferred argument count.
                stack_words=[stack.get(offset+4*i, ('load32', add(SP, offset+4*i)))
                             for i in range(4)], conditions=conditions))
            continue
        if insn.group(CS_GRP_RET):
            returns += 1
            continue
        if insn.group(CS_GRP_JUMP):
            if len(ops) != 1 or ops[0].type != X86_OP_IMM:
                raise ValueError('Unresolved prefix jump')
            target = ops[0].imm & 0xffffffff
            if insn.mnemonic == 'jmp':
                pending.append((target, regs, stack, conditions, predicate, visited))
            else:
                if predicate is None or insn.mnemonic not in (
                        'je', 'jne', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle',
                        'jo', 'jno', 'jp', 'jnp', 'js', 'jns'):
                    raise ValueError('Unmodelled branch predicate')
                for taken, successor in ((True,target), (False,pc+insn.size)):
                    condition = dict(branch_rva=hex(pc-BASE), condition=insn.mnemonic,
                                     taken=taken, predicate=predicate)
                    pending.append((successor, deepcopy(regs), dict(stack),
                                    [*conditions, condition], predicate, visited))
            continue
        if insn.mnemonic in ('mov', 'lea') and len(ops) == 2:
            dst = ops[0]
            if dst.type != X86_OP_REG or dst.size != 4:
                raise ValueError('Prefix memory/subregister write rejected')
            name = insn.reg_name(dst.reg)
            if name not in regs or name == 'esp':
                raise ValueError('Unsupported destination')
            if insn.mnemonic == 'lea':
                if ops[1].type != X86_OP_MEM:
                    raise ValueError('Invalid LEA')
                regs[name] = address(ops[1])
            else:
                regs[name] = value(ops[1])
        elif insn.mnemonic == 'push' and len(ops) == 1:
            pushed = value(ops[0])  # PUSH ESP observes the pre-decrement value.
            offset = stack_offset(regs['esp'])-4
            regs['esp'] = add(SP, offset)
            stack[offset] = pushed
        elif insn.mnemonic == 'pop' and len(ops) == 1:
            if ops[0].type != X86_OP_REG or ops[0].size != 4:
                raise ValueError('Unsupported POP')
            name = insn.reg_name(ops[0].reg)
            if name not in regs or name == 'esp':
                raise ValueError('Unsupported POP destination')
            offset = stack_offset(regs['esp'])
            regs[name] = stack.get(offset, ('load32', add(SP, offset)))
            regs['esp'] = add(SP, offset+4)
        elif insn.mnemonic == 'add' and len(ops) == 2:
            if (ops[0].type != X86_OP_REG or ops[0].size != 4 or
                    insn.reg_name(ops[0].reg) != 'esp' or ops[1].type != X86_OP_IMM or
                    not 0 <= ops[1].imm <= 256):
                raise ValueError('Only bounded immediate stack ADD supported')
            regs['esp'] = add(SP, stack_offset(regs['esp'])+ops[1].imm)
            predicate = None  # Arithmetic flags are not modelled.
        elif insn.mnemonic == 'inc' and len(ops) == 1:
            if ops[0].type != X86_OP_REG or ops[0].size != 4:
                raise ValueError('Unsupported INC')
            name = insn.reg_name(ops[0].reg)
            if name not in regs or name == 'esp':
                raise ValueError('Unsupported INC destination')
            regs[name] = add(regs[name], 1)
            predicate = None
        elif insn.mnemonic in ('test', 'cmp') and len(ops) == 2:
            predicate = (insn.mnemonic, value(ops[0]), value(ops[1]))
        elif insn.mnemonic != 'nop':
            raise ValueError('Unsupported prefix instruction')
        pending.append((pc+insn.size, regs, stack, conditions, predicate, visited))
    return dict(calls=calls, return_paths=returns, steps=steps,
                target_resolved=False, execution_performed=False)


def inspect(output, index):
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='ts2-cache-callback-provenance/1', inspection_complete=False,
        caller_closure=[hex(r) for r in CLOSURE], inspected_rvas=['0x1290'],
        invocation=[sys.executable,*sys.argv], harness_sha256=digest(Path(__file__)),
        lifted=False, host_executed=False, arm64_executed=False, android_executed=False,
        limits=['HYPOTHESIS: syntactic prefix dependencies, not resolved pointer values or ABI proof',
                'Both branch edges explored; feasibility and exceptions not modelled',
                'Inputs must not alias prefix stack stores; 32-bit address wrap excluded',
                'Four candidate pre-call words are NOT proof of callback arity or cleanup',
                'Stop at first call/return; no callback body, post-call effects or target execution'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Image mapping mismatch')
        _, nodes, _, flow = decode_flow(pe.get_data(0x1290,64), BASE+0x1290, lambda i:i)
        metadata = dict(flow, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
        report['index'] = crosscheck_index(json.loads(index.read_text()), metadata, 0x1290)
        report['index_sha256'] = digest(index)
        report['image_sha256'] = IMAGE_SHA
        report['scope_gate'] = dependency_gate(nodes)
        report['prefix'] = trace_prefix(nodes, BASE+0x1290)
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image changed')
        report['inspection_complete'] = True
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        raise
    finally:
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--index-1290', required=True, type=Path)
    a = p.parse_args()
    try:
        inspect(a.output, a.index_1290)
    except Exception:
        p.exit(1, 'Prefix inspection failed; inspect private result.\n')
    print('Static prefix inspected; callback remains unresolved. No lift or execution.')
    return 2  # A successful inspection NEVER clears the dependency gate.


if __name__ == '__main__':
    raise SystemExit(main())
