#!/usr/bin/env python3
"""Bounded read-only Campaign D root-scope audit; never lift or execute callees.

Constant propagation stops at the first call on each normal-flow path. Branch
conditions are NOT solved, so targets are possibilities, not reachable behavior.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, decode_flow, dependencies
from inspect_startup_dependency import crosscheck_index

ROOTS = (0x1ab665, 0x20d0)
BOUND = 0x200
# Explicit previously verified inventory relevant to this queue, not a whole-repo
# catalog or authorization. Includes the historical first helper at 1070.
KNOWN = frozenset((0x1070, 0x1ab770, 0x1ab78c, 0x825bb0, 0x82a47b,
                   0x1240, 0x1250, 0x1270, 0x1290, 0x12d0,
                   0xfcf0, 0x9550, 0x1abd40))
REGS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')


def first_call_constants(nodes, edges, entry, budget=512):
    """Conservative full-GPR constants; partial/implicit writes kill knowledge.

    MOV reg,imm/reg and XOR reg,reg alone propagate constants. Memory is unknown;
    no stack, path feasibility, flags, imports, ABI or callee effects are inferred.
    Every path terminates at its first CALL or return. Exhaustion fails closed.
    """
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_REG, X86_OP_IMM
    pending = [(entry, (None,)*len(REGS))]
    seen, calls = set(), set()
    aliases = {alias: full for full, group in (
        ('eax', ('eax','ax','al','ah')), ('ebx', ('ebx','bx','bl','bh')),
        ('ecx', ('ecx','cx','cl','ch')), ('edx', ('edx','dx','dl','dh')),
        ('esi', ('esi','si')), ('edi', ('edi','di')),
        ('ebp', ('ebp','bp')), ('esp', ('esp','sp'))) for alias in group}
    while pending:
        address, values = pending.pop()
        if (address, values) in seen:
            continue
        if len(seen) >= budget:
            raise ValueError('Prefix analysis budget exhausted')
        seen.add((address, values))
        insn = nodes[address]
        state = dict(zip(REGS, values))
        if insn.group(CS_GRP_CALL):
            op = insn.operands[0]
            target = (op.imm & 0xffffffff) if op.type == X86_OP_IMM else (
                state.get(insn.reg_name(op.reg)) if op.type == X86_OP_REG else None)
            calls.add((address-BASE, target, state['edi']))
            continue
        updated = dict(state)
        for reg in insn.regs_access()[1]:
            full = aliases.get(insn.reg_name(reg))
            if full:
                updated[full] = None
        ops = insn.operands
        if len(ops) == 2 and ops[0].type == X86_OP_REG:
            dest = insn.reg_name(ops[0].reg)
            if dest in REGS:
                if insn.mnemonic == 'mov':
                    if ops[1].type == X86_OP_IMM:
                        updated[dest] = ops[1].imm & 0xffffffff
                    elif ops[1].type == X86_OP_REG:
                        updated[dest] = state.get(insn.reg_name(ops[1].reg))
                elif (insn.mnemonic == 'xor' and ops[1].type == X86_OP_REG
                      and ops[0].reg == ops[1].reg):
                    updated[dest] = 0
        pending.extend((n, tuple(updated[r] for r in REGS)) for n in edges[address])
    return [dict(site_rva=hex(site), target_rva=hex(target-BASE) if target is not None else None,
                 edi_constant=hex(edi) if edi is not None else None)
            for site, target, edi in sorted(calls, key=lambda c: tuple(-1 if v is None else v for v in c))]


def scope(nodes, edges, entry):
    deps = dependencies(nodes, type('PE', (), {})())
    direct = sorted(set(deps['direct_calls']), key=lambda r: int(r, 16))
    missing = [r for r in direct if int(r, 16) not in KNOWN]
    prefix = first_call_constants(nodes, edges, entry)
    return dict(direct_callee_rvas=direct,
        not_in_verified_inventory=missing,
        indirect_call_sites=[r['call_rva'] for r in deps['indirect_call_sites']],
        first_call_prefix_possibilities=prefix,
        needs_scoped_decision=bool(missing or deps['indirect_calls']),
        whole_caller_comparison_ready=False,
        reason='Root-only static evidence; missing inventory is not a whole-repo absence proof; new callee bodies/indirect ABI require a bounded decision')


def inspect(rva, index, output):
    if rva not in ROOTS:
        raise ValueError('Unapproved root')
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    # Reserve the output exclusively before inspecting any private input.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='ts2-continuation-scope/1', rva=hex(rva),
        inspection_complete=False, lifted=False, host_executed=False,
        arm64_executed=False, android_executed=False,
        dependencies_decoded=False, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)),
        limits=['HYPOTHESIS: normal-return flow, calls assumed returning',
                'Prefix constants overapproximate paths; no branch feasibility or behavior proof',
                'No callees read/lifted/executed; no reference states or production binding'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Wrong image mapping')
        code = pe.get_data(rva, BOUND)
        if len(code) != BOUND:
            raise ValueError('Short root window')
        _, nodes, edges, flow = decode_flow(code, BASE+rva, lambda i: i)
        body = dict(flow, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
        indexed = crosscheck_index(json.loads(index.read_text()), body, rva)
        report.update(image_sha256=IMAGE_SHA, index_sha256=digest(index),
            index=indexed, flow=flow, scope=scope(nodes, edges, BASE+rva))
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
    p.add_argument('--rva', type=lambda s: int(s, 16), required=True)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        report = inspect(a.rva, a.index, a.output)
    except Exception:
        p.exit(1, 'Root scope audit failed; no execution claim.\n')
    print('Root scope audited; whole-caller execution BLOCKED; no callee traversed')
    return 2 if report['scope']['needs_scoped_decision'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
