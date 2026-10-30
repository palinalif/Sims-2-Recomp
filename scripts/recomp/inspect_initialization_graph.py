#!/usr/bin/env python3
"""Campaign E read-only initialization graph; no lift, reference run or bindings.

Reuse the settled root receipt, decode only the fixed investigation inventory,
and stop every unlisted edge. A frontier is NOT an authorized translation list.
"""
import argparse
from collections import deque
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inspect_continuation_scope import KNOWN
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, FlowRejection, decode_flow, dependencies
from inspect_startup_dependency import crosscheck_index

ROOT_RVA = 0x1ab665
SEED_SHA = 'c2ba70eb70bb93536021826ef630d852f99d9e8814ba06a09b8b635dc2ae1389'
# Root's measured direct callees plus documented opener/cleanup/producer boundaries.
# This fixed inventory is analysis-only; it does not authorize external bodies.
INTERNAL = frozenset((0x1030, 0x1070, 0x1090, 0x10a0, 0x10b0, 0x10c0,
    0x10e0, 0x1100, 0x1110, 0x1120, 0x1130, 0x1140, 0x3a50, 0x3c50,
    0x27d0, 0x3700, 0x831a6f, 0x831a54, 0x109d0, 0x10960, 0x10700))
BOUND = 0x400
MAX_NODES = 1 + len(INTERNAL)


def seed_receipt(path):
    if digest(path) != SEED_SHA:
        raise ValueError('Settled seed pin mismatch')
    row = json.loads(path.read_text())
    if (row['schema'] != 'ts2-continuation-scope/1' or
            row['image_sha256'] != IMAGE_SHA or row['rva'] != hex(ROOT_RVA) or
            row['inspection_complete'] is not True):
        raise ValueError('Invalid settled seed')
    return dict(complete=True, direct=row['scope']['direct_callee_rvas'],
        indirect=[], reused_seed=True, flow=row['flow'], index=row['index'])


def boundary_index(envelope, body, rva):
    """No indexed body is not evidence of absent code; caps are not agreement."""
    p, result = envelope['provenance'], envelope['result']
    if (envelope['schema'] != 'sims2-ghidra-query-envelope/1' or
            p['sourceImageSha256'] != IMAGE_SHA or p['mode'] != 'readOnly' or
            p['analysisPerformed'] is not False or p['headlessExitCode'] != 0 or
            p['outputParseError'] is not None or
            envelope['queryLogSignals']['scriptCompileError'] or
            int(result['query']['rva'], 16) != rva or
            int(result['program']['imageBaseVa'], 16) != BASE):
        raise ValueError('Index provenance mismatch')
    f = result['function']
    if (body is not None and f['resolution'] == 'function-at' and
            not result['truncation']['instructions']):
        return crosscheck_index(envelope, body, rva)
    return dict(boundaries_agree=False, resolution=f['resolution'],
        log_signals=envelope['queryLogSignals'], truncation=result['truncation'],
        interpretation='Index gap/cap or incomplete decoder: not boundary agreement')


def inspect_code(code, rva, pe, envelope):
    """Bounded normal flow or a single entry tail; never follow an external JMP."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    first = next(md.disasm(code[:15], BASE+rva, count=1), None)
    if first is not None and first.mnemonic == 'jmp' and first.operands[0].type == X86_OP_IMM:
        # Allocation wrappers may be direct tail thunks, not returning bodies.
        target = (first.operands[0].imm & 0xffffffff)-BASE
        body = dict(instructions=1, size_bytes=first.size, instruction_rvas=[hex(rva)])
        return dict(complete=True, direct=[], indirect=[], tails=[hex(target)],
            flow=body, index=boundary_index(envelope, body, rva), entry_tail=True)
    try:
        _, nodes, _, flow = decode_flow(code, BASE+rva, lambda i: i)
    except FlowRejection as exc:
        evidence = exc.evidence
        return dict(complete=False, direct=evidence['observed_direct_call_rvas'],
            escapes=[evidence['rejected_instruction_rva']],
            indirect=[], unresolved_indirect_count=evidence['observed_indirect_calls'],
            rejection=evidence, index=boundary_index(envelope, None, rva))
    deps = dependencies(nodes, pe)
    body = dict(flow, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
    return dict(complete=True, direct=sorted(set(deps['direct_calls']), key=lambda s:int(s,16)),
        indirect=deps['indirect_call_sites'], tails=[], flow=flow,
        index=boundary_index(envelope, body, rva))


def graph(seed, load, budget=MAX_NODES):
    """Deterministic BFS. Known/external targets are never passed to load()."""
    pending = deque([ROOT_RVA])
    queued, nodes, edges = {ROOT_RVA}, [], []
    while pending:
        if len(nodes) >= budget:
            raise ValueError('Graph node budget exhausted')
        rva = pending.popleft()
        row = dict(seed if rva == ROOT_RVA else load(rva))
        for field in ('direct', 'tails'):
            row[field] = sorted(set(row.get(field, [])), key=lambda s:int(s,16))
        nodes.append(dict(rva=hex(rva), classification='newly_needed', **row))
        for kind, targets in (('call', row['direct']), ('tail', row.get('tails', []))):
            for target in sorted(set(targets), key=lambda s:int(s,16)):
                dest = int(target, 16)
                category = ('already_verified' if dest in KNOWN else
                            'newly_needed' if dest in INTERNAL else 'external_frontier')
                edges.append(dict(source=hex(rva), target=hex(dest), kind=kind,
                                  classification=category))
                if category == 'newly_needed' and dest not in queued:
                    pending.append(dest)
                    queued.add(dest)
        # A rejected normal-flow successor is not necessarily a tail/function
        # entry. Record it, but never infer its owner or traverse its body.
        for target in row.get('escapes', []):
            edges.append(dict(source=hex(rva), target=target, kind='normal_flow_escape',
                classification='external_frontier' if int(target,16) not in INTERNAL | KNOWN
                else 'unresolved_decode_boundary'))
        for site in row['indirect']:
            edges.append(dict(source=hex(rva), target=None, kind='indirect',
                              classification='unresolved_indirect', **site))
    frontier = sorted({e['target'] for e in edges if e['classification']=='external_frontier'},
                      key=lambda s:int(s,16))
    leaf_units = [n['rva'] for n in nodes if n['complete'] and not n['direct'] and
                  not n['indirect'] and not n.get('tails') and not n.get('unresolved_indirect_count')]
    return dict(nodes=nodes, edges=edges, external_frontier=frontier,
        candidate_leaf_units=leaf_units, composed_execution_ready=False,
        bounded_decodes_complete=all(n['complete'] for n in nodes),
        interpretation='HYPOTHESIS: normal-return graph; no path feasibility/callee effects/ABI proof')


def inspect(output, index_dir):
    output, index_dir = output.resolve(), index_dir.resolve()
    private = (ROOT/'work/recomp-bench').resolve()
    if (not output.is_relative_to(private) or output == private or
            not index_dir.is_relative_to(private)):
        raise ValueError('Private output and index cache required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='ts2-initialization-graph/1', inspection_complete=False,
        image_sha256=IMAGE_SHA, seed_sha256=SEED_SHA, harness_sha256=digest(Path(__file__)),
        invocation=[sys.executable, *sys.argv], bound_bytes=BOUND, max_nodes=MAX_NODES,
        lifted=False, host_executed=False, arm64_executed=False, android_executed=False,
        limits=['No external-frontier bodies read, lifted or executed',
                'Callbacks stored as data are not call edges or verified callback contracts',
                'Leaf candidates require fresh lift and independent x86/native comparison',
                'No whole-caller input/producer/lifetime contract established'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Wrong image mapping')
        seed = seed_receipt(ROOT/'work/recomp-bench/frontier-d3-sibling-final/result.json')
        index_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        def load(rva):
            if rva not in INTERNAL or rva in KNOWN:
                raise ValueError('Unapproved body read')
            path = index_dir/f'{rva:x}.json'
            env = Path(str(path)+'.env.json')
            if not env.exists():
                subprocess.run([str(ROOT/'scripts/ghidra-query.sh'), '--rva', f'{rva:x}',
                    '--instructions', '320', '--refs', '8', '--callers', '8', '--callees', '32',
                    '--out', str(path), '--quiet'], check=True, timeout=90, capture_output=True)
            code = pe.get_data(rva, BOUND)
            if len(code) != BOUND:
                raise ValueError('Short body window')
            row = inspect_code(code, rva, pe, json.loads(env.read_text()))
            row['index_sha256'] = digest(env)
            (output/f'{rva:x}.json').write_text(json.dumps(row, indent=2)+'\n')
            return row
        report['graph'] = graph(seed, load)
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
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--index-dir', type=Path, required=True)
    a = p.parse_args()
    try:
        inspect(a.output, a.index_dir)
    except Exception:
        p.exit(1, 'Initialization graph rejected; see private failure receipt.\n')
    print('Bounded static graph recorded; external/indirect boundaries NOT executable')
    return 2  # Static evidence is never a composed execution pass.


if __name__ == '__main__':
    raise SystemExit(main())
