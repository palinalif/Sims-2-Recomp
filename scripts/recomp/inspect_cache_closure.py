#!/usr/bin/env python3
"""Fail-closed dependency preflight for the owner's explicit cache caller closure.

Stops before any lift/reference execution on a new direct or indirect dependency.
Private image/index output only; this does NOT widen the 25-function survey.
"""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, decode_flow
from inspect_startup_dependency import crosscheck_index

CLOSURE = (0x1abd40, 0x1240, 0x1250, 0x1270, 0x1290, 0x12d0)
LEAVES = (0x1290, 0x12d0)


def dependency_gate(nodes):
    """Calls and external tail jumps require explicit targets inside the closure.

    An unresolved indirect target is NOT evidence that it is in scope. No name,
    neighbouring RVA or old catalog can authorize it. Local branch targets must
    be decoded instruction boundaries. Returns are not inferred call targets.
    """
    from capstone import CS_GRP_CALL, CS_GRP_JUMP
    from capstone.x86 import X86_OP_IMM
    calls, blocked = [], []
    for address, insn in sorted(nodes.items()):
        if not (insn.group(CS_GRP_CALL) or insn.group(CS_GRP_JUMP)):
            continue
        direct = len(insn.operands) == 1 and insn.operands[0].type == X86_OP_IMM
        target = insn.operands[0].imm & 0xffffffff if direct else None
        if insn.group(CS_GRP_JUMP) and target in nodes:
            continue
        item = dict(site_rva=hex(address-BASE), kind='call' if insn.group(CS_GRP_CALL) else 'external-jump',
                    target_rva=hex(target-BASE) if target is not None else None,
                    indirect=not direct)
        calls.append(item)
        if target is None or target-BASE not in CLOSURE:
            blocked.append(item)
    return dict(dependencies=calls, unresolved_or_out_of_scope=blocked,
                ready_for_lift=not blocked)


def inspect(output, indexes):
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    if set(indexes) != set(LEAVES):
        raise ValueError('Both bounded persistent indexes required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='ts2-cache-closure-preflight/1', inspection_complete=False,
        caller_closure=[hex(r) for r in CLOSURE], survey_expanded=False,
        invocation=[sys.executable, *sys.argv], harness_sha256=digest(Path(__file__)),
        functions={}, ready_for_lift=False, lifted=False, host_executed=False,
        arm64_executed=False, android_executed=False,
        limits=['Static normal-flow hypothesis, not observed behavior or full function ownership',
                'Indirect target unresolved; no dispatch, authored callee, lift or reference execution',
                'A ready preflight is not correctness evidence or permission for new dependencies'])
    stage, start = 'preflight', time.monotonic()
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14c:
            raise ValueError('Image mapping mismatch')
        report['image_sha256'] = IMAGE_SHA
        for rva in LEAVES:
            stage = hex(rva)+'-analysis'
            row = report['functions'][hex(rva)] = dict(lifted=False)
            envelope = json.loads(indexes[rva].read_text())
            row['index_sha256'] = digest(indexes[rva])
            _, nodes, _, flow = decode_flow(pe.get_data(rva, 64), BASE+rva, lambda i: i)
            metadata = dict(flow, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
            row['index'] = crosscheck_index(envelope, metadata, rva)
            row.update(flow=flow, **dependency_gate(nodes))
            if not row['ready_for_lift']:
                report['blocked_stage'] = 'closure-dependency-scope'
                report['stop_rva'] = hex(rva)
                break  # Stop-and-record: do not inspect/translate the next body.
        else:
            report['ready_for_lift'] = True
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image changed')
        report['inspection_complete'] = True
    except Exception as exc:
        report.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        report['seconds'] = time.monotonic()-start
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--index-1290', type=Path, required=True)
    p.add_argument('--index-12d0', type=Path, required=True)
    a = p.parse_args()
    try:
        row = inspect(a.output, {0x1290:a.index_1290, 0x12d0:a.index_12d0})
    except Exception:
        p.exit(1, 'Cache closure inspection failed; inspect private result.\n')
    print('Cache closure: '+('preflight ready; NOT executed' if row['ready_for_lift'] else
                             'BLOCKED on unresolved/out-of-scope dependency; no lift/execution'))
    return 0 if row['ready_for_lift'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
