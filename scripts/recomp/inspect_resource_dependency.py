#!/usr/bin/env python3
"""Bounded private index/decoder comparison for resource dependency 82A70A.

No lifting, service substitution, PE launch or nonreturn policy is introduced.
An indexed linear extent is not a complete returning control-flow graph.
"""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inspect_startup_dependency import crosscheck_index, first_direct_call
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, FlowRejection, decode_flow, dependencies

RVA = 0x82A70A
BOUND = 256


def characterize(code, base, indexed_size, pe):
    """Compare indexed linear boundaries and bounded normal-flow failures.

    One extra instruction is inspected separately, never assigned to the indexed
    function. Calls remain assumed returning in the unchanged normal-flow decoder.
    Metadata contains addresses/counts only, never encodings or disassembly.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_INT, CS_GRP_CALL
    from capstone.x86 import X86_OP_IMM
    if not (type(indexed_size) is int and 0 < indexed_size < len(code) <= BOUND):
        raise ValueError('Invalid bounded index extent')
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes = list(md.disasm(code[:indexed_size], base))
    if not nodes or sum(i.size for i in nodes) != indexed_size:
        raise ValueError('Incomplete indexed linear decode')
    body = dict(size_bytes=indexed_size, instructions=len(nodes),
                instruction_rvas=[hex(i.address-BASE) for i in nodes])
    following = next(md.disasm(code[indexed_size:], base+indexed_size, count=1), None)
    if following is None:
        raise ValueError('Missing adjacent instruction')
    row = dict(body=body, linear_dependencies=dependencies({i.address: i for i in nodes}, pe),
        linear_dependencies_are_complete_cfg=False,
        adjacent_instruction_rva=hex(following.address-BASE),
        adjacent_instruction_is_interrupt=following.group(CS_GRP_INT),
        adjacent_instruction_owned_by_function=False,
        adjacent_predecessor_is_direct_call=False,
        adjacent_predecessor_target_rva=None)
    last = nodes[-1]
    if last.group(CS_GRP_CALL) and last.operands[0].type == X86_OP_IMM:
        row.update(adjacent_predecessor_is_direct_call=True,
                   adjacent_predecessor_target_rva=hex((last.operands[0].imm & 0xFFFFFFFF)-BASE))
    for label, window in (('indexed', code[:indexed_size]),
                          ('with_one_adjacent_instruction', code[:indexed_size+following.size])):
        try:
            _, _, _, analysis = decode_flow(window, base, lambda i: i)
            row[label] = dict(accepted=True, instructions=analysis['instructions'])
        except FlowRejection as exc:
            row[label] = dict(accepted=False, reason=str(exc), evidence=exc.evidence)
    try:
        site, target = first_direct_call(code[:indexed_size], base)
        row['straight_prefix'] = dict(accepted=True, call_rva=hex(site-BASE), target_rva=hex(target-BASE))
    except ValueError as exc:
        row['straight_prefix'] = dict(accepted=False, reason=str(exc))
    return row


def run(index, output):
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    if output.exists():
        raise FileExistsError('Exclusive output required')
    start = time.monotonic()
    image = ROOT/'work/interop-legacy-002/analysis-image.bin'
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image pin mismatch')
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise ValueError('Wrong PE mapping')
    envelope = json.loads(index.read_text())
    function = envelope['result']['function']
    size = function['disassembly']['extentBytes']
    code = pe.get_data(RVA, BOUND)
    if len(code) != BOUND:
        raise ValueError('Short private inspection window')
    result = characterize(code, BASE+RVA, size, pe)
    indexed = crosscheck_index(envelope, result['body'], RVA)
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image changed during inspection')
    row = dict(schema='ts2-resource-dependency-inspection/1', rva=hex(RVA),
        image_sha256=IMAGE_SHA, index_sha256=digest(index), harness_sha256=digest(Path(__file__)),
        invocation=[sys.executable, *sys.argv], result=result, index=indexed,
        indexed_no_return=function['noReturn'], indexed_calling_convention=function['callingConvention'],
        index_metadata_is_behavioral_proof=False, elapsed_seconds=time.monotonic()-start,
        selected_new=False, lift_attempted=False, lifted=False, arm64_compiled=False,
        matched_x86=False, qemu_executed=False, android_executed=False,
        limits=['Static index/linear/normal-flow comparison, not execution or ABI proof',
                'HYPOTHESIS: returning call assumptions may expose adjacent trap after a nonreturn call',
                'Adjacent instruction is not assigned to indexed function ownership',
                'Callbacks, return/effects, SEH and original resource caller remain unresolved',
                'No callee stubs, path pruning or decoder/acceptance policy changes'])
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
        run(args.index, args.output)
    except (OSError, ValueError, KeyError, TypeError):
        print('Resource dependency inspection rejected; no ABI claim', file=sys.stderr)
        return 1
    print('Bounded dependency evidence recorded; no translation/execution claim')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
