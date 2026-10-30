#!/usr/bin/env python3
"""Read-only inspection of the rejected tail's first direct dependency.

No lift, code execution, inferred ABI implementation, or candidate selection.
Only metadata/counts/addresses are emitted; original instructions stay private.
"""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_startup import BASE, TAIL_RVA, decode_flow
from measure_leaf import ROOT, IMAGE_SHA, digest

DEPENDENCY = 0x825BB0
CALLER_BOUND = 64
DEPENDENCY_BOUND = 128


def first_direct_call(code, base):
    """Only a contiguous straight-line entry prefix establishes the first call.

    Do not scan past an earlier indirect call, branch, return or trap. This is
    static instruction order, not proof the entry or call executes at runtime.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_INT
    from capstone.x86 import X86_OP_IMM
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for insn in md.disasm(code, base):
        if insn.group(CS_GRP_CALL):
            if len(insn.operands) != 1 or insn.operands[0].type != X86_OP_IMM:
                raise ValueError('Earlier indirect call')
            return insn.address, insn.operands[0].imm & 0xFFFFFFFF
        if (insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET) or
                insn.group(CS_GRP_INT) or insn.mnemonic.startswith(('loop', 'ud'))):
            raise ValueError('Control flow before first call')
    raise ValueError('No contiguous bounded first call')


def inspect_body(code, base):
    """Observe FS/GS and explicit frame-register writes; never infer an ABI.

    Reuses fail-closed normal-flow decoder, including independent linear-boundary
    agreement. Calls are NOT traversed. Return cleanup is an encoded immediate,
    not a net stack delta: prologue helpers can replace/rebase their caller frame.
    """
    from capstone import CS_AC_READ, CS_AC_WRITE, CS_GRP_RET
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM, X86_REG_FS, X86_REG_GS, X86_REG_ESP, X86_REG_EBP
    _, nodes, _, analysis = decode_flow(code, base, lambda i: i)
    segments, frame_writes, returns = [], [], []
    for insn in sorted(nodes.values(), key=lambda i: i.address):
        if insn.mnemonic.startswith('ud'):
            raise ValueError('Undefined instruction requires explicit trap policy')
        rva = hex(insn.address - BASE)
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.segment in (X86_REG_FS, X86_REG_GS):
                segments.append(dict(rva=rva, segment='fs' if op.mem.segment == X86_REG_FS else 'gs',
                    read=bool(op.access & CS_AC_READ), write=bool(op.access & CS_AC_WRITE)))
            if op.type == X86_OP_REG and op.reg in (X86_REG_ESP, X86_REG_EBP) and op.access & CS_AC_WRITE:
                frame_writes.append(dict(rva=rva, register='esp' if op.reg == X86_REG_ESP else 'ebp'))
        if insn.group(CS_GRP_RET):
            cleanup = insn.operands[0].imm if insn.operands and insn.operands[0].type == X86_OP_IMM else 0
            returns.append(dict(rva=rva, encoded_cleanup_bytes=cleanup))
    return dict(size_bytes=analysis['size_bytes'], instructions=analysis['instructions'],
        edges=analysis['edges'], blocks=analysis['blocks'],
        linear_boundary_agreement=analysis['linear_boundary_agreement'],
        instruction_rvas=[hex(a-BASE) for a in sorted(nodes)],
        direct_call_count=sum(c is not None for c in analysis['calls']),
        indirect_call_count=sum(c is None for c in analysis['calls']),
        segment_accesses=segments, explicit_frame_register_writes=frame_writes, returns=returns,
        abi_established=False, net_stack_delta=None, exception_semantics_verified=False,
        interpretation='HYPOTHESIS: frame/segment obligations only; calls assumed returning')


def crosscheck_index(envelope, body, rva=DEPENDENCY):
    """Require pinned read-only index provenance and exact instruction boundaries.

    Preserves warnings/truncation. Boundary agreement does not validate operands,
    Ghidra prototypes, exception flow, or behavior. The envelope is local evidence,
    not a cryptographic attestation of the Ghidra query process.
    """
    p = envelope['provenance']
    result = envelope['result']
    if (envelope['schema'] != 'sims2-ghidra-query-envelope/1' or
            p['sourceImageSha256'] != IMAGE_SHA or p['mode'] != 'readOnly' or
            p['analysisPerformed'] is not False or p['headlessExitCode'] != 0 or
            p['outputParseError'] is not None or int(result['query']['rva'], 16) != rva or
            int(result['program']['imageBaseVa'], 16) != BASE or
            result['function']['resolution'] != 'function-at' or
            int(result['function']['entryRva'], 16) != rva):
        raise ValueError('Index provenance/entry mismatch')
    dis = result['function']['disassembly']
    addresses = [hex(int(i['rva'], 16)) for i in dis['items']]
    if (addresses != body['instruction_rvas'] or
            dis['instructionCount'] != body['instructions'] or
            # Sims2Query.java emits the INCLUSIVE final byte, not the next PC.
            int(dis['extentEndVa'], 16) != BASE+rva+body['size_bytes']-1 or
            dis['extentBytes'] != body['size_bytes'] or
            result['truncation']['instructions']):
        raise ValueError('Index boundary mismatch')
    return dict(boundaries_agree=True, operand_semantics_compared=False,
        ghidra_version=p['ghidraVersion'], log_signals=envelope['queryLogSignals'],
        truncation=result['truncation'])


def inspect(output, index):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    if output.exists():
        raise FileExistsError('Exclusive output required')
    start = time.monotonic()
    image = ROOT / 'work/interop-legacy-002/analysis-image.bin'
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image pin mismatch')
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise ValueError('Wrong PE mapping')
    caller = pe.get_data(TAIL_RVA, CALLER_BOUND)
    code = pe.get_data(DEPENDENCY, DEPENDENCY_BOUND)
    if len(caller) != CALLER_BOUND or len(code) != DEPENDENCY_BOUND:
        raise ValueError('Short inspection window')
    site, target = first_direct_call(caller, BASE+TAIL_RVA)
    if target != BASE+DEPENDENCY:
        raise ValueError('First dependency changed')
    body = inspect_body(code, target)
    indexed = crosscheck_index(json.loads(index.read_text()), body)
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image changed during inspection')
    row = dict(schema='ts2-startup-dependency-inspection/1', image_sha256=IMAGE_SHA,
        invocation=[sys.executable, *sys.argv], caller_rva=hex(TAIL_RVA),
        call_site_rva=hex(site-BASE), dependency_rva=hex(DEPENDENCY),
        caller_window_bytes=CALLER_BOUND, dependency_window_bytes=DEPENDENCY_BOUND,
        body=body, index=indexed, elapsed_seconds=time.monotonic()-start,
        selected_for_translation=False, lifted=False, executed=False,
        limits=['static inspection, no CPU/reference states compared',
                'no SEH/TEB/FS implementation or binding',
                'encoded RET cleanup does not establish caller stack/return ABI',
                'tail interrupt rejection remains unchanged'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(row, stream, indent=2)
        stream.write('\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True, help='private Ghidra envelope JSON')
    ap.add_argument('--output', type=Path, required=True, help='new private metadata JSON')
    args = ap.parse_args()
    try:
        inspect(args.output, args.index)
    except (OSError, ValueError, KeyError, TypeError):
        print('Dependency inspection rejected; no execution performed', file=sys.stderr)
        return 1
    print('Static dependency inspection recorded; ABI/exception behavior unverified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
