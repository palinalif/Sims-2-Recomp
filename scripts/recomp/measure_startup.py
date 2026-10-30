#!/usr/bin/env python3
"""Bounded selected startup dependency lift; no PE launch, service stubs or recovery.

Only selected startup RVAs, resource entry 1E36F0, its bounded failure-path
dependency, selected cache caller 1ABD40, attachment funnel 9B52C0 and candidate
rebuild 1E95C0, factories 1D3E20/1DA310, callback producer 1460 and
cache/mapping caller 1AB7E0 are
accepted. Indexed measurements require a pinned index.
Output includes derived private code.
Object compilation is NOT linking, execution or differential verification.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify

RVA = 0x8258A9
ENTRY_RVA = 0x8248A3
TAIL_RVA = 0x824727
FRAME_RVA = 0x825BB0
RESOURCE_RVA = 0x1E36F0
HANDLER_RVA = 0x82A6D3
RESOURCE_LEAF_RVA = 0x82A47B
CACHE_REFRESH_RVA = 0x1ABD40
ATTACHMENT_RVA = 0x9B52C0
REBUILD_RVA = 0x1E95C0
FACTORY_RVA = 0x1D3E20
SIBLING_FACTORY_RVA = 0x1DA310
CALLBACK_PRODUCER_RVA = 0x1460
CACHE_MAPPING_RVA = 0x1AB7E0
INDEXED_RVAS = (RESOURCE_RVA, HANDLER_RVA, RESOURCE_LEAF_RVA, CACHE_REFRESH_RVA,
                ATTACHMENT_RVA, REBUILD_RVA, FACTORY_RVA, SIBLING_FACTORY_RVA,
                CALLBACK_PRODUCER_RVA, CACHE_MAPPING_RVA)
ALLOWED_RVAS = (RVA, 0x82585C, ENTRY_RVA, TAIL_RVA, FRAME_RVA, *INDEXED_RVAS)
BASE = 0xA0000000
BOUND = 0x400


def dependencies(nodes, pe):
    """Resolve only absolute IAT call operands; never guess register targets.

    Import metadata names a dependency, not a native binding or ABI contract.
    """
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    imports = {i.address: dict(dll=d.dll.decode('ascii'),
                name=i.name.decode('ascii') if i.name else None, ordinal=i.ordinal)
               for d in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', ()) for i in d.imports}
    absolute = set()
    direct, indirect, segmented = [], [], []
    for insn in sorted(nodes.values(), key=lambda i: i.address):
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                if op.mem.segment:
                    segmented.append(dict(instruction_rva=hex(insn.address - BASE),
                        segment=insn.reg_name(op.mem.segment),
                        displacement=op.mem.disp, size_bytes=op.size))
                elif not op.mem.base and not op.mem.index:
                    absolute.add(op.mem.disp & 0xFFFFFFFF)
        if not insn.group(CS_GRP_CALL):
            continue
        op = insn.operands[0]
        if op.type == X86_OP_IMM:
            direct.append(hex((op.imm & 0xFFFFFFFF) - BASE))
            continue
        slot = (op.mem.disp & 0xFFFFFFFF) if (op.type == X86_OP_MEM and
                not op.mem.segment and not op.mem.base and not op.mem.index) else None
        indirect.append(dict(call_rva=hex(insn.address - BASE),
            slot_rva=hex(slot - BASE) if slot is not None else None,
            import_metadata=imports.get(slot)))
    return dict(direct_calls=direct, indirect_calls=len(indirect),
                indirect_call_sites=indirect,
                absolute_memory_va=[hex(a) for a in sorted(absolute)],
                segmented_memory_operands=segmented)


class FlowRejection(ValueError):
    """Sanitized partial-analysis evidence, never instructions/bytes or a full CFG."""

    def __init__(self, message, address, nodes, pending):
        super().__init__(message)
        from capstone import CS_GRP_CALL
        from capstone.x86 import X86_OP_IMM
        calls = [i for i in nodes.values() if i.group(CS_GRP_CALL)]
        direct = [i.operands[0].imm & 0xFFFFFFFF for i in calls
                  if i.operands and i.operands[0].type == X86_OP_IMM]
        predecessor = next((i for i in nodes.values() if i.address+i.size == address), None)
        preceding_call = predecessor is not None and predecessor.group(CS_GRP_CALL)
        preceding_target = (predecessor.operands[0].imm & 0xFFFFFFFF
            if preceding_call and predecessor.operands[0].type == X86_OP_IMM else None)
        self.evidence = dict(rejected_instruction_rva=hex(address-BASE),
            adjacent_predecessor_rva=hex(predecessor.address-BASE) if predecessor else None,
            adjacent_predecessor_is_call=bool(preceding_call),
            adjacent_call_target_rva=hex(preceding_target-BASE) if preceding_target is not None else None,
            visited_instructions=len(nodes), pending_addresses=len(set(pending)),
            observed_direct_call_rvas=[hex(a-BASE) for a in sorted(set(direct))],
            observed_indirect_calls=len(calls)-len(direct),
            complete_cfg=False, dependencies_complete=False)


def decode_flow(code, base, wrapper):
    """Normal-return CFG, ignoring call effects; reject escapes/overlaps/indirect JMP.

    Does not infer entry identity, exception flow, reachability or callee behavior.
    A separate linear sweep must agree on every reachable instruction boundary.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INT
    from capstone.x86 import X86_OP_IMM
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    nodes, edges, leaders, calls = {}, {}, {base}, []
    pending = [base]
    while pending:
        address = pending.pop()
        if address in nodes:
            continue
        offset = address - base
        if not 0 <= offset < len(code):
            raise FlowRejection('Escaping normal flow', address, nodes, pending)
        insn = next(md.disasm(code[offset:offset + 15], address, count=1), None)
        if insn is None:
            raise ValueError('Undecodable normal flow')
        end = address + insn.size
        if any(address < other.address + other.size and other.address < end
               for other in nodes.values()):
            raise ValueError('Overlapping instructions')
        if insn.group(CS_GRP_INT):
            # Neither a returning instruction nor an ordinary fallthrough edge.
            # Reject until a separately verified trap/nonreturn policy exists.
            raise FlowRejection('Interrupt requires explicit nonreturn policy',
                                address, nodes, pending)
        nodes[address] = insn
        successors = []
        if insn.group(CS_GRP_RET):
            if insn.mnemonic != 'ret':
                raise ValueError('Unsupported return')
        elif insn.group(CS_GRP_JUMP) or insn.mnemonic.startswith('loop'):
            if not insn.operands or insn.operands[0].type != X86_OP_IMM:
                raise ValueError('Unresolved jump')
            successors.append(insn.operands[0].imm & 0xFFFFFFFF)
            if insn.mnemonic != 'jmp':
                successors.append(end)
            leaders.update(successors)
        else:
            successors.append(end)
        if insn.group(CS_GRP_CALL):
            op = insn.operands[0]
            calls.append(op.imm & 0xFFFFFFFF if op.type == X86_OP_IMM else None)
        edges[address] = successors
        pending.extend(successors)
    if not any(i.group(CS_GRP_RET) for i in nodes.values()):
        raise ValueError('No bounded return')
    extent = max(i.address + i.size for i in nodes.values()) - base
    linear = {i.address: i for i in md.disasm(code[:extent], base)}
    if any(a not in linear or linear[a].bytes != i.bytes for a, i in nodes.items()):
        raise ValueError('Linear boundary disagreement')
    blocks = {}
    current = None
    previous = None
    for a, insn in sorted(nodes.items()):
        if a in leaders or previous is None or previous.address + previous.size != a:
            current = SimpleNamespace(start=a, instructions=[])
            blocks[a] = current
        current.instructions.append(wrapper(insn))
        previous = insn
    function = SimpleNamespace(name=f'startup_{base - BASE:06X}', address=base, blocks=blocks)
    return function, nodes, edges, dict(size_bytes=extent, reachable_bytes=sum(i.size for i in nodes.values()),
        instructions=len(nodes), blocks=len(blocks), edges=sum(map(len, edges.values())),
        calls=calls, linear_boundary_agreement=True,
        boundary_interpretation='HYPOTHESIS: bounded normal flow, not indexed function ownership')


def decode_tail(code, base, call_target, tail_target, wrapper):
    """Exactly one direct CALL and external JMP; never decode the tail target.

    Separate from normal-return decoding: no RET or returning-tail assumption.
    Targets are explicit contracts, not inferred from nearest indexed functions.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from capstone.x86 import X86_OP_IMM
    if len(code) != 10 or base <= tail_target < base + len(code):
        raise ValueError('Invalid external-tail boundary')
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    instructions = list(md.disasm(code, base))
    if len(instructions) != 2:
        raise ValueError('Invalid external-tail boundary')
    for n, (insn, mnemonic, target) in enumerate(zip(
            instructions, ('call', 'jmp'), (call_target, tail_target))):
        if (insn.address != base + n*5 or insn.size != 5 or
                insn.mnemonic != mnemonic or len(insn.operands) != 1 or
                insn.operands[0].type != X86_OP_IMM or
                (insn.operands[0].imm & 0xFFFFFFFF) != target):
            raise ValueError('Unexpected call/tail contract')
    nodes = {i.address: i for i in instructions}
    block = SimpleNamespace(start=base, instructions=[wrapper(i) for i in instructions])
    function = SimpleNamespace(name=f'startup_{base - BASE:06X}', address=base,
                               blocks={base: block})
    return function, nodes, {base: [base+5], base+5: [tail_target]}, dict(
        size_bytes=10, reachable_bytes=10, instructions=2, blocks=1, edges=2,
        calls=[call_target], external_tail_va=hex(tail_target),
        tail_target_decoded=False, linear_boundary_agreement=True,
        boundary_interpretation='explicit call/tail boundary; calls assumed returning; target excluded')


def decode_candidate(code, rva, wrapper):
    """Selected boundary policy; unknown candidates never reach the decoder."""
    if rva not in ALLOWED_RVAS:
        raise ValueError('Unselected startup candidate')
    if rva == ENTRY_RVA:
        return decode_tail(code[:10], BASE+rva, BASE+RVA, BASE+TAIL_RVA, wrapper)
    # Do not merge the known original entry into its preceding tail region.
    bounded = code[:ENTRY_RVA-TAIL_RVA] if rva == TAIL_RVA else code
    return decode_flow(bounded, BASE+rva, wrapper)


def resource_index_context(envelope, rva=RESOURCE_RVA):
    """Validate selected index provenance; preserve caps/errors on failure."""
    if rva not in INDEXED_RVAS:
        raise ValueError('Unselected indexed candidate')
    p, result = envelope['provenance'], envelope['result']
    if (envelope['schema'] != 'sims2-ghidra-query-envelope/1' or
            p['sourceImageSha256'] != IMAGE_SHA or p['mode'] != 'readOnly' or
            p['analysisPerformed'] is not False or p['headlessExitCode'] != 0 or
            p['outputParseError'] is not None or
            int(result['query']['rva'], 16) != rva or
            int(result['program']['imageBaseVa'], 16) != BASE or
            result['function']['resolution'] != 'function-at' or
            int(result['function']['entryRva'], 16) != rva):
        raise ValueError('Resource index provenance/entry mismatch')
    dis = result['function']['disassembly']
    return dict(ghidra_version=p['ghidraVersion'],
        log_signals=envelope['queryLogSignals'], truncation=result['truncation'],
        indexed_instructions=dis['instructionCount'], indexed_extent_bytes=dis['extentBytes'],
        indexed_extent_end_va=dis['extentEndVa'],
        boundaries_crosschecked=False, interpretation='index extent may be a capped lower bound')


def decode_resource(code, context, wrapper, rva=RESOURCE_RVA):
    """Never absorb bytes after the selected index extent to invent a return."""
    if rva not in INDEXED_RVAS:
        raise ValueError('Unselected indexed candidate')
    if context['truncation']['instructions']:
        raise ValueError('Capped resource index extent')
    extent = context['indexed_extent_bytes']
    if (not isinstance(extent, int) or not 0 < extent <= min(len(code), BOUND) or
            int(context['indexed_extent_end_va'], 16) != BASE+rva+extent-1):
        raise ValueError('Resource index extent mismatch')
    return decode_candidate(code[:extent], rva, wrapper)


def supported(body):
    return not any(marker in body.lower() for marker in ('unimplemented', 'unhandled', 'unresolved'))


def measure(output, rva=RVA, index=None):
    if rva not in ALLOWED_RVAS:
        raise ValueError('Unselected startup candidate')
    if rva in INDEXED_RVAS and index is None:
        raise ValueError('Selected resource/dependency requires index envelope')
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-startup-attempt/1', rva=hex(rva), category=['startup or resource path'],
        invocation=[sys.executable, *sys.argv], pcrecomp_revision=REVISION,
        harness_sha256=digest(Path(__file__)),
        attempted=False, lifted=False, compiled_for_aarch64=False, linked=False,
        matched_x86_reference=False, executed_under_qemu=False, android_executed=False,
        ghidra_boundaries_reliable=None, timings={}, commands=[], runs={},
        limits=['normal-flow assumes returning calls; no SEH/nonreturn model',
                'object compilation only; no service stubs or executable',
                'no original x86 reference run or CPU state comparison'])
    if rva in (CACHE_REFRESH_RVA, CACHE_MAPPING_RVA):
        row['category'] = ['memory access through pointers', 'direct call']
        row['limits'].append('caller only; unverified callees are not lifted or stubbed')
    if rva == CACHE_MAPPING_RVA:
        row['limits'].append('cache/mapping caller only; jump-table dependency and ownership remain unresolved')
    if rva in (RESOURCE_RVA, ATTACHMENT_RVA, REBUILD_RVA, CALLBACK_PRODUCER_RVA):
        row['category'].append('indirect call / vtable')
    if rva == CALLBACK_PRODUCER_RVA:
        row['limits'].append('callback producer only; service/output ownership and failure callbacks remain unresolved')
    if rva == ATTACHMENT_RVA:
        row['limits'].append('attachment caller only; callback/lock/container dependencies remain unresolved')
    if rva == REBUILD_RVA:
        row['limits'].append('candidate rebuild only; enumeration/callback/sort/container dependencies remain unresolved')
    if rva in (FACTORY_RVA, SIBLING_FACTORY_RVA):
        row['limits'].append('factory only; allocation/construction/registration and FS/SEH dependencies remain unresolved')
    stage = 'preflight'
    try:
        start = time.monotonic()
        image = ROOT / 'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        upstream = ROOT / 'work/interop-legacy-002/pcrecomp'
        pristine = ROOT / 'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        lock = json.loads((ROOT / 'config/dependencies.lock.json').read_text())['pcrecomp']
        used = [name for name in lock['files'] if '/drm/' not in name]
        used += ['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        for name in used:
            if digest(upstream / name) != digest(pristine / name):
                raise ValueError('Private lifter differs')
        row['upstream_files'] = {name: digest(upstream / name) for name in used}
        row['image_sha256'] = IMAGE_SHA
        sys.path.insert(0, str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        origin = Path(sys.modules[Lifter.__module__].__file__).resolve()
        if origin != (upstream / 'tools/lift/lift32.py').resolve():
            raise ValueError('Wrong lifter origin')
        row['lifter_module'] = str(origin)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14C:
            raise ValueError('Wrong PE mapping')
        code = pe.get_data(rva, BOUND)
        if len(code) != BOUND:
            raise ValueError('Short code window')
        if rva in INDEXED_RVAS:
            row['index_context'] = resource_index_context(json.loads(index.read_text()), rva)
            row['index_sha256'] = digest(index)
        row['timings']['preflight'] = time.monotonic() - start
        stage = 'analysis'
        row['attempted'] = True
        start = time.monotonic()
        try:
            if rva in INDEXED_RVAS:
                function, nodes, edges, analysis = decode_resource(code, row['index_context'], LinearInstruction, rva)
            else:
                function, nodes, edges, analysis = decode_candidate(code, rva, LinearInstruction)
        finally:
            row['timings']['analysis'] = time.monotonic() - start
        if rva == ENTRY_RVA:
            row['limits'][0] = 'explicit external-tail boundary; CALL assumed returning; no SEH/nonreturn model'
        row['analysis'] = analysis
        row['size_bytes'] = analysis['size_bytes']
        row['dependencies'] = dependencies(nodes, pe)
        if rva in INDEXED_RVAS:
            # Reuse the existing provenance and inclusive-end boundary contract.
            # Index warnings/truncation are retained, not converted into success.
            from inspect_startup_dependency import crosscheck_index
            stage = 'index-crosscheck'
            start = time.monotonic()
            body_metadata = dict(analysis,
                instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
            row['index'] = crosscheck_index(json.loads(index.read_text()), body_metadata, rva)
            row['index_sha256'] = digest(index)
            row['timings']['index_crosscheck'] = time.monotonic() - start
            row['index_context']['boundaries_crosschecked'] = True
            row['ghidra_boundaries_reliable'] = True  # boundaries only, not ABI/semantics
            row['limits'].append('index boundary agreement does not validate ABI or indirect targets')
        (output / 'flow.json').write_text(json.dumps(dict(edges=edges,
            instructions={a: dict(mnemonic=i.mnemonic, operands=i.op_str) for a, i in nodes.items()})))
        stage = 'translation'
        start = time.monotonic()
        # Only this entry is emitted; other direct calls retain exact-VA dispatch.
        body = Lifter(precise_carry=True, lifted={function.address}).lift_function(function)
        row['timings']['translation'] = time.monotonic() - start
        row['lift_invocation'] = (f'Lifter(precise_carry=True, lifted={{{hex(function.address)}}})'
                                  f'.lift_function(function); exact VA {hex(function.address)}')
        (output / 'lifted.c').write_text(body)
        row['lifted_sha256'] = digest(output / 'lifted.c')
        if not supported(body):
            row['blocked_stage'] = 'translation-unsupported'
            return row
        row['lifted'] = True
        source = '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n' + body + '\n'
        (output / 'object.c').write_text(source)
        for isa in ('host', 'arm64'):
            stage = isa + '-object-compile'
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl']
            argv = ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11', '-O0',
                '-Werror=implicit-function-declaration', '-I' + str(upstream / 'runtime/recomp32'),
                '-c', str(output / 'object.c'), '-o', str(output / (isa + '.o'))]
            start = time.monotonic()
            with (output / (isa + '.stdout')).open('xb') as out, (output / (isa + '.stderr')).open('xb') as err:
                result = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, timeout=120)
            row['commands'].append(dict(argv=argv, exit_code=result.returncode,
                                       seconds=time.monotonic() - start))
            row['runs'][isa] = dict(object_compiled=False)
            if result.returncode:
                raise ValueError('Object compilation failed')
            header = (output / (isa + '.o')).read_bytes()[:20]
            if (header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[16:18], 'little') != 1 or
                    int.from_bytes(header[18:20], 'little') != (62 if isa == 'host' else 183)):
                raise ValueError('Wrong ELF object')
            row['runs'][isa]['object_compiled'] = True
            if isa == 'arm64':
                row['compiled_for_aarch64'] = True
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image changed during measurement')
        row['blocked_stage'] = 'reference-and-runtime-dependencies'
    except Exception as exc:
        row['failed_stage'] = stage
        row['error_type'] = type(exc).__name__
        if stage == 'analysis':
            reasons = {'Interrupt requires explicit nonreturn policy': 'interrupt-without-nonreturn-policy',
                       'Escaping normal flow': 'escaping-normal-flow',
                       'Capped resource index extent': 'capped-resource-index-extent'}
            if str(exc) in reasons:
                row['analysis_rejection'] = reasons[str(exc)]
            if isinstance(exc, FlowRejection):
                row['partial_analysis'] = exc.evidence
        raise
    finally:
        (output / 'metrics.jsonl').write_text(json.dumps(row) + '\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rva', type=lambda s: int(s, 16), choices=ALLOWED_RVAS, default=RVA)
    parser.add_argument('--index', type=Path, help='required read-only envelope for resource entry/dependency')
    args = parser.parse_args()
    try:
        row = measure(args.output, args.rva, args.index)
    except Exception:
        parser.exit(1, 'Startup attempt failed; inspect private metrics/logs.\n')
    print('RVA %X: attempted; lifted=%s; ARM object=%s; unverified, not executed' %
          (args.rva, row['lifted'], row['compiled_for_aarch64']))
    return 2  # intentionally incomplete pipeline, including successful object compilation


if __name__ == '__main__':
    sys.exit(main())
