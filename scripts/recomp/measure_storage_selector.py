#!/usr/bin/env python3
"""Measure the real selector lift using existing ABI evidence, not new services.

Private original bodies/objects/states stay ignored. The external indirect tail
is retained verbatim and unresolved; compiling it is NOT native verification.
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
from measure_startup import BASE, dependencies, supported
from inspect_startup_dependency import crosscheck_index
from measure_resource_return import selection as prior_selection, assemble, require

RVA, SIZE = 0x8480BF, 63
TAIL_SLOT = BASE+0xD9A2C8


def selection():
    manifest = prior_selection()
    require(manifest['counts']['selected'] < manifest['authorization_limit'])
    require(f'0x{RVA:X}'.upper() not in {r['rva'].upper() for r in manifest['selected']})
    manifest['selected'].append(dict(rank=len(manifest['selected'])+1, rva=f'0x{RVA:X}',
        size_bytes=SIZE, categories=['startup or resource path', 'indirect call / vtable',
                                   'stack operations', 'direct call'],
        source='scripts/recomp/README.md',
        selection_rule='first dependency of 8460CF; reuse existing selector ABI reference',
        boundary_evidence='indexed extent plus explicit external indirect tail, not service identity',
        reliable_ghidra_boundary=None, dependencies=None, status='selected-not-attempted-this-run'))
    manifest['counts']['selected'] += 1
    return manifest


def decode_selector(code, entry, tail_slot, wrapper):
    """Bounded CFG with ONE declared absolute-memory external JMP, never a RET.

    Every linear instruction must be reachable. Other indirect jumps, interrupts,
    overlaps, escapes and interior targets reject. No callee behavior is inferred.
    Kept separate from the existing rejecting normal-return decoder.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INT
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    require(0 < len(code) <= 128 and BASE <= entry <= 0xFFFFFFFF-len(code))
    require(type(tail_slot) is int and 0 <= tail_slot <= 0xFFFFFFFC and tail_slot % 4 == 0)
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    linear = list(md.disasm(code, entry))
    require(sum(i.size for i in linear) == len(code))
    nodes = {i.address: i for i in linear}
    edges, leaders, calls, tails, returns = {}, {entry}, [], [], 0
    for i in linear:
        require(not i.group(CS_GRP_INT))
        end, successors = i.address+i.size, []
        if i.group(CS_GRP_RET):
            require(i.mnemonic == 'ret'); returns += 1
            leaders.add(end)
        elif i.group(CS_GRP_JUMP):
            require(len(i.operands) == 1)
            op = i.operands[0]
            if op.type == X86_OP_IMM:
                successors.append(op.imm & 0xFFFFFFFF)
                if i.mnemonic != 'jmp': successors.append(end)
            else:
                require(i.mnemonic == 'jmp' and op.type == X86_OP_MEM and
                        not op.mem.segment and not op.mem.base and not op.mem.index and
                        op.size == 4 and op.mem.disp & 0xFFFFFFFF == tail_slot)
                tails.append(i.address)
            leaders.update(successors); leaders.add(end)
        else:
            successors.append(end)
        require(all(a in nodes for a in successors))
        edges[i.address] = successors
        if i.group(CS_GRP_CALL):
            op = i.operands[0]
            calls.append(op.imm & 0xFFFFFFFF if op.type == X86_OP_IMM else None)
    require(len(tails) == 1 and returns > 0)
    seen, pending = set(), [entry]
    while pending:
        a = pending.pop()
        if a not in seen: seen.add(a); pending.extend(edges[a])
    require(seen == set(nodes))
    blocks, block = {}, None
    for i in linear:
        if block is None or i.address in leaders:
            block = SimpleNamespace(start=i.address, instructions=[]); blocks[i.address] = block
        block.instructions.append(wrapper(i))
    analysis = dict(size_bytes=len(code), reachable_bytes=len(code), instructions=len(nodes),
        edges=sum(map(len, edges.values())), blocks=len(blocks), calls=calls,
        instruction_rvas=[hex(i.address-BASE) for i in linear], linear_boundary_agreement=True,
        external_tail_sites=[hex(a-BASE) for a in tails], external_tail_slot_rva=hex(tail_slot-BASE),
        external_tail_is_return=False, call_effects_verified=False)
    return SimpleNamespace(name='storage_selector', address=entry, blocks=blocks), nodes, analysis


def measure(index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-storage-selector-measurement/1', rva=hex(RVA), size_bytes=SIZE,
        pcrecomp_revision=REVISION, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), selected=True, attempted=False, lifted=False,
        compiled_for_aarch64=False, linked=False, matched_x86_reference=False,
        executed_under_qemu=False, android_executed=False, commands=[], timings={},
        limits=['Existing x86 ABI rig uses authored resolver/guard/storage responses, NOT Windows services',
                'Resolver body is not executed by this isolated reference',
                'Object-only compilation, no native CPU-state comparison or integration',
                'External indirect tail retained, not converted into RET or bound'])
    stage = 'preflight'
    try:
        start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        row.update(image_sha256=IMAGE_SHA, selection=selection(), index_sha256=digest(index))
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        lock = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
        used = [n for n in lock['files'] if '/drm/' not in n]+['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        require(all(digest(upstream/n) == digest(pristine/n) for n in used))
        row['upstream_files'] = {n: digest(upstream/n) for n in used}
        sys.path.insert(0, str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
        code = pe.get_data(RVA, SIZE)
        require(len(code) == SIZE)
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'analysis'; row['attempted'] = True; start = time.monotonic()
        function, nodes, analysis = decode_selector(code, BASE+RVA, TAIL_SLOT, LinearInstruction)
        row.update(analysis=analysis, dependencies=dependencies(nodes, pe),
            index=crosscheck_index(json.loads(index.read_text()), analysis, RVA))
        imports = {i.address: dict(dll=d.dll.decode('ascii'),
            name=i.name.decode('ascii') if i.name else None, ordinal=i.ordinal)
            for d in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', ()) for i in d.imports}
        row['external_tail_import_metadata'] = imports.get(TAIL_SLOT)
        row['external_tail_metadata_is_binding'] = False
        row['timings']['analysis_and_index'] = time.monotonic()-start
        stage = 'existing-abi-reference'; start = time.monotonic()
        # Import existing rigs only after upstream import (both use a tools name).
        sys.path.insert(0, str(ROOT/'tools'))
        import ptd_query_probe as query
        row['isolated_x86_reference'] = query.probe(pe, json.loads(index.read_text())['result'])
        row['timings']['existing_abi_reference'] = time.monotonic()-start
        stage = 'translation'; start = time.monotonic()
        body = Lifter(precise_carry=True, lifted={BASE+RVA}).lift_function(function)
        row['timings']['translation'] = time.monotonic()-start
        row['lift_invocation'] = f'Lifter(precise_carry=True, lifted={{{hex(BASE+RVA)}}}).lift_function(function)'
        (output/'lifted.c').write_text(body)
        row['lifted_sha256'] = digest(output/'lifted.c')
        require(supported(body)); row['lifted'] = True
        (output/'object.c').write_text(assemble(body))
        for isa in ('host', 'arm64'):
            stage = isa+'-object'; start = time.monotonic()
            argv = ['zig-cc', *([] if isa=='host' else ['-target','aarch64-linux-musl']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream/'runtime/recomp32'),'-c',str(output/'object.c'),'-o',str(output/(isa+'.o'))]
            with (output/(isa+'.stdout')).open('xb') as out, (output/(isa+'.stderr')).open('xb') as err:
                result = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, timeout=120)
            row['commands'].append(dict(argv=argv, exit_code=result.returncode, seconds=time.monotonic()-start))
            require(result.returncode == 0)
            h = (output/(isa+'.o')).read_bytes()[:20]
            require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[16:18],'little') == 1 and
                    int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
            row[isa+'_object_compiled'] = True
            if isa == 'arm64': row['compiled_for_aarch64'] = True
        require(digest(image) == IMAGE_SHA)
        row['blocked_stage'] = 'native-dispatch-and-ABI-comparison'
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        measure(args.index, args.output)
    except Exception:
        print('Selector measurement rejected; inspect private metrics', file=sys.stderr); return 1
    print('8480BF lifted/ARM object compiled; NOT native matched or executed'); return 2


if __name__ == '__main__':
    raise SystemExit(main())
