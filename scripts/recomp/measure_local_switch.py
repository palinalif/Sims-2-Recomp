#!/usr/bin/env python3
"""Bounded closure-leaf switch lift; object evidence only, NOT M1 execution."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from execute_cache_skip import private_output, require
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify
from measure_startup import BASE, supported


def decode_switch(code, base, table_va, targets, wrapper):
    """Explicit local table inventory, not automatic switch-size inference.

    Only an absolute indexed dword JMP using the declared table is admitted.
    Every supplied arm must decode inside the bound and be an independent linear
    instruction boundary. Unknown computed destinations retain external ITAIL.
    No calls, interrupts, segments or external immediate jumps are admitted.
    """
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_CALL, CS_GRP_INT
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    require(0 < len(code) <= 1024 and 0 < len(targets) <= 16)
    require(all(type(a) is int and base <= a < base+len(code) for a in targets))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    linear = {i.address:i for i in md.disasm(code,base)}
    require(all(a in linear for a in targets))
    pending, nodes, edges, leaders = [base], {}, {}, {base,*targets}
    switches = []
    while pending:
        a = pending.pop()
        if a in nodes:
            continue
        require(a in linear)
        i = linear[a]
        require(not i.group(CS_GRP_CALL) and not i.group(CS_GRP_INT) and
                not i.mnemonic.startswith('ud'))
        require(all(not op.mem.segment for op in i.operands if op.type == X86_OP_MEM))
        nodes[a] = i
        end = a+i.size
        successors = []
        if i.group(CS_GRP_RET):
            require(i.mnemonic == 'ret' and not i.operands)
        elif i.group(CS_GRP_JUMP):
            require(len(i.operands) == 1)
            op = i.operands[0]
            if op.type == X86_OP_IMM:
                successors = [op.imm & 0xffffffff]
                if i.mnemonic != 'jmp':
                    successors.append(end)
            else:
                require(i.mnemonic == 'jmp' and op.type == X86_OP_MEM and op.size == 4)
                m = op.mem
                require(not m.segment and not m.base and m.index and m.scale == 4 and
                        (m.disp & 0xffffffff) == table_va)
                successors = sorted(set(targets))
                switches.append(a)
            leaders.update(successors)
        else:
            require(not i.mnemonic.startswith('loop'))
            successors = [end]
        require(all(base <= s < base+len(code) for s in successors))
        edges[a] = successors
        pending.extend(successors)
    require(len(switches) == 1 and any(i.group(CS_GRP_RET) for i in nodes.values()))
    require(set(targets) <= nodes.keys())
    blocks, current, previous = {}, None, None
    for a,i in sorted(nodes.items()):
        if a in leaders or previous is None or previous.address+previous.size != a:
            current = SimpleNamespace(start=a,instructions=[])
            blocks[a] = current
        current.instructions.append(wrapper(i))
        previous = i
    func = SimpleNamespace(name=f'startup_{base-BASE:06X}',address=base,blocks=blocks,
                           jump_targets=set(targets))
    return func,nodes,edges


def measure(output,index):
    output = private_output(output)
    row = dict(schema='ts2-local-switch-object/1',success=False,rva='0x9550',
        invocation=[sys.executable,*sys.argv], harness_sha256=digest(Path(__file__)),
        pcrecomp_revision=REVISION,image_sha256=IMAGE_SHA,commands=[],runs={},
        matched_x86_reference=False,arm64_executed=False,android_executed=False,
        m1_complete=False,survey_expanded=False,
        limits=['object compilation only; no reference execution or runtime binding',
                'six-entry local table inventory is bounded static evidence, not encoding semantics',
                'unknown computed destinations retain ITAIL; no behavior response supplied'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        lock = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
        used = [n for n in lock['files'] if '/drm/' not in n]
        used += ['tools/lift/generate.py','tools/disasm/disasm32.py']
        require(all(digest(upstream/n) == digest(pristine/n) for n in used))
        row['upstream_files'] = {n:digest(upstream/n) for n in used}
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        envelope = json.loads(index.read_text())
        p,r = envelope['provenance'],envelope['result']
        require(envelope['schema'] == 'sims2-ghidra-query-envelope/1' and
                p['sourceImageSha256'] == IMAGE_SHA and p['mode'] == 'readOnly' and
                p['analysisPerformed'] is False and p['headlessExitCode'] == 0 and
                p['outputParseError'] is None and int(r['query']['rva'],16) == 0x9550 and
                int(r['program']['imageBaseVa'],16) == BASE)
        row['index_sha256'] = digest(index)
        row['index'] = dict(resolution=r['function']['resolution'],truncation=r['truncation'],
                            log_signals=envelope['queryLogSignals'],owns_boundary=False)
        # This specific table is within the owner-authorized 9550 closure body.
        # The six values and body window are written only to private outputs.
        targets = struct.unpack('<6I',pe.get_data(0x95c8,24))
        start = time.monotonic()
        func,nodes,edges = decode_switch(pe.get_data(0x9550,0x78),BASE+0x9550,
                                         BASE+0x95c8,targets,LinearInstruction)
        indexed = r['function']['disassembly']['items']
        # The advisory query is address-only/capped, not an authoritative extent.
        # Crosscheck its available prefix only; never promote it to full ownership.
        require(all(BASE+int(i['rva'],16) in nodes for i in indexed))
        row['index']['available_boundary_count'] = len(indexed)
        row['index']['available_boundaries_agree'] = True
        row['analysis_seconds'] = time.monotonic()-start
        row['flow'] = dict(instructions=len(nodes),blocks=len(func.blocks),
            reachable_bytes=sum(i.size for i in nodes.values()),
            extent_bytes=max(a+i.size for a,i in nodes.items())-func.address,
            table_entries=len(targets),unique_arms=len(set(targets)))
        (output/'flow.json').write_text(json.dumps(dict(edges=edges,targets=targets)))
        start = time.monotonic()
        body = Lifter(precise_carry=True,lifted={func.address}).lift_function(func)
        row['translation_seconds'] = time.monotonic()-start
        row['lift_api'] = 'Lifter(precise_carry=True,lifted={entry_va}).lift_function(function with jump_targets)'
        require(supported(body))
        require(all(f'case 0x{t:08X}u: goto L_{t:08X};' in body for t in set(targets)))
        require('default: RECOMP_ITAIL(_jt); return;' in body)
        (output/'lifted.c').write_text(body)
        row['lifted_sha256'] = digest(output/'lifted.c')
        (output/'object.c').write_text('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'+body+'\n')
        for isa in ('host','arm64'):
            argv = ['zig-cc',* ([] if isa == 'host' else ['-target','aarch64-linux-musl']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream/'runtime/recomp32'),'-c',str(output/'object.c'),'-o',str(output/(isa+'.o'))]
            start = time.monotonic()
            with (output/(isa+'.stdout')).open('xb') as out,(output/(isa+'.stderr')).open('xb') as err:
                child = subprocess.run(argv,stdout=out,stderr=err,timeout=120,cwd=ROOT)
            row['commands'].append(dict(argv=argv,exit_code=child.returncode,seconds=time.monotonic()-start))
            require(child.returncode == 0)
            h = (output/(isa+'.o')).read_bytes()[:20]
            require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[16:18],'little') == 1 and
                    int.from_bytes(h[18:20],'little') == (62 if isa == 'host' else 183))
            row['runs'][isa] = dict(object_compiled=True,executed=False)
        require(digest(image) == IMAGE_SHA)
        row['success'] = True
    except Exception as exc:
        row['error_type'] = type(exc).__name__
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--index',type=Path,required=True)
    a = p.parse_args()
    try:
        measure(a.output,a.index)
    except Exception:
        p.exit(1,'Local switch experiment failed; inspect private result.\n')
    print('Whole switch lift and both objects OK; NOT executed, M1 incomplete')
    return 0


if __name__ == '__main__':
    sys.exit(main())
