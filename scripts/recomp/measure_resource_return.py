#!/usr/bin/env python3
"""Measure one additional resource return dependency, without invented services.

Supplement the historical fixed shortlist; never replace a failed candidate.
Original bytes, generated bodies, object files and detailed results stay private.
Object compilation is not linking, reference matching, or native execution.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify
from measure_startup import BASE, decode_flow, dependencies, supported
from inspect_startup_dependency import crosscheck_index
from select_candidates import select_candidates, MAX_FUNCTIONS

RVA = 0x82A528
SIZE = 70
BOUND = 128


def selection():
    """Re-runnable supplement, retaining every historical selection/rejection."""
    manifest = select_candidates()
    require(len(manifest['selected']) < MAX_FUNCTIONS)
    require(hex(RVA).upper() not in {r['rva'].upper() for r in manifest['selected']})
    manifest['selected'].append(dict(rank=len(manifest['selected'])+1, rva=f'0x{RVA:X}',
        size_bytes=SIZE, categories=['startup or resource path', 'direct call', 'stack operations'],
        source='scripts/recomp/README.md',
        selection_rule='first direct dependency on 82A70A null-pointee branch',
        boundary_evidence='indexed-normal-return-flow-only-not-behavior',
        reliable_ghidra_boundary=None, dependencies=None, status='selected-not-attempted-this-run'))
    manifest['counts']['selected'] += 1
    manifest['policy'] += '; explicit resource return-dependency supplement, no replacements'
    return manifest


def require(ok):
    if not ok:
        raise ValueError('Resource return measurement rejected')


def characterize(code, envelope, pe):
    """Independent normal-flow decoding vs persistent index; no ABI inference."""
    require(len(code) == SIZE and len(code) <= BOUND)
    function, nodes, edges, analysis = decode_flow(code, BASE+RVA, lambda i: i)
    require(analysis['size_bytes'] == SIZE)
    body = dict(analysis, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
    index = crosscheck_index(envelope, body, RVA)
    return function, nodes, edges, analysis, index, dependencies(nodes, pe)


def assemble(body):
    require(type(body) is str and body.strip() and supported(body))
    return '#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n'+body+'\n'


def measure(index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-resource-return-measurement/1', rva=hex(RVA), size_bytes=SIZE,
        pcrecomp_revision=REVISION, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), selected=True, attempted=False, lifted=False,
        compiled_for_aarch64=False, linked=False, matched_x86_reference=False,
        executed_under_qemu=False, android_executed=False, timings={}, commands=[], runs={},
        limits=['HYPOTHESIS: normal-return control flow, not observed return/ABI behavior',
                'No original execution or independent return/effects oracle',
                'Unresolved imports and direct dependency: no service stubs or target substitution',
                'Object-only compilation: no link, CPU-state comparison, FP/SEH or game startup'])
    stage = 'preflight'
    try:
        start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        row['image_sha256'] = IMAGE_SHA
        row['selection'] = selection()
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        lock = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
        used = [n for n in lock['files'] if '/drm/' not in n]
        used += ['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        require(all(digest(upstream/n) == digest(pristine/n) for n in used))
        row['upstream_files'] = {n: digest(upstream/n) for n in used}
        sys.path.insert(0, str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        origin = Path(sys.modules[Lifter.__module__].__file__).resolve()
        require(origin == (upstream/'tools/lift/lift32.py').resolve())
        row['lifter_module'] = str(origin)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
        row['index_sha256'] = digest(index)
        envelope = json.loads(index.read_text())
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'analysis'
        row['attempted'] = True
        start = time.monotonic()
        _, nodes, edges, analysis, indexed, deps = characterize(pe.get_data(RVA, SIZE), envelope, pe)
        row.update(analysis=analysis, index=indexed, dependencies=deps)
        # Construct blocks again using the exact pinned upstream wrapper, with
        # unchanged decoder policy and no rewriting of the emitted body.
        function, _, _, _ = decode_flow(pe.get_data(RVA, SIZE), BASE+RVA, LinearInstruction)
        row['timings']['analysis_and_index'] = time.monotonic()-start
        (output/'flow.json').write_text(json.dumps(dict(edges=edges,
            instructions={a: dict(mnemonic=i.mnemonic, operands=i.op_str) for a,i in nodes.items()})))
        stage = 'translation'
        start = time.monotonic()
        body = Lifter(precise_carry=True, lifted={BASE+RVA}).lift_function(function)
        row['timings']['translation'] = time.monotonic()-start
        row['lift_invocation'] = f'Lifter(precise_carry=True, lifted={{{hex(BASE+RVA)}}}).lift_function(function)'
        (output/'lifted.c').write_text(body)
        row['lifted_sha256'] = digest(output/'lifted.c')
        require(supported(body))
        row['lifted'] = True
        (output/'object.c').write_text(assemble(body))
        for isa in ('host', 'arm64'):
            stage = isa+'-object-compile'
            argv = ['zig-cc', *([] if isa=='host' else ['-target','aarch64-linux-musl']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-I'+str(upstream/'runtime/recomp32'),'-c',str(output/'object.c'),'-o',str(output/(isa+'.o'))]
            start = time.monotonic()
            with (output/(isa+'.stdout')).open('xb') as out, (output/(isa+'.stderr')).open('xb') as err:
                result = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=err, timeout=120)
            row['commands'].append(dict(argv=argv, exit_code=result.returncode, seconds=time.monotonic()-start))
            require(result.returncode == 0)
            header = (output/(isa+'.o')).read_bytes()[:20]
            require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[16:18],'little') == 1
                    and int.from_bytes(header[18:20],'little') == (62 if isa=='host' else 183))
            row['runs'][isa] = dict(object_compiled=True)
            if isa=='arm64':
                row['compiled_for_aarch64'] = True
        require(digest(image) == IMAGE_SHA)
        row['blocked_stage'] = 'reference-and-runtime-dependencies'
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
        row = measure(args.index, args.output)
    except Exception:
        print('Return dependency measurement rejected; inspect private metrics', file=sys.stderr)
        return 1
    print('RVA 82A528: lifted=%s ARM object=%s; NOT linked/matched/executed' %
          (row['lifted'], row['compiled_for_aarch64']))
    return 2  # Incomplete pipeline, never a successful behavioral comparison.


if __name__ == '__main__':
    raise SystemExit(main())
