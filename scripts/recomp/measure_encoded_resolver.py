#!/usr/bin/env python3
"""Measure the whole pinned encoded resolver; never prune its cold branches.

Private object compilation is not native correctness or Windows-service evidence.
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
from measure_resource_return import assemble, require
from measure_storage_selector import selection as prior_selection

RVA, SIZE = 0x847E6C, 133


def selection():
    manifest = prior_selection()
    require(manifest['counts']['selected'] < manifest['authorization_limit'])
    require(f'0x{RVA:X}'.upper() not in {r['rva'].upper() for r in manifest['selected']})
    manifest['selected'].append(dict(rank=len(manifest['selected'])+1, rva=f'0x{RVA:X}',
        size_bytes=SIZE, categories=['startup or resource path', 'direct call',
                                    'indirect call / vtable', 'stack operations'],
        source='scripts/recomp/README.md',
        selection_rule='actual resolver called by selected 8480BF; whole body including cold paths',
        boundary_evidence='existing persistent index and independent whole normal-flow decoding',
        reliable_ghidra_boundary=None, dependencies=None, status='selected-not-attempted-this-run'))
    manifest['counts']['selected'] += 1
    return manifest


def characterize(code, entry, wrapper):
    """Require every supplied byte in reachable CFG, not just a hot subset."""
    require(0 < len(code) <= 256)
    function, nodes, edges, analysis = decode_flow(code, entry, wrapper)
    require(analysis['size_bytes'] == analysis['reachable_bytes'] == len(code))
    analysis['instruction_rvas'] = [hex(a-BASE) for a in sorted(nodes)]
    analysis['cold_paths_pruned'] = False
    return function, nodes, edges, analysis


def measure(index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-encoded-resolver-measurement/1', rva=hex(RVA), size_bytes=SIZE,
        pcrecomp_revision=REVISION, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), selected=True, attempted=False, lifted=False,
        compiled_for_aarch64=False, linked=False, matched_x86_reference=False,
        executed_under_qemu=False, android_executed=False, commands=[], timings={},
        limits=['Whole-body translation; hot-only original x86 reference, NOT cold correctness',
                'Unresolved calls retained, no service replacements or cold-path pruning',
                'Object-only compilation: no native CPU comparison, linking or runtime binding',
                'Normal flow assumes returning calls; no FP/SEH/lifecycle/startup evidence'])
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
        function, nodes, edges, analysis = characterize(code, BASE+RVA, LinearInstruction)
        row.update(analysis=analysis, dependencies=dependencies(nodes, pe),
            index=crosscheck_index(json.loads(index.read_text()), analysis, RVA))
        (output/'flow.json').write_text(json.dumps(dict(edges=edges)))
        row['timings']['analysis_and_index'] = time.monotonic()-start
        stage = 'existing-hot-reference'; start = time.monotonic()
        sys.path.insert(0, str(ROOT/'tools'))
        import encoded_cache_probe as hot
        row['hot_x86_reference'] = hot.probe(pe, json.loads(index.read_text())['result'])
        row['timings']['existing_hot_reference'] = time.monotonic()-start
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
        row['blocked_stage'] = 'native-hot-comparison-and-cold-dependencies'
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
        print('Resolver measurement rejected; inspect private metrics', file=sys.stderr); return 1
    print('847E6C whole body lifted/ARM object compiled; NOT native matched or executed'); return 2


if __name__ == '__main__':
    raise SystemExit(main())
