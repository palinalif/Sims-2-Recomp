#!/usr/bin/env python3
"""Fresh lift of the pinned four-body cache rig, then saved-x86 comparisons.

Private inputs/output only. Reuses the unchanged rig and exact source pin before
adapting its checked-memory/dispatch boundary. No fresh x86 run or Android claim.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify
from measure_startup import decode_flow, dependencies
sys.path.insert(0, str(ROOT / 'tools'))
from prepare_private_scoped_dispatch import prepare, SOURCE_SHA, REFERENCE_SHA
from check_private_scoped_dispatch import check

RIG_SHA = '4285d00e7da1ebe3596a3b5309e5c0eb78c5b6cec1a1529a60579d8b4c469ea1'
CATALOG_SHA = '8b82d4a44732c47315752109553ab19c5b458c9732505efca2e8fc6704b988dc'
RVAS = (0x1250, 0x1270, 0x1AB770, 0x1AB78C)


def index_context(envelope, rva):
    """Index is advisory here: pinned rig, not a capped sweep, owns the extent."""
    p, result = envelope['provenance'], envelope['result']
    if (envelope['schema'] != 'sims2-ghidra-query-envelope/1' or
            p['sourceImageSha256'] != IMAGE_SHA or p['mode'] != 'readOnly' or
            p['analysisPerformed'] is not False or p['headlessExitCode'] != 0 or
            p['outputParseError'] is not None or
            int(result['query']['rva'], 16) != rva or
            int(result['program']['imageBaseVa'], 16) != 0xA0000000):
        raise ValueError('Index provenance mismatch')
    return dict(resolution=result['function']['resolution'],
                truncation=result['truncation'], log_signals=envelope['queryLogSignals'],
                ghidra_version=p['ghidraVersion'],
                reliable_boundaries=False,
                interpretation='advisory only; exact pinned rig range independently decoded')


def require_complete(report):
    if (set(report['functions']) != {hex(rva) for rva in RVAS} or
            not all(row['lifted'] for row in report['functions'].values()) or
            report['generated_source_sha256'] != SOURCE_SHA or
            set(report['runs']) != {'host', 'arm64'}):
        raise ValueError('Incomplete fresh pipeline')
    for run in report['runs'].values():
        if (not run['compiled'] or not run['executed'] or
                run['exit_code'] != 0 or run['matched'] != 64):
            raise ValueError('Incomplete execution/comparison')
    if report['runs']['host']['stdout_sha256'] != report['runs']['arm64']['stdout_sha256']:
        raise ValueError('Cross-ISA output differs')


def measure(output, indexes):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    if set(indexes) != {0x1270, 0x1AB770, 0x1AB78C}:
        raise ValueError('Three persistent index queries required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(schema='ts2-fresh-wrapper-group/1', success=False,
        pcrecomp_revision=REVISION, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), functions={}, runs={}, commands=[],
        timings={}, fresh_x86_reference=False, android_executed=False,
        limits=['64 saved x86/oracle cases, not fresh x86 execution',
                'two wrapper entries; leaf 1270 tested only through wrapper 1AB770',
                'all GPRs, defined flags, memory deltas, FP depth/empty stack transport',
                'undefined AF normalized only by unchanged pinned rig',
                'no transient writes, native PC/RET, FP arithmetic, threads or ownership',
                'fixture-specific checked window/dispatch, not production integration'])
    stage = 'preflight'

    def command(name, argv):
        record = dict(name=name, argv=[str(a) for a in argv], exit_code=None)
        report['commands'].append(record)
        start = time.monotonic()
        try:
            with (output / (name + '.stdout')).open('xb') as out, \
                 (output / (name + '.stderr')).open('xb') as err:
                run = subprocess.run(record['argv'], cwd=ROOT, stdout=out,
                                     stderr=err, timeout=180)
            record['exit_code'] = run.returncode
            if run.returncode:
                raise ValueError('Child failed')
        finally:
            record['seconds'] = time.monotonic() - start
        return record

    try:
        start = time.monotonic()
        fixture = ROOT / 'work/interop-legacy-002'
        image = fixture / 'analysis-image.bin'
        rig_path = fixture / 'wrapper_probe.py'
        catalog = fixture / 'wrapper-reference.json'
        reference = fixture / 'wrapper-bundle/reference.json'
        for path, pin in ((image, IMAGE_SHA), (rig_path, RIG_SHA),
                          (catalog, CATALOG_SHA), (reference, REFERENCE_SHA)):
            if digest(path) != pin:
                raise ValueError('Private input pin mismatch')
        report['pins'] = dict(image=IMAGE_SHA, rig=RIG_SHA, catalog=CATALOG_SHA,
                              reference=REFERENCE_SHA)
        upstream = fixture / 'pcrecomp'
        pristine = ROOT / 'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        locked = json.loads((ROOT / 'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [name for name in locked if '/drm/' not in name]
        used += ['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        for name in used:
            if digest(upstream / name) != digest(pristine / name):
                raise ValueError('Private upstream differs')
        report['upstream_files'] = {name: digest(upstream / name) for name in used}
        sys.path.insert(0, str(upstream))
        from tools.lift import difftest  # noqa: F401
        from tools.lift.generate import LinearInstruction
        spec = importlib.util.spec_from_file_location('private_wrapper_rig', rig_path)
        rig = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(rig)  # Never invoke main/run_host or write fixtures.
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        codes = rig.read_codes()
        saved = json.loads(catalog.read_text())
        if set(codes) != set(RVAS) or len(saved['states']) != 64:
            raise ValueError('Catalog shape mismatch')
        for rva, code in codes.items():
            if code != pe.get_data(rva, len(code)) or digest_bytes(code) != saved['function_sha256_by_rva'][f'{rva:06x}']:
                raise ValueError('Function range pin mismatch')
        for entry in saved['states']:
            rig.check_oracle(entry['case'], entry['state'])
        report['timings']['preflight'] = time.monotonic() - start
        report['indexes'] = {hex(rva): index_context(json.loads(path.read_text()), rva)
                             for rva, path in indexes.items()}
        original_lift = rig.lift

        def timed_lift(code, rva, ranges, name):
            if rva not in RVAS or hex(rva) in report['functions']:
                raise ValueError('Unexpected/duplicate lift')
            row = report['functions'][hex(rva)] = dict(attempted=True, lifted=False,
                size=len(code), category='direct call' if rva > 0x10000 else 'branching arithmetic',
                ghidra_boundaries_reliable=False, timings={})
            start = time.monotonic()
            _, nodes, _, flow = decode_flow(code, rig.BASE+rva, LinearInstruction)
            if flow['size_bytes'] != len(code):
                raise ValueError('Pinned range/flow mismatch')
            row['flow'] = flow
            row['dependencies'] = dependencies(nodes, pe)
            row['timings']['analysis'] = time.monotonic() - start
            start = time.monotonic()
            body = original_lift(code, rva, ranges, name)
            row['timings']['translation'] = time.monotonic() - start
            row['lift_invocation'] = dict(call='wrapper_probe.lift -> Lifter(precise_carry=True).lift_function',
                rva=hex(rva), ranges=ranges, name=name)
            (output / (hex(rva) + '-lifted.c')).write_text(body)
            row['lifted_sha256'] = digest_bytes(body.encode())
            row['lifted'] = True
            return body

        stage = 'fresh_lift_and_fixture'
        # Timing-only interposition calls the unchanged, pinned implementation.
        rig.lift = timed_lift
        start = time.monotonic()
        source = rig.build_host_source(saved['states'], codes)
        report['timings']['lift_and_fixture'] = time.monotonic() - start
        origin = Path(sys.modules[rig.h.Lifter.__module__].__file__).resolve()
        if origin != (upstream / 'tools/lift/lift32.py').resolve():
            raise ValueError('Unexpected lifter origin')
        (output / 'fresh.c').write_text(source)
        report['generated_source_sha256'] = digest(output / 'fresh.c')
        # Proves identical instruction bodies/cases to the reviewed fixture.
        if report['generated_source_sha256'] != SOURCE_SHA:
            raise ValueError('Fresh output differs from pinned source')
        prepare(output / 'fresh.c', output / 'scoped.c')
        for isa in ('host', 'arm64'):
            stage = isa + '-compile'
            run = report['runs'][isa] = dict(compiled=False, executed=False, matched=0, exit_code=None)
            build = ROOT / 'build' / isa
            command(isa+'-build', ['cmake', '--build', build, '-j4'])
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
            obj, exe = output / (isa+'.o'), output / isa
            command(stage, ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11', '-O0',
                '-I'+str(ROOT/'tools'), '-I'+str(upstream/'runtime/recomp32'),
                '-c', output/'scoped.c', '-o', obj])
            stage = isa+'-link'
            command(stage, ['zig-cxx', *opts, obj, build/'libts2_scoped_dispatch_bridge.a',
                            build/'libts2_core.a', '-lm', '-o', exe])
            header = exe.read_bytes()[:20]
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != (62 if isa == 'host' else 183):
                raise ValueError('Wrong ELF ISA')
            run['compiled'] = True
            run['binary_sha256'] = digest(exe)
            stage = isa+'-execute'
            record = command(stage, [exe] if isa == 'host' else [ROOT/'scripts/campaign/arm64-run.sh', exe])
            run.update(executed=True, exit_code=record['exit_code'])
            stage = isa+'-compare'
            start = time.monotonic()
            run['matched'] = check(reference, output/(isa+'-execute.stdout'))
            run['comparison_seconds'] = time.monotonic() - start
            run['stdout_sha256'] = digest(output/(isa+'-execute.stdout'))
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image changed')
        require_complete(report)
        report['success'] = True
    except Exception as exc:
        report.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        # Compilation/link/execution cost belongs to the composed group; never
        # divide it by four and pretend it is a per-function measurement.
        rows = []
        for rva, function in report['functions'].items():
            rows.append(dict(function, rva=rva, pcrecomp_revision=REVISION,
                compiled_for_aarch64=report['runs'].get('arm64', {}).get('compiled', False),
                matched_x86_reference=report['success'], executed_under_qemu=report['success'],
                verification_scope='composed wrapper entries, saved x86 states only',
                group_result='result.json', group_commands=report['commands'],
                group_success=report['success']))
        (output/'metrics.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def digest_bytes(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--index-1270', type=Path, required=True)
    p.add_argument('--index-1ab770', type=Path, required=True)
    p.add_argument('--index-1ab78c', type=Path, required=True)
    args = p.parse_args()
    try:
        measure(args.output, {0x1270: args.index_1270, 0x1AB770: args.index_1ab770,
                              0x1AB78C: args.index_1ab78c})
    except Exception:
        p.exit(1, 'Fresh wrapper measurement failed; inspect private result/logs.\n')
    print('Fresh four-body wrapper lift: host64/64; AArch64 Linux/QEMU64/64; not Android')


if __name__ == '__main__':
    main()
