#!/usr/bin/env python3
"""Fresh bounded RVA 1250 lift; private artifacts only, no PE launch or recovery.

Uses the unchanged pinned private reference rig for cases/block construction and
pcrecomp for every lifted instruction. Not a generic batch runner or Android test.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from android_probe import compare, parse_output
from fetch_pcrecomp import verify
from prepare_private_readonly_dispatch import REFERENCE_SHA

IMAGE_SHA = '63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985'
RIG_SHA = '5c7cb7209594108cedb957ee88c9d38e254554c4d890d402ae636ffc3cecf2de'
REVISION = 'c0cbd3e3653010782b17e8a87b58953608ea411c'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_states(expected, text):
    actual = parse_output(text)
    result = compare(expected, actual)
    if len(expected) != 32 or len(actual) != 32 or result['matched'] != 32 or result['differences']:
        raise ValueError('Leaf state comparison failed')
    return 32


def decode_function(code, ranges, base, instruction_wrapper):
    """Bounded exact block construction; reject gaps, overlaps and escaping edges."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP, CS_GRP_CALL
    from capstone.x86 import X86_OP_IMM
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    insns = list(decoder.disasm(code, base))
    if not insns or sum(i.size for i in insns) != len(code) or insns[-1].mnemonic != 'ret':
        raise ValueError('Incomplete leaf decode')
    if not ranges or ranges[0][0] != 0 or ranges[-1][1] != len(code):
        raise ValueError('Incomplete block bounds')
    blocks = {}
    previous = 0
    starts = {base + start for start, _ in ranges}
    for start, end in ranges:
        if start != previous or end <= start:
            raise ValueError('Noncontiguous blocks')
        selected = [i for i in insns if base + start <= i.address < base + end]
        if not selected or selected[0].address != base + start or selected[-1].address + selected[-1].size != base + end:
            raise ValueError('Unaligned block')
        for insn in selected:
            if insn.group(CS_GRP_CALL):
                raise ValueError('Not a leaf')
            if insn.group(CS_GRP_JUMP):
                if (insn is not selected[-1] or not insn.operands or
                        insn.operands[0].type != X86_OP_IMM or
                        insn.operands[0].imm not in starts):
                    raise ValueError('Unsupported leaf edge')
        blocks[base + start] = SimpleNamespace(start=base + start,
            instructions=[instruction_wrapper(i) for i in selected])
        previous = end
    return SimpleNamespace(name='object_query_1250', address=base, blocks=blocks)


def complete(row):
    runs = row['runs']
    if set(runs) != {'host', 'arm64'} or not row['lifted']:
        raise ValueError('Missing stage')
    for run in runs.values():
        if not run['compiled'] or not run['executed'] or run['matched'] != 32:
            raise ValueError('Incomplete ISA verification')
    if runs['host']['stdout_sha256'] != runs['arm64']['stdout_sha256']:
        raise ValueError('Cross-ISA output differs')


def measure(output):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    row = dict(schema='ts2-fresh-leaf/1', rva='0x1250', size=27,
               category=['branching arithmetic', 'memory access through pointers'],
               dependencies={'imports': [], 'calls': [], 'globals': [],
                             'data': ['caller object and stack']},
               ghidra_boundaries_reliable=None, attempted=False, lifted=False,
               success=False, android_executed=False, fresh_x86_reference=False,
               pcrecomp_revision=REVISION, commands=[], runs={}, timings={},
               invocation=[sys.executable, *sys.argv],
               limits=['saved x86 states, not fresh x86 execution',
                       'undefined AF normalized only on logical branch',
                       'integer/flags/stack/memory deltas/FP transport only',
                       'no FP instructions, invalid pointers, services or startup'])
    stage = 'preflight'

    def command(name, argv):
        start = time.monotonic()
        record = dict(name=name, argv=[str(a) for a in argv], exit_code=None)
        row['commands'].append(record)
        try:
            with (output / (name + '.stdout')).open('xb') as out, \
                 (output / (name + '.stderr')).open('xb') as err:
                result = subprocess.run(record['argv'], cwd=ROOT, stdout=out,
                                        stderr=err, timeout=120)
            record['exit_code'] = result.returncode
            if result.returncode:
                raise ValueError('Child failed')
        finally:
            record['seconds'] = time.monotonic() - start

    try:
        start = time.monotonic()
        fixture = ROOT / 'work/interop-legacy-002'
        image = fixture / 'analysis-image.bin'
        reference = fixture / 'group-bundle/reference.json'
        rig_path = fixture / 'group_probe.py'
        if digest(image) != IMAGE_SHA or digest(reference) != REFERENCE_SHA or digest(rig_path) != RIG_SHA:
            raise ValueError('Input pin mismatch')
        upstream = fixture / 'pcrecomp'
        pristine = ROOT / 'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        # Private recovery copy differs only in DRM tooling, never imported here.
        verify(pristine)
        spec = json.loads((ROOT / 'config/dependencies.lock.json').read_text())['pcrecomp']
        used = [name for name in spec['files'] if '/drm/' not in name]
        # Also cover the block-wrapper dependency not present in the old lock.
        used += ['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        for name in used:
            if digest(upstream / name) != digest(pristine / name):
                raise ValueError('Private lifter differs')
        row['upstream_files'] = {name: digest(upstream / name) for name in used}
        row['image_sha256'] = IMAGE_SHA
        row['rig_sha256'] = RIG_SHA
        row['reference_sha256'] = REFERENCE_SHA
        # Load private pinned upstream BEFORE the rig's historical path insertion.
        sys.path.insert(0, str(upstream))
        from tools.lift import difftest  # noqa: F401
        from tools.lift.generate import LinearInstruction  # noqa: F401
        module_spec = importlib.util.spec_from_file_location('private_group_rig', rig_path)
        rig = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(rig)  # main is never invoked
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        codes = {}
        # Reuse unchanged case generator's full input catalog, but lift ONLY 1250.
        for rva, (size, pin, _) in rig.FUNCTIONS.items():
            code = pe.get_data(rva, size)
            if hashlib.sha256(code).hexdigest() != pin:
                raise ValueError('Range pin mismatch')
            codes[rva] = code
        selected = [entry for entry in rig.make_cases(codes) if entry[0] == 0x1250]
        expected = json.loads(reference.read_text())['states'][16:48]
        if len(selected) != 32:
            raise ValueError('Unexpected case count')
        row['timings']['preflight_and_cases'] = time.monotonic() - start
        stage = 'analysis'
        row['attempted'] = True
        start = time.monotonic()
        function = decode_function(codes[0x1250], rig.FUNCTIONS[0x1250][2],
                                   rig.h.BASE, LinearInstruction)
        row['timings']['analysis_decode_and_blocks'] = time.monotonic() - start
        stage = 'translation'
        start = time.monotonic()
        body = rig.h.Lifter(precise_carry=True).lift_function(function)
        row['timings']['translation'] = time.monotonic() - start
        if 'UNIMPLEMENTED' in body or 'unhandled' in body.lower():
            raise ValueError('Unsupported lift')
        row['lift_invocation'] = 'tools.lift.lift32.Lifter(precise_carry=True).lift_function(function), RVA 0x1250, blocks ((0,14),(14,23),(23,27)), decode base 0xA0000000'
        lifter_module = Path(sys.modules[rig.h.Lifter.__module__].__file__).resolve()
        if lifter_module != (upstream / 'tools/lift/lift32.py').resolve():
            raise ValueError('Unexpected lifter module origin')
        row['lifter_module'] = str(lifter_module)
        (output / 'lifted.c').write_text(body)
        row['lifted'] = True
        row['lifted_sha256'] = digest(output / 'lifted.c')
        stage = 'fixture_assembly'
        start = time.monotonic()
        source = rig.build_c(selected, {0x1250: body})
        # Registry-only filtering; generated instruction body is never rewritten.
        for rva in ('1240', '1270'):
            line = f'    {{0xA000{rva}u, object_query_{rva}}},\n'
            if source.count(line) != 1:
                raise ValueError('Registry shape changed')
            source = source.replace(line, '')
        source = source.replace('query_entries, 3);', 'query_entries, 1);')
        if body not in source:
            raise ValueError('Lift body changed')
        (output / 'probe.c').write_text(source)
        row['timings']['fixture_assembly'] = time.monotonic() - start
        for isa in ('host', 'arm64'):
            stage = isa + '-compile'
            run = row['runs'][isa] = dict(compiled=False, executed=False, matched=0)
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
            exe = output / isa
            command(stage, ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11',
                           '-O0', '-I' + str(ROOT / 'tools'),
                           '-I' + str(upstream / 'runtime/recomp32'),
                           output / 'probe.c', '-lm', '-o', exe])
            header = exe.read_bytes()[:20]
            machine = 62 if isa == 'host' else 183
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != machine:
                raise ValueError('Wrong ISA')
            run['compiled'] = True
            stage = isa + '-execute'
            command(stage, [exe] if isa == 'host' else [ROOT / 'scripts/campaign/arm64-run.sh', exe])
            run['executed'] = True
            stage = isa + '-compare'
            start = time.monotonic()
            text_path = output / (isa + '-execute.stdout')
            run['matched'] = check_states(expected, text_path.read_text())
            row['timings'][stage] = time.monotonic() - start
            run['stdout_sha256'] = digest(text_path)
        complete(row)
        row['success'] = True
    except Exception as exc:
        row['failed_stage'] = stage
        row['error_type'] = type(exc).__name__  # no proprietary diagnostics in summary
        raise
    finally:
        (output / 'metrics.jsonl').write_text(json.dumps(row) + '\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        measure(args.output)
    except Exception:
        parser.exit(1, 'Fresh leaf failed; inspect private metrics/logs.\n')
    print('RVA 1250: fresh lift; host 32/32; AArch64 Linux/QEMU 32/32; not Android')


if __name__ == '__main__':
    main()
