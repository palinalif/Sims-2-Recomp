#!/usr/bin/env python3
"""Fresh selected RVA1070 lift using existing upstream case/transport APIs.

Historical bundle lacks its generator: these are NEW deterministic x86 cases,
not a reconstruction of the old device inputs. Derived output stays private.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify, decode_function
from measure_group import index_context, digest_bytes
sys.path.insert(0, str(ROOT / 'tools'))
from android_probe import compare, parse_output
from probe_function import extract

FUNCTION_SHA = '3a32b6526f23eadf353f95e8d33392d8a303ecae4496a354cff28118759cb27a'
BASE, SIZE = 0xA0000000, 0x40000


def cases(h, code):
    rng = random.Random(0x1070)
    edges = (0, 1, 0xffffffff, 0x7fffffff, 0x80000000, 0xaaaaaaaa, 0x55555555, 0x10000)
    result = []
    for i in range(64):
        obj, sp = BASE + 0x10000 + i * 128, BASE + 0x20000 + i * 32
        a = edges[i % 8] if i < 32 else rng.getrandbits(32)
        b = edges[i // 8] if i < 32 else rng.getrandbits(32)
        regs = {name: rng.getrandbits(32) for name in h.REGS}
        regs['esp'] = sp
        mem = {obj: rng.randbytes(64), sp: struct.pack('<IIII', BASE + len(code), obj, a, b)}
        result.append(h.Case(f'setter.{i}', code, regs=regs, mem=mem))
    return result


def oracle(case):
    """Documented setter contract, independent of decoding/lifting/Unicorn."""
    sp = case.regs['esp']
    _, obj, a, b = struct.unpack('<IIII', case.mem[sp])
    regs = dict(case.regs, eax=obj, ecx=a, edx=b, esp=sp + 4)
    before = case.mem[obj]
    after = bytearray(before)
    struct.pack_into('<II', after, 0x28, a, b)
    return dict(regs=regs, eflags=0x202, fp_depth=0, st=[],
                mem={str(obj+i): value for i, value in enumerate(after) if value != before[i]})


def checked_accesses(insn, regvalue, sp, obj):
    """Pre-step range journal, following reference_startup.py (no C callbacks)."""
    from capstone import CS_AC_READ, CS_AC_WRITE
    from capstone.x86 import X86_OP_MEM
    if insn.mnemonic not in ('mov', 'ret'):
        raise ValueError('Instruction outside setter access contract')
    accesses = []
    if insn.mnemonic == 'ret':
        if insn.op_str or regvalue('esp') != sp:
            raise ValueError('Unexpected return frame')
        accesses.append(('read', sp, 4))
    for op in insn.operands:
        if op.type != X86_OP_MEM:
            continue
        if op.mem.segment or op.mem.index or op.size != 4 or op.access not in (CS_AC_READ, CS_AC_WRITE):
            raise ValueError('Unsupported memory operand')
        base = regvalue(insn.reg_name(op.mem.base)) if op.mem.base else 0
        address = base + op.mem.disp
        write = op.access == CS_AC_WRITE
        if not 0 <= address <= 0xfffffffc or not (
                obj+0x28 <= address and address+4 <= obj+0x30 if write
                else sp <= address and address+4 <= sp+16):
            raise ValueError('Memory access outside reviewed ranges')
        accesses.append(('write' if write else 'read', address, 4))
    return accesses


def reference(h, case):
    """Upstream state protocol with bounded, checked hook-free single stepping."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    from unicorn import x86_const as X
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(BASE, SIZE)
    mu.mem_write(BASE, case.code)
    for va, data in case.mem.items():
        mu.mem_write(va, data)
    for name, val in case.regs.items():
        mu.reg_write(h.UC_REGS[name], val)
    mu.reg_write(X.UC_X86_REG_EFLAGS, 0x202)
    mu.reg_write(X.UC_X86_REG_FPCW, h.FPU_CONTROL_WORD)
    mu.reg_write(X.UC_X86_REG_MXCSR, 0x1f80)
    sp = case.regs['esp']
    obj = struct.unpack('<IIII', case.mem[sp])[1]
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    nodes = {i.address: i for i in decoder.disasm(case.code, BASE)}
    if sum(i.size for i in nodes.values()) != len(case.code):
        raise ValueError('Incomplete reference decode')
    journal = []
    before = bytes(mu.mem_read(BASE, SIZE))
    mu.reg_write(X.UC_X86_REG_EIP, BASE)
    for _ in range(32):
        ip = mu.reg_read(X.UC_X86_REG_EIP)
        if ip == BASE+len(case.code):
            break
        if ip not in nodes:
            raise ValueError('Reference escaped code')
        journal.extend(checked_accesses(nodes[ip], lambda name: mu.reg_read(h.UC_REGS[name]), sp, obj))
        mu.emu_start(ip, BASE+len(case.code), timeout=1000000, count=1)
    else:
        raise ValueError('Reference instruction budget')
    if [entry for entry in journal if entry[0] == 'write'] != [('write', obj+0x28, 4), ('write', obj+0x2c, 4)]:
        raise ValueError('Reference store journal mismatch')
    after = bytes(mu.mem_read(BASE, SIZE))
    return dict(regs={n: mu.reg_read(h.UC_REGS[n]) for n in h.REGS},
                eflags=mu.reg_read(X.UC_X86_REG_EFLAGS),
                mem={str(k): v for k, v in h.mem_diff(before, after).items()},
                fp_depth=h.fpu_depth(mu), st=h.fpu_stack(mu))


def source(h, selected, body):
    # Shell cases use authored NOPs; ONLY the single lift_function body executes.
    shell = [h.Case(c.name, b'\x90', regs=c.regs, mem=c.mem) for c in selected]
    text = h.build_c(shell)
    start, end = text.index('static void case_0('), text.index('int main(void)')
    guard = '''
static uint32_t object_va, stack_va;
static uint32_t *checked_word(uint32_t va) {
    uint64_t end = (uint64_t)va + 4;
    if ((va & 3) || !((va >= object_va && end <= (uint64_t)object_va + 64) ||
                       (va >= stack_va && end <= (uint64_t)stack_va + 16))) exit(91);
    return (uint32_t *)(win + (va - WIN_BASE));
}
#undef MEM32
#define MEM32(va) (*checked_word((uint32_t)(va)))
'''
    wrappers = []
    for i, c in enumerate(selected):
        sp = c.regs['esp']
        obj = struct.unpack('<IIII', c.mem[sp])[1]
        wrappers.append(f'''static void case_{i}(void) {{
    object_va=0x{obj:08x}u; stack_va=0x{sp:08x}u;
    g_flag_k=FK_NONE; g_flag_a=g_flag_b=g_flag_cf=0;
    setter_1070();
    out_eflags=recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);
}}''')
    return text[:start] + guard + body + '\n' + '\n'.join(wrappers) + '\n' + text[end:]


def require_match(expected, actual):
    result = compare(expected, actual)
    if result['cases'] != 64 or result['matched'] != 64 or result['differences']:
        raise ValueError('Setter comparison failed')
    return 64


def complete(row):
    if not row['lifted'] or row['x86_oracle_matches'] != 64 or set(row['runs']) != {'host', 'arm64'}:
        raise ValueError('Missing pipeline stage')
    for run in row['runs'].values():
        if not run['compiled'] or not run['executed'] or run['matched'] != 64 or run['exit_code'] != 0:
            raise ValueError('Incomplete native stage')
    if row['runs']['host']['stdout_sha256'] != row['runs']['arm64']['stdout_sha256']:
        raise ValueError('ISA output differs')


def measure(output, index):
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    row = dict(schema='ts2-fresh-setter/1', rva='0x1070', size=19,
        category=['simple leaf', 'memory access through pointers', 'callback registration setter'],
        dependencies={'imports': [], 'calls': [], 'globals': [], 'data': ['object and caller stack']},
        success=False, attempted=False, lifted=False, x86_oracle_matches=0, runs={}, commands=[], timings={},
        fresh_x86_reference=False, historical_cases_reproduced=False, android_executed=False,
        pcrecomp_revision=REVISION, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)),
        limits=['new deterministic fixture, NOT old device inputs', 'fixed initial flags 0x202',
                'all GPRs/full flags/memory deltas/FP empty-stack transport',
                'x86 PC/pre-step access journal checked; native PC/transient writes NOT compared',
                'aligned valid pointers only; no callback execution, services or production integration'])
    stage = 'preflight'

    def command(name, argv):
        rec = dict(name=name, argv=[str(a) for a in argv], exit_code=None)
        row['commands'].append(rec)
        start = time.monotonic()
        try:
            with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
                run = subprocess.run(rec['argv'], cwd=ROOT, stdout=out, stderr=err, timeout=120)
            rec['exit_code'] = run.returncode
            if run.returncode:
                raise ValueError('Child failed')
        finally:
            rec['seconds'] = time.monotonic()-start
        return rec

    try:
        start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image pin mismatch')
        row['index'] = index_context(json.loads(index.read_text()), 0x1070)
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        locked = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]
        used += ['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        for name in used:
            if digest(upstream/name) != digest(pristine/name):
                raise ValueError('Private upstream differs')
        row['upstream_files'] = {n: digest(upstream/n) for n in used}
        # Existing read-only extraction gate; existing public stack-only execution
        # gate remains unchanged (it intentionally does not accept this setter).
        code = extract(image, IMAGE_SHA, 0x1070, 19)
        if digest_bytes(code) != FUNCTION_SHA:
            raise ValueError('Range pin mismatch')
        row['pins'] = dict(image=IMAGE_SHA, function=FUNCTION_SHA)
        spec = importlib.util.spec_from_file_location('setter_upstream_harness', upstream/'tools/lift/difftest.py')
        sys.path.insert(0, str(upstream))
        h = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = h
        spec.loader.exec_module(h)
        from tools.lift.generate import LinearInstruction
        if Path(sys.modules[h.Lifter.__module__].__file__).resolve() != (upstream/'tools/lift/lift32.py').resolve():
            raise ValueError('Unexpected lifter origin')
        h.BASE = BASE
        selected = cases(h, code)
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'analysis'
        row['attempted'] = True
        start = time.monotonic()
        function = decode_function(code, ((0, 19),), BASE, LinearInstruction)
        row['timings']['analysis'] = time.monotonic()-start
        row['instructions'] = sum(len(b.instructions) for b in function.blocks.values())
        row['blocks'] = len(function.blocks)
        function.name = 'setter_1070'
        row['lift_invocation'] = dict(call='Lifter(precise_carry=True).lift_function',
            rva='0x1070', decode_base=hex(BASE), blocks=[[0,19]], name=function.name)
        stage = 'translation'
        start = time.monotonic()
        body = h.Lifter(precise_carry=True).lift_function(function)
        row['timings']['translation'] = time.monotonic()-start
        if 'UNIMPLEMENTED' in body or 'unhandled' in body.lower():
            raise ValueError('Unsupported lift')
        (output/'lifted.c').write_text(body)
        row['lifted'] = True
        stage = 'x86-reference'
        start = time.monotonic()
        expected = [reference(h, c) for c in selected]
        row['x86_oracle_matches'] = require_match([oracle(c) for c in selected], expected)
        row['fresh_x86_reference'] = True
        row['timings']['x86_reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(dict(states=expected)))
        stage = 'fixture'
        start = time.monotonic()
        (output/'probe.c').write_text(source(h, selected, body))
        row['timings']['fixture'] = time.monotonic()-start
        for isa in ('host', 'arm64'):
            stage = isa+'-compile'
            run = row['runs'][isa] = dict(compiled=False, executed=False, matched=0, exit_code=None)
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
            obj, exe = output/(isa+'.o'), output/isa
            command(stage, ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11', '-O0', '-I'+str(upstream/'runtime/recomp32'),
                            '-c', output/'probe.c', '-o', obj])
            command(isa+'-link', ['zig-cc', *opts, obj, '-lm', '-o', exe])
            header = exe.read_bytes()[:20]
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != (62 if isa == 'host' else 183):
                raise ValueError('Wrong ISA')
            run['compiled'] = True
            stage = isa+'-execute'
            rec = command(stage, [exe] if isa == 'host' else [ROOT/'scripts/campaign/arm64-run.sh', exe])
            run.update(executed=True, exit_code=rec['exit_code'])
            stage = isa+'-compare'
            start = time.monotonic()
            path = output/(isa+'-execute.stdout')
            run['matched'] = require_match(expected, parse_output(path.read_text()))
            run['comparison_seconds'] = time.monotonic()-start
            run['stdout_sha256'] = digest(path)
        if digest(image) != IMAGE_SHA:
            raise ValueError('Image changed')
        row['artifact_sha256'] = {name: digest(output/name) for name in
                                  ('lifted.c', 'probe.c', 'reference.json', 'host', 'arm64')}
        complete(row)
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--index-1070', required=True, type=Path)
    args = p.parse_args()
    try:
        measure(args.output, args.index_1070)
    except Exception:
        p.exit(1, 'Setter measurement failed; inspect private metrics/logs.\n')
    print('RVA1070 fresh lift/new x86 oracle64; host64; Linux/AArch64/QEMU64; not Android')


if __name__ == '__main__':
    main()
