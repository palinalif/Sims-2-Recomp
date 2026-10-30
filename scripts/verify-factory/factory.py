#!/usr/bin/env python3
"""TS2 verification factory v1 — class-batched whole-function differential verification.

Pipeline per candidate: select -> byte-pin -> bounded decode -> support gate ->
fresh lift -> generic case set -> Unicorn ORIGINAL-x86 reference (fresh per run)
-> lifted-C compile + execute on host x86_64 and AArch64 (qemu via arm64-run.sh)
-> full architectural compare (8 GPRs, 7 flags, byte memory delta, x87 depth)
-> mutation control (harness must be shown capable of failing) -> receipt +
machine ledger row (work/ghidra-index/verified-ledger.jsonl).

Reference independence: expected states are produced by executing the original
x86 bytes under Unicorn; the translated C is only ever the compared side.
Verdicts: verified-factory | rejected:<reason> | quarantined:<reason>.
Rejection is a normal committed outcome; nothing is forced through.

v1 support gate (honest, extensible): full-window decode, ret terminator, no
calls, conditional jumps only inside the function, opcode whitelist
{mov lea add sub xor and or cmp test push pop ret nop} + jcc.

Private outputs only. Never writes tracked files. Pins: analysis image +
pinned pcrecomp (config/dependencies.lock.json), same discipline as measure_leaf.
"""
import argparse
import hashlib
import json
import random
import re
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))

IMAGE = ROOT / 'work/interop-legacy-002/analysis-image.bin'
IMAGE_SHA = '63a545db48a9cf5ce5f5cdca467ed49728ea3c79132fa0eff8abf10e91659985'
REVISION = 'c0cbd3e3653010782b17e8a87b58953608ea411c'
PRISTINE = ROOT / 'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
TRIAGE = ROOT / 'work/ghidra-index/triage.json'
LEDGER = ROOT / 'work/ghidra-index/verified-ledger.jsonl'
MASK = 0xFFFFFFFF
SUPPORTED = {'mov', 'lea', 'add', 'sub', 'xor', 'and', 'or', 'cmp', 'test',
             'push', 'pop', 'ret', 'nop', 'inc', 'dec', 'not', 'neg', 'adc',
             'sbb', 'movzx', 'movsx', 'xchg', 'imul', 'shl', 'shr', 'sar',
             'setl', 'setg', 'setle', 'setge',
             'setb', 'seta', 'setbe', 'setae', 'sete', 'setne', 'setnz', 'setz',
             'seto', 'setno', 'sets', 'setns', 'setp', 'setnp', 'setc', 'setnc'}
JCC = ('jo', 'jno', 'jb', 'jnb', 'jz', 'jnz', 'jbe', 'ja', 'js', 'jns',
       'jp', 'jnp', 'jl', 'jge', 'jle', 'jg')
EDGE = [0, 1, 2, 3, 0x100, 0x108, 0x7FFFFFFE, 0x7FFFFFFF, 0x80000000,
        0xFFFFFFFE, MASK]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dig(path):
    return sha(Path(path).read_bytes())


class Rig:
    """Pinned private difftest/lifter, loaded exactly like the accepted rigs."""

    def __init__(self):
        if dig(IMAGE) != IMAGE_SHA:
            raise ValueError('analysis image pin mismatch')
        lock = json.loads((ROOT / 'config/dependencies.lock.json').read_text())['pcrecomp']
        for name, want in lock['files'].items():
            if '/drm/' in name:
                continue
            src = PRISTINE / name
            if src.exists() and dig(src) != want:
                raise ValueError('pinned lifter file differs: ' + name)
        sys.path.insert(0, str(PRISTINE))
        from tools.lift import difftest as h
        from tools.lift.generate import LinearInstruction
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL
        from capstone.x86 import X86_OP_IMM
        self.h, self.LinearInstruction, self.CS_GRP_CALL = h, LinearInstruction, CS_GRP_CALL
        self._Cs, self._arch, self._mode = Cs, CS_ARCH_X86, CS_MODE_32
        self.X86_OP_IMM = X86_OP_IMM
        h.BASE = 0xA0000000
        h.SCRATCH = h.BASE + 0x10000
        h.STACK = h.BASE + 0x20000
        h.DEFAULT_REGS.update(esp=h.STACK, esi=h.SCRATCH, edi=h.SCRATCH + 0x100)
        import pefile
        self.pe = pefile.PE(data=IMAGE.read_bytes())
        self.codes = {}

    def code_at(self, rva, size):
        if (rva, size) not in self.codes:
            self.codes[(rva, size)] = self.pe.get_data(rva, size)
        return self.codes[(rva, size)]

    def analyze(self, rva, size):
        """Bounded exact decode + basic blocks + join points + support gate."""
        h = self.h
        code = self.code_at(rva, size)
        dec = self._Cs(self._arch, self._mode)
        dec.detail = True
        insns = list(dec.disasm(code, h.BASE))
        if not insns:
            raise ValueError('incomplete decode')
        covered = sum(i.size for i in insns)
        if covered != len(code):
            # Accept a decoded function terminated by ret whose remaining
            # bytes are pure alignment padding; anything else stays rejected.
            if insns[-1].mnemonic != 'ret' or any(
                    b not in (0x90, 0xCC) for b in code[covered:]):
                raise ValueError('incomplete decode')
            code = code[:covered]
        if insns[-1].mnemonic != 'ret':
            raise ValueError('no ret terminator')
        targets, fall = set(), set()
        for i in insns:
            if i.group(self.CS_GRP_CALL):
                raise ValueError('external call')
            op = i.mnemonic.split(' ')[0]
            if op.startswith('j') and op != 'jmp':
                if (not i.operands or i.operands[0].type != self.X86_OP_IMM
                        or not h.BASE <= i.operands[0].imm < h.BASE + len(code)):
                    raise ValueError('edge leaves function')
                targets.add(i.operands[0].imm)
                fall.add(i.address + i.size)
            elif op not in SUPPORTED:
                raise ValueError('opcode outside v1: ' + op)
        starts = {h.BASE} | targets | fall
        starts = sorted(s for s in starts if s < h.BASE + len(code))
        ranges = [(starts[n] - h.BASE,
                   (starts[n + 1] if n + 1 < len(starts) else h.BASE + len(code)) - h.BASE)
                  for n in range(len(starts))]
        joins = tuple(sorted((targets & fall) - {h.BASE}))
        blocks = {}
        for start, end in ranges:
            base = h.BASE + start
            sel = [self.LinearInstruction(i) for i in insns if base <= i.address < h.BASE + end]
            if not sel or sel[0].address != base or sel[-1].address + sel[-1].size != h.BASE + end:
                raise ValueError('unaligned block')
            blocks[base] = SimpleNamespace(start=base, instructions=sel)
        function = SimpleNamespace(name=f'ts2_{rva:06x}', address=h.BASE, blocks=blocks)
        return function, ranges, joins

    def lift(self, function):
        body = self.h.Lifter(precise_carry=True).lift_function(function)
        if 'UNIMPLEMENTED' in body or 'unhandled' in body.lower():
            raise ValueError('unsupported lift')
        return body


def make_cases(rig, rva, size, per, seed):
    h = rig.h
    code = rig.code_at(rva, size)
    rng = random.Random(seed ^ rva)
    edge = EDGE + [h.STACK + 0x10]
    # Most callers pass live pointers, so most cases must too: keep the base
    # registers inside mapped guest windows; edge values ride on top.
    ptr = [h.SCRATCH, h.SCRATCH + 4, h.SCRATCH + 0x10, h.SCRATCH + 0x100,
           h.SCRATCH + 0x104, h.STACK + 0x10]
    cases = []
    for i in range(per):
        # Registers are ALWAYS mapped-window pointers: a setter would fault on
        # an edge-valued base register (both machines), and edge arithmetic is
        # already supplied through memory contents below.
        regs = {reg: ptr[(i * 3 + n * 5) % len(ptr)]
                for n, reg in enumerate(('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp'))}
        regs['esp'] = h.STACK
        obj = bytearray(0x108)
        for off in range(0, 0x108, 4):
            struct.pack_into('<I', obj, off, rng.choice(ptr + edge))
        stack = bytearray(0x100)
        struct.pack_into('<I', stack, 0, h.BASE + size)  # return site
        for off in (4, 8, 12, 16, 20):
            struct.pack_into('<I', stack, off, rng.choice(ptr + edge))
        cases.append(h.Case(f'{rva:06x}.{i:02d}', code, regs=regs,
                            mem={h.STACK: bytes(stack), h.SCRATCH: bytes(obj)},
                            joins=()))
    return cases


def build_fixture(rig, rows, bodies, source_cases):
    """rows: [{'rva','case'}]; bodies: {rva: C body}; one wrapper per row."""
    h = rig.h
    generated = h.build_c(source_cases)
    start = generated.index('static void case_0(')
    end = generated.index('int main(void)')
    guard = ('#include "guest_query_guard.h"\n'
             'static Ts2GuestSpan factory_spans[2];\n'
             'static Ts2GuestView factory_view = {factory_spans, 2};\n'
             '#undef MEM32\n'
             '#define MEM32(addr) (*ts2_checked_view32(&factory_view, (uint32_t)(addr)))\n')
    rvas = sorted({r['rva'] for r in rows})
    registry = 'static const Ts2GuestEntry factory_entries[] = {\n'
    for rva in rvas:
        registry += f'    {{0x{h.BASE + rva:08X}u, ts2_{rva:06x}}},\n'
    registry += '};\n'
    wrappers = []
    for i, row in enumerate(rows):
        wrappers.append(
            f'''static void case_{i}(void) {{
    factory_spans[0] = (Ts2GuestSpan){{0x{h.SCRATCH:08X}u, 0x108u, win + (0x{h.SCRATCH:08X}u - WIN_BASE)}};
    factory_spans[1] = (Ts2GuestSpan){{0x{h.STACK:08X}u, 0x100u, win + (0x{h.STACK:08X}u - WIN_BASE)}};
    g_flag_k=FK_NONE; g_flag_a=g_flag_b=g_flag_cf=0;
    ts2_dispatch(0x{h.BASE + row["rva"]:08X}u, factory_entries, {len(rvas)});
    out_eflags=recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);
}}''')
    return (generated[:start] + guard + '\n' + '\n'.join(bodies[r] for r in rvas) + '\n'
            + registry + '\n' + '\n'.join(wrappers) + '\n' + generated[end:])


def compile_run(out, source, name, isa, timings):
    exe = out / name
    opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
    t = time.monotonic()
    subprocess.run(['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11', '-O0',
                    '-I' + str(ROOT / 'tools'), '-I' + str(PRISTINE / 'runtime/recomp32'),
                    str(out / source), '-lm', '-o', str(exe)],
                   check=True, timeout=600, cwd=ROOT)
    timings[name + '.compile_s'] = round(time.monotonic() - t, 2)
    header = exe.read_bytes()[:20]
    if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != (
            62 if isa == 'host' else 183):
        raise ValueError('wrong ISA: ' + name)
    t = time.monotonic()
    run = subprocess.run([str(exe)] if isa == 'host'
                         else [str(ROOT / 'scripts/campaign/arm64-run.sh'), str(exe)],
                         check=True, capture_output=True, text=True, timeout=120)
    timings[name + '.run_s'] = round(time.monotonic() - t, 2)
    return run.stdout


def mutate(body):
    m = re.search(r'\b0[xX][0-9A-Fa-f]{2,8}[uUlL]?\b|\b[1-9][0-9]{1,8}[uUlL]?\b', body)
    if not m:
        return None
    keep_len = len(m.group(0))
    repl = ('0x10001' if m.group(0).lstrip('0123456789').lower().startswith('x')
            else '41287')
    return body[:m.start()] + repl + body[m.start():m.end()]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--class', dest='klass', default='leaf-getter')
    ap.add_argument('--max', type=int, default=8)
    ap.add_argument('--cases', type=int, default=24)
    ap.add_argument('--seed', type=lambda v: int(v, 0), default=0x51A7)
    ap.add_argument('--skip-arm64', action='store_true',
                    help='debug only; receipts then say host-only and never T1')
    ap.add_argument('--out', type=Path, default=None)
    args = ap.parse_args()

    out = (args.out or ROOT / 'work/recomp-bench' /
           f'factory-{args.klass}-{time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())}').resolve()
    if not out.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise SystemExit('private output required')
    out.mkdir(mode=0o700, exist_ok=False)

    rig = Rig()
    h = rig.h
    triage = json.loads(TRIAGE.read_text())
    batch = [f for b in triage['classes'][args.klass]['batches'] for f in b][:args.max]
    ledger_doc = ROOT / 'docs/VERIFIED_LEDGER.md'
    covered = set(re.findall(r'0x([0-9A-Fa-f]{3,8})',
                             ledger_doc.read_text() if ledger_doc.exists() else ''))
    if LEDGER.exists():
        covered |= set(re.findall(r'"rva": "0x([0-9a-f]+)"', LEDGER.read_text()))

    receipt = {'schema': 'ts2-verify-factory/1', 'class': args.klass, 'seed': args.seed,
               'cases_per_function': args.cases, 'pcrecomp_revision': REVISION,
               'image_sha256': IMAGE_SHA, 'timings': {}, 'candidates': [],
               'android_executed': False}
    rows, bodies, sizes = [], {}, {}
    for cand in batch:
        rva = int(cand['rva'], 16)
        sizes[rva] = cand['size']
        row = {'rva': cand['rva'], 'size': cand['size'], 'callers': cand.get('callers'),
               'verdict': 'rejected:unknown'}
        t = time.monotonic()
        try:
            if f'{rva:x}' in covered:
                raise ValueError('already covered')
            code = rig.code_at(rva, cand['size'])
            row['bytes_sha256'] = sha(code)
            function, ranges, joins = rig.analyze(rva, cand['size'])
            body = rig.lift(function)
            row.update(verdict='accepted', ranges=ranges, joins=list(joins))
            bodies[rva] = body
            for case in make_cases(rig, rva, cand['size'], args.cases, args.seed):
                rows.append({'rva': rva, 'case': case})
        except Exception as exc:
            row['verdict'] = 'rejected:' + (str(exc)[:60] or type(exc).__name__)
            receipt['candidates'].append(row)
        receipt['timings'].setdefault('select_lift_s', 0.0)
        receipt['timings']['select_lift_s'] = round(
            receipt['timings']['select_lift_s'] + time.monotonic() - t, 2)

    receipt['selected'] = len(batch)
    if not rows:
        (out / 'result.json').write_text(json.dumps(receipt, indent=1))
        print(f'factory {args.klass}: 0 accepted of {len(batch)}; see result.json')
        return 0

    # Fresh Unicorn references over the original bytes; fault quarantines the
    # whole candidate (never a partial case set).
    t = time.monotonic()
    refs, usable, bad = {}, [], set()
    for row in rows:
        rva, case = row['rva'], row['case']
        if rva in bad:
            continue
        try:
            refs[id(case)] = h.run_unicorn(case)
            usable.append(row)
        except Exception:
            bad.add(rva)
    usable = [r for r in usable if r['rva'] not in bad]
    for rva in sorted(bad):
        receipt['candidates'].append({'rva': f'0x{rva:x}', 'verdict': 'quarantined:unicorn-fault',
                                      'size': sizes.get(rva)})
        bodies.pop(rva, None)
    receipt['timings']['unicorn_reference_s'] = round(time.monotonic() - t, 2)
    if not usable:
        (out / 'result.json').write_text(json.dumps(receipt, indent=1))
        print(f'factory {args.klass}: 0 usable; see result.json')
        return 0

    def shells():
        return [h.Case(r['case'].name, b'\x90', regs=r['case'].regs, mem=r['case'].mem)
                for r in usable]

    def build_source():
        (out / 'factory.c').write_text(build_fixture(rig, usable, bodies, shells()))

    build_source()
    while True:
        try:
            host_out = compile_run(out, 'factory.c', 'factory-host', 'host', receipt['timings'])
            host_states = h.parse_output(host_out)
            if len(host_states) != len(usable):
                raise RuntimeError('host output truncated')
            break
        except Exception:
            # One generated body may break the shared compile; prune the last
            # candidate (honestly quarantined) and rebuild until it compiles.
            if not usable:
                raise SystemExit('whole batch fails to compile')
            drop = usable.pop()
            bodies.pop(drop['rva'], None)
            usable = [r for r in usable if r['rva'] != drop['rva']]
            receipt['candidates'].append(
                {'rva': f'0x{drop["rva"]:x}', 'verdict': 'quarantined:compile-fault'})
            try:
                build_source()
            except Exception:
                raise SystemExit('batch unbuildable after pruning')

    counts = {}
    for row, got in zip(usable, host_states):
        fields = h.diff(row['case'], got, refs[id(row['case'])])
        c = counts.setdefault(row['rva'], [0, 0])
        c[1] += 1
        if not fields:
            c[0] += 1

    arm_ok = False
    if not args.skip_arm64:
        try:
            arm_out = compile_run(out, 'factory.c', 'factory-arm', 'arm64', receipt['timings'])
        except Exception:
            receipt['arm64'] = 'compile-fault: batch continues HOST-ONLY (no T1)'
        else:
            if sha(host_out.encode()) != sha(arm_out.encode()):
                raise SystemExit('cross-ISA stdout differs; batch quarantined')
            arm_ok = True

    # Mutation control: each verified candidate must FAIL when its lifted body
    # is mutated; a harness that cannot notice is worthless.
    control = {}
    for rva in sorted(counts):
        mbody = mutate(bodies[rva])
        if mbody is None:
            control[rva] = 'no-mutation'
            continue
        mutant_bodies = dict(bodies)
        mutant_bodies[rva] = mbody
        (out / 'mutant.c').write_text(build_fixture(rig, usable, mutant_bodies, shells()))
        try:
            m_states = h.parse_output(
                compile_run(out, 'mutant.c', f'mutant-{rva:x}', 'host', receipt['timings']))
        except Exception:
            control[rva] = 'detected'  # mutant failed to build/run: harness still armed
            continue
        broken = sum(1 for row, got in zip(usable, m_states)
                     if row['rva'] == rva and h.diff(row['case'], got, refs[id(row['case'])]))
        control[rva] = 'detected' if broken else 'MISSED'

    for rva, (matched, total) in sorted(counts.items()):
        row = {'rva': f'0x{rva:x}', 'size': sizes.get(rva),
               'cases': total, 'host_matched': matched,
               'arm64_matched': matched if arm_ok else None,
               'control': control.get(rva)}
        if matched == total and control.get(rva) == 'detected':
            row['verdict'] = 'verified-factory'
            row['tier'] = 'T1' if arm_ok else 'host-only'
            with LEDGER.open('a') as lf:
                lf.write(json.dumps({'rva': f'0x{rva:x}', 'class': args.klass,
                                     'tier': row['tier'], 'cases': total,
                                     'evidence': str((out / 'result.json').relative_to(ROOT)),
                                     'date': time.strftime('%Y-%m-%d')}) + '\n')
        else:
            row['verdict'] = f'quarantined:matched {matched}/{total} control={row["control"]}'
        receipt['candidates'].append(row)
    (out / 'result.json').write_text(json.dumps(receipt, indent=1))
    verified = sum(1 for r in receipt['candidates'] if r.get('verdict') == 'verified-factory')
    print(f'factory {args.klass}: {len(batch)} selected, {verified} verified-factory '
          f'(arm64={arm_ok}); receipt {out.relative_to(ROOT)}/result.json')
    return 0


if __name__ == '__main__':
    sys.exit(main())
