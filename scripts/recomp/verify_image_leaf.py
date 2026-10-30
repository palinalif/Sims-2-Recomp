#!/usr/bin/env python3
"""Fresh non-image x86 inputs for ONE unchanged pinned lift, RVA1250.

Private interoperability diagnostic; not a new translation, game startup or Android.
No saved states are relocated/reused. No PE launch, recovery or upstream edits.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from android_probe import REGS, compare, parse_output
from fetch_pcrecomp import verify
from prepare_private_readonly_dispatch import SOURCE_SHA
from verify_existing_group import IMAGE_SHA

OBJECT, STACK, ENTRY, RETURN = 0xb0001000, 0xb0003000, 0xa0001250, 0xc0000000
RANGE_SHA = '3d3b467ac94d779b05c24d2c928485b8b7522941d19830c8c8a76b9440bbdea8'
MASK = 0xffffffff


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cases():
    rng = random.Random(125014)
    edge = (0, 1, 15, 16, 0x7fffffff, 0x80000000, 0xfffffffe, MASK)
    result = []
    for i in range(32):
        a, b = (edge[i % 8], edge[(i * 3 + 1) % 8]) if i % 16 < 8 else (rng.getrandbits(32), rng.getrandbits(32))
        extra = 0 if i < 16 else (edge[i % 8] or MASK)
        obj = bytearray([0xa5] * 0x108)
        for offset, value in ((0x18, a), (0x1c, b), (0x100, extra)):
            struct.pack_into('<I', obj, offset, value)
        regs = dict(zip(REGS, (0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00,
                               STACK, 0x12345678, OBJECT, OBJECT + 0x100)))
        result.append(dict(fields=(a, b, extra), regs=regs, obj=bytes(obj),
                           stack=struct.pack('<II', RETURN, OBJECT)))
    return result


def oracle(case):
    """Independent modular arithmetic and integer flags, no disassembly/lift input."""
    a, b, extra = case['fields']
    regs = dict(case['regs'], esp=STACK + 4, ecx=OBJECT, edx=extra)
    if not extra:
        regs['eax'], flags = MASK, 0x286  # OR -1; AF undefined and normalized away.
    else:
        left = (a - b) & MASK
        value = (left + extra) & MASK
        regs['eax'] = value
        flags = 0x202 | int(left + extra > MASK)
        flags |= int((value & 255).bit_count() % 2 == 0) << 2
        flags |= int(bool((left ^ extra ^ value) & 16)) << 4
        flags |= int(value == 0) << 6 | (value >> 31) << 7
        flags |= int(bool((~(left ^ extra) & (left ^ value)) & 0x80000000)) << 11
    return dict(regs=regs, eflags=flags, mem={}, fp_depth=0, st=[])


def reference(code, inputs):
    """Bounded original x86 execution, explicit logical reads and no stores."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn import x86_const as X
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_AC_WRITE
    from capstone.x86 import X86_OP_MEM
    decoder = Cs(CS_ARCH_X86, CS_MODE_32)
    decoder.detail = True
    states = []
    ids = [getattr(X, 'UC_X86_REG_' + r.upper()) for r in REGS]
    for case in inputs:
        mu = Uc(UC_ARCH_X86, UC_MODE_32)
        pages = (ENTRY & ~4095, OBJECT, STACK)
        for page in pages:
            mu.mem_map(page, 4096)
        mu.mem_write(ENTRY, code)
        mu.mem_write(OBJECT, case['obj'])
        mu.mem_write(STACK, case['stack'])
        before = [bytes(mu.mem_read(p, 4096)) for p in pages]
        for r, value in zip(ids, case['regs'].values()):
            mu.reg_write(r, value)
        mu.reg_write(X.UC_X86_REG_EFLAGS, 0x202)
        pc = ENTRY
        for _ in range(64):
            if pc == RETURN:
                break
            if not ENTRY <= pc < ENTRY + len(code):
                raise ValueError('Escaping instruction')
            insn = next(decoder.disasm(code[pc-ENTRY:], pc, count=1), None)
            if insn is None or insn.mnemonic not in ('mov', 'test', 'je', 'jne', 'jmp', 'sub', 'add', 'or', 'ret', 'nop'):
                raise ValueError('Unsupported reference instruction')
            reads = []
            for operand in insn.operands:
                if operand.type != X86_OP_MEM:
                    continue
                if operand.access & CS_AC_WRITE or operand.mem.segment:
                    raise ValueError('Reference store or segment operand')
                def register(reg):
                    return mu.reg_read(getattr(X, 'UC_X86_REG_'+insn.reg_name(reg).upper())) if reg else 0
                address = (register(operand.mem.base) + register(operand.mem.index)*operand.mem.scale + operand.mem.disp) & MASK
                reads.append((address, operand.size))
            if insn.mnemonic == 'ret':
                if insn.op_str:
                    raise ValueError('Unexpected return cleanup')
                reads.append((mu.reg_read(X.UC_X86_REG_ESP), 4))
            for address, size in reads:
                if not any(start <= address and address + size <= start + length
                           for start, length in ((OBJECT, 0x108), (STACK, 8))):
                    raise ValueError('Out-of-span reference read')
            mu.emu_start(pc, RETURN, timeout=100000, count=1)
            pc = mu.reg_read(X.UC_X86_REG_EIP)
        if pc != RETURN:
            raise ValueError('Reference did not return within budget')
        if before != [bytes(mu.mem_read(p, 4096)) for p in pages]:
            raise ValueError('Reference memory changed')
        flags = mu.reg_read(X.UC_X86_REG_EFLAGS)
        if not case['fields'][2]:
            flags &= ~16  # Only architecturally undefined AF on logical branch.
        state = dict(regs=dict(zip(REGS, (mu.reg_read(r) for r in ids))),
                     eflags=flags, mem={}, fp_depth=0, st=[])
        if compare([oracle(case)], [state])['matched'] != 1:
            raise ValueError('Independent x86 oracle mismatch')
        states.append(state)
    return states


def assemble(text, inputs):
    """Retain pinned 1250 body verbatim; replace fixture inputs/transport explicitly."""
    start = text.index('void object_query_1240(')
    leaf = text.index('void object_query_1250(')
    end = text.index('void object_query_1270(')
    body = text[leaf:end]
    prefix = text[:start]
    old = '#define MEM32(addr) ts2_checked_read32(&query_view, (uint32_t)(addr))'
    if prefix.count(old) != 1:
        raise ValueError('Unexpected memory seam')
    prefix = prefix.replace(old, '#define MEM32(addr) ts2_image_read32((uint32_t)(addr))')
    source = '#include "image_dispatch.h"\n' + prefix + body
    source += '\nstatic void leaf_callback(uint32_t *s) {\n'
    # Inspect the actual persistent guest spans, not merely the host input arrays.
    source += f'uint32_t before[68]; for(int j=0;j<68;++j) before[j]=ts2_image_read32(j<66 ? {OBJECT}u+4*j : {STACK}u+4*(j-66));\n'
    source += ''.join(f'g_{r}=s[{i}];\n' for i, r in enumerate(REGS))
    source += 'g_flag_k=FK_NONE; g_flag_a=g_flag_b=g_flag_cf=0;\nobject_query_1250();\n'
    source += f'for(int j=0;j<68;++j) if(before[j]!=ts2_image_read32(j<66 ? {OBJECT}u+4*j : {STACK}u+4*(j-66))) exit(106);\n'
    source += ''.join(f's[{i}]=g_{r};\n' for i, r in enumerate(REGS))
    source += 's[8]=recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);\n}\nint fixture_main(void) {\n'
    for i, case in enumerate(inputs):
        values = lambda data: ','.join(str(v) for v in data)
        source += '{\nunsigned char obj[]={'+values(case['obj'])+'};\n'
        source += 'unsigned char stack[]={'+values(case['stack'])+'};\n'
        source += 'uint32_t s[]={'+values([*case['regs'].values(), 0x202])+'};\n'
        source += f'Ts2ReadSpan spans[]={{{{{OBJECT}u,sizeof(obj),obj}},{{{STACK}u,sizeof(stack),stack}}}};\n'
        source += f'Ts2ReadEntry entry={{{ENTRY}u,leaf_callback}};\n'
        source += f'if(ts2_image_dispatch({ENTRY}u,s,spans,2,&entry,1)!=TS2_READ_OK) return 105;\n'
        if not case['fields'][2]:
            source += 's[8]&=~16u;\n'
        source += f'printf("CASE {i}\\nR");\n'
        source += 'for(int j=0;j<8;++j) printf(" %08x",s[j]);\n'
        source += 'printf("\\nF %08x\\nT 0\\nENDCASE\\n",s[8]);\n}\n'
    source += 'return 0;\n}\n'
    if source.count(body) != 1:
        raise ValueError('Changed lifted body')
    return source, hashlib.sha256(body.encode()).hexdigest()


def check(expected, text):
    actual = parse_output(text)
    if len(expected) != 32 or compare(expected, actual)['matched'] != 32:
        raise ValueError('Native state mismatch')
    return 32


def run(output):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    row = dict(schema='ts2-image-leaf/1', success=False, rva='0x1250',
               fresh_lift=False, fresh_x86_reference=False, android_executed=False,
               arm64_executed=False, runs={}, commands=[], timings={},
               pcrecomp_revision='c0cbd3e3653010782b17e8a87b58953608ea411c',
               limits=['integer-only read-only leaf, not startup',
                       'undefined AF normalized only on zero branch',
                       'complete declared native input spans and full mapped image unchanged',
                       'reference three full pages unchanged; no native gap-page comparison',
                       'zero FP transport, no FP/SIMD/SEH/transient-write proof',
                       'single-owner callbacks and nontransactional input copies'])
    def command(name, argv):
        record = dict(name=name, argv=[str(a) for a in argv], exit_code=None)
        row['commands'].append(record)
        start = time.monotonic()
        try:
            with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
                proc = subprocess.run(record['argv'], cwd=ROOT, stdout=out, stderr=err, timeout=180)
            record['exit_code'] = proc.returncode
            if proc.returncode:
                raise ValueError('Child failure')
        finally:
            record['seconds'] = time.monotonic()-start
    try:
        fixture = ROOT/'work/interop-legacy-002'
        image, original = fixture/'analysis-image.bin', fixture/'group.c'
        if digest(image) != IMAGE_SHA or digest(original) != SOURCE_SHA:
            raise ValueError('Private pin mismatch')
        upstream = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(upstream)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        code = pe.get_data(0x1250, 27)
        if hashlib.sha256(code).hexdigest() != RANGE_SHA:
            raise ValueError('Range pin mismatch')
        for address, size in ((OBJECT, 0x108), (STACK, 8)):
            if address < pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.SizeOfImage and address+size > pe.OPTIONAL_HEADER.ImageBase:
                raise ValueError('Inputs alias image')
        inputs = cases()
        start = time.monotonic()
        states = reference(code, inputs)
        row['timings']['fresh_x86_and_oracle'] = time.monotonic()-start
        row['fresh_x86_reference'] = True
        (output/'reference.json').write_text(json.dumps(dict(states=states))+'\n')
        source, body_sha = assemble(original.read_text(), inputs)
        (output/'probe.c').write_text(source)
        row.update(image_sha256=IMAGE_SHA, source_sha256=SOURCE_SHA, body_sha256=body_sha,
                   reference_sha256=digest(output/'reference.json'),
                   object_address=OBJECT, stack_address=STACK,
                   adapter_sha256=digest(ROOT/'scripts/recomp/image_dispatch.cpp'))
        for isa in ('host', 'arm64'):
            command(isa+'-build', ['cmake', '--build', ROOT/'build'/isa, '-j4'])
            opts = [] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']
            obj, adapter, exe = [output/(isa+s) for s in ('.o', '-adapter.o', '-private')]
            command(isa+'-compile', ['zig-cc', *opts, '-D_POSIX_C_SOURCE=200809L', '-std=c11', '-O0', '-I'+str(ROOT/'tools'),
                    '-I'+str(ROOT/'scripts/recomp'), '-I'+str(upstream/'runtime/recomp32'),
                    '-c', output/'probe.c', '-o', obj])
            command(isa+'-adapter', ['zig-cxx', *opts, '-std=c++20', '-O0',
                    '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'native/include'),
                    '-c', ROOT/'scripts/recomp/image_dispatch.cpp', '-o', adapter])
            command(isa+'-link', ['zig-cxx', *opts, obj, adapter, ROOT/'build'/isa/'libts2_core.a', '-lm', '-o', exe])
            header = exe.read_bytes()[:20]
            if header[:6] != b'\x7fELF\x02\x01' or int.from_bytes(header[18:20], 'little') != (62 if isa=='host' else 183):
                raise ValueError('Wrong ELF ISA')
            argv = [exe, image] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh', exe, image]
            command(isa+'-execute', argv)
            matched = check(states, (output/(isa+'-execute.stdout')).read_text())
            row['runs'][isa] = dict(matched=matched, binary_sha256=digest(exe),
                                   stdout_sha256=digest(output/(isa+'-execute.stdout')))
        if digest(image) != IMAGE_SHA or digest(original) != SOURCE_SHA:
            raise ValueError('Private input changed')
        if row['runs']['host']['stdout_sha256'] != row['runs']['arm64']['stdout_sha256']:
            raise ValueError('Cross-ISA stream differs')
        row.update(success=True, arm64_executed=True, image_unchanged=True)
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        run(args.output)
    except Exception:
        parser.exit(1, 'Image leaf comparison failed; inspect private artifacts.\n')
    print('RVA1250 persistent image: fresh x86/oracle32; host32; AArch64 Linux/QEMU32; not Android')


if __name__ == '__main__':
    main()
