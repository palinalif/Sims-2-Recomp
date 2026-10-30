#!/usr/bin/env python3
"""One selected original leaf: bounded x86 reference vs unchanged lift on two ISAs.

Synthetic global/entry states, NOT the caller's ABI or a Windows service binding.
No calls, PE launch, callbacks, exception flow or runtime x86 interpreter.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_startup import BASE, RESOURCE_LEAF_RVA, decode_flow
from measure_leaf import ROOT, IMAGE_SHA, digest
from inspect_startup_dependency import crosscheck_index

RVA = RESOURCE_LEAF_RVA
REGS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp')
PAGES = (0x70000000, 0x72000000, 0xA104F000, 0xA10DF000)
RETURN = 0x71000000
TEMPLATE = Path(__file__).with_name('resource_leaf_transport.c.in')


def require(ok):
    if not ok:
        raise ValueError('Selected leaf contract rejected')


def reference_case(code, entry, regs, pages, budget=64, *, prefix=None, accesses=None):
    """Hook-free reference; prevalidate every explicit/implicit 32-bit access.

    Calls/segments/other opcodes rejected before execution. Data pages are explicit
    synthetic windows (including slack), not evidence of real global ownership.
    """
    from capstone.x86 import X86_OP_MEM
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    require(0 < len(code) <= 128 and set(regs) == set(REGS))
    require(0 < budget <= 64 and set(pages) == set(PAGES))
    require(all(len(p) == 4096 for p in pages.values()))
    _, nodes, _, analysis = decode_flow(code, entry, lambda i: i)
    require(analysis['size_bytes'] == len(code) and not analysis['calls'])
    require(all(i.mnemonic in ('mov', 'push', 'pop', 'xor', 'test', 'cmp', 'je', 'jne', 'jmp', 'ret')
                for i in nodes.values()))
    require(all(o.size == 4 or (i.mnemonic == 'mov' and o.size == 1)
                for i in nodes.values() for o in i.operands))
    code_page = entry & ~4095
    require(code_page == (entry+len(code)-1) & ~4095 and code_page not in PAGES)
    require(RETURN not in PAGES and code_page != RETURN)
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, data in pages.items():
        u.mem_map(p, 4096)
        u.mem_write(p, bytes(data))
    for p in (code_page, RETURN):
        u.mem_map(p, 4096)
    u.mem_write(entry, code)
    plan = []
    return_address = RETURN
    if prefix is not None:
        from reference_resource_call import prefix_plan
        prefix_code, prefix_entry = prefix
        require(prefix_entry & ~4095 == code_page and
                prefix_entry+len(prefix_code) <= code_page+4096 and
                (prefix_entry+len(prefix_code) <= entry or entry+len(code) <= prefix_entry))
        plan = prefix_plan(prefix_code, prefix_entry, regs, pages[PAGES[0]])
        require(plan[-1]['next_pc'] == entry)
        return_address = prefix_entry+len(prefix_code)
        u.mem_write(prefix_entry, prefix_code)
    immutable = bytes(u.mem_read(code_page, 4096))
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS:
        require(type(regs[r]) is int and 0 <= regs[r] <= 0xFFFFFFFF)
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    for step in plan:
        u.emu_start(step['pc'], 0, count=1)
        require(u.reg_read(x.UC_X86_REG_EIP) == step['next_pc'])
        require(all(u.reg_read(ids[r]) == step['regs'][r] for r in REGS))
        require((u.reg_read(x.UC_X86_REG_EFLAGS) ^ step['flags']) & step['flag_mask'] == 0)
        require(bytes(u.mem_read(PAGES[0], 4096)) == step['stack'])
        require(all(bytes(u.mem_read(p, 4096)) == bytes(pages[p]) for p in PAGES[1:]))
        require(bytes(u.mem_read(code_page, 4096)) == immutable)
        require(bytes(u.mem_read(RETURN, 4096)) == bytes(4096))
    pc, visited = entry, set()

    def check(a, size=4):
        require(size in (1, 4) and type(a) is int and a % size == 0 and
                any(p <= a <= p+4096-size for p in PAGES))

    for _ in range(budget):
        require(pc in nodes)
        i = nodes[pc]
        visited.add(pc-entry)
        for op in i.operands:
            if op.type != X86_OP_MEM:
                continue
            m = op.mem
            require(not m.segment)
            a = m.disp
            for reg, scale in ((m.base, 1), (m.index, m.scale)):
                if reg:
                    require(i.reg_name(reg) in ids)
                    a += u.reg_read(ids[i.reg_name(reg)])*scale
            check(a & 0xFFFFFFFF, op.size)
            if accesses is not None:
                accesses.append((a & 0xFFFFFFFF, op.size))
        sp = u.reg_read(ids['esp'])
        if i.mnemonic in ('push', 'pop', 'ret'):
            check(sp-4 if i.mnemonic == 'push' else sp)
        u.emu_start(pc, 0, count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
        require(bytes(u.mem_read(code_page, 4096)) == immutable)
        require(bytes(u.mem_read(RETURN, 4096)) == bytes(4096))
        if i.mnemonic == 'ret':
            require(pc == return_address)
            return dict(regs=[u.reg_read(ids[r]) for r in REGS],
                pages=b''.join(bytes(u.mem_read(p, 4096)) for p in PAGES).hex()), visited
    raise ValueError('Reference instruction budget exhausted')


def synthetic_global_state(n, pages, *, aliases=False):
    """Explicit hypotheses, NOT recovered global initializers or service state.

    Eight zero/mapped-pointer slot combinations x four pointed-byte values x
    two stack positions. Optional alias profiles use the declared ECX/EDX/stack
    argument payload addresses instead of distinct slot pointees. These test
    pointer equality hypotheses, not actual global ownership.
    Only declared payload/global pages are initialized.
    A reference rejection is a failed hypothesis, never a skipped case.
    """
    require(type(n) is int and 0 <= n < 64 and set(pages) == set(PAGES))
    require(all(len(p) == 4096 for p in pages.values()))
    slots = (0xA104F958, 0xA104F95C, 0xA10DFCAC)
    mask, byte = (n // 2) % 8, (0, 1, 0x7F, 0xFF)[n // 16]
    for k, slot in enumerate(slots):
        offset = (1024+k*64, 128, 256, 512)[n // 16] if aliases else 1024+k*64
        pointer = PAGES[1]+offset
        struct.pack_into('<I', pages[slot & ~4095], slot & 4095,
                         pointer if mask & (1 << k) else 0)
        pages[PAGES[1]][pointer-PAGES[1]] = byte
    return dict(slot_mask=mask, pointed_byte=byte, alias_profile=n // 16 if aliases else None)


def compare(text, expected):
    rows = [json.loads(line) for line in text.splitlines()]
    require(len(rows) == len(expected) == 64)
    for n, (row, wanted) in enumerate(zip(rows, expected)):
        require(type(row) is dict and set(row) == {'case', 'regs', 'pages'})
        require(type(row['case']) is int and row['case'] == n)
        require(type(row['regs']) is list and len(row['regs']) == 8 and
                all(type(v) is int and 0 <= v <= 0xFFFFFFFF for v in row['regs']))
        require(type(row['pages']) is str and len(row['pages']) == 32768)
        require(row == wanted)
    return dict(cases=64, matched=64)


def assemble(body):
    require(type(body) is str and bool(body.strip()))
    template = TEMPLATE.read_text()
    require(template.count('\n@BODY@\n') == 1)
    return template.replace('\n@BODY@\n', '\n'+body+'\n')


def run(output, index, caller_index=None, *, global_states=False, global_aliases=False):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-resource-leaf-native/1', rva=hex(RVA), success=False,
        image_sha256=IMAGE_SHA, invocation=[sys.executable, *sys.argv],
        harness_sha256=digest(Path(__file__)), template_sha256=digest(TEMPLATE),
        selected=True, attempted=False, lifted=False, compiled_for_aarch64=False,
        linked=False, matched_x86_reference=False, executed_under_qemu=False, android_executed=False,
        commands=[], runs={}, timings={}, linked_isas=[],
        synthetic_global_states=global_states, synthetic_global_aliases=global_aliases,
        compared=['eight final GPRs', 'four entire 4096-byte data pages'],
        limits=['synthetic entry/globals, caller ABI and real global ownership unknown',
                'no native guest PC/flags/FP/SIMD/transient-write comparison',
                'reference memory guard shares Capstone decoding; page slack admitted',
                'no callbacks, exceptions, service binding or game startup'])
    def command(name, argv, data=None, expected=0):
        start = time.monotonic()
        record = dict(name=name, argv=[str(a) for a in argv])
        row['commands'].append(record)
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            result = subprocess.run(record['argv'], input=data, stdout=out, stderr=err, cwd=ROOT, timeout=120)
        record.update(exit_code=result.returncode, seconds=time.monotonic()-start)
        require(result.returncode == expected)
    stage = 'reference'
    try:
        require(not global_aliases or global_states)
        start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
        code = pe.get_data(RVA, 72)
        _, nodes, _, analysis = decode_flow(code, BASE+RVA, lambda i: i)
        metadata = dict(analysis, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
        row['index'] = crosscheck_index(json.loads(index.read_text()), metadata, RVA)
        row['index_sha256'] = digest(index)
        prefix = None
        if caller_index is not None:
            from reference_resource_call import prefix_plan, RVA as CALLER
            from inspect_startup_dependency import first_direct_call, inspect_body
            caller = pe.get_data(CALLER, 55)
            row['caller_index'] = crosscheck_index(json.loads(caller_index.read_text()),
                inspect_body(caller, BASE+CALLER), CALLER)
            row['caller_index_sha256'] = digest(caller_index)
            site, target = first_direct_call(caller, BASE+CALLER)
            require(target == BASE+RVA)
            prefix = (caller[:site+5-(BASE+CALLER)], BASE+CALLER)
            row['limits'].append('Native starts at independently predicted caller-produced leaf frame; caller prefix not translated')
        rng = random.Random(11818726)
        inputs, expected, coverage, entry_stacks = bytearray(), [], set(), set()
        accesses = []
        for n in range(64):
            regs = {r: rng.getrandbits(32) for r in REGS}
            regs.update(esp=PAGES[0]+(0x800 if n%2 else 0xC00), ecx=PAGES[1]+128, edx=PAGES[1]+256)
            pages = {p: bytearray(4096) for p in PAGES}
            pages[PAGES[0]][:] = rng.randbytes(4096)
            # Deliberately synthetic data, not copied game globals or TLS state.
            sp = regs['esp']-PAGES[0]
            struct.pack_into('<II', pages[PAGES[0]], sp, RETURN, PAGES[1]+512+(n%4)*64)
            if global_states:
                synthetic_global_state(n, pages, aliases=global_aliases)
            result, seen = reference_case(code, BASE+RVA, regs, pages, prefix=prefix, accesses=accesses)
            if prefix is not None:
                # Original x86 ran prefix+leaf continuously. Native runs only the
                # leaf, starting from the independent raw prefix oracle's frame.
                plan = prefix_plan(*prefix, regs, pages[PAGES[0]])
                regs = plan[-1]['regs']
                pages[PAGES[0]] = bytearray(plan[-1]['stack'])
            require(result['regs'][-1] == regs['esp']+8)
            coverage.update(seen)
            expected.append(dict(case=n, **result))
            entry_stacks.add(regs['esp'])
            inputs.extend(struct.pack('<8I', *(regs[r] for r in REGS)))
            inputs.extend(b''.join(bytes(pages[p]) for p in PAGES))
        require(len(entry_stacks) == 2 and all(PAGES[0] <= sp <= PAGES[0]+4092 and sp % 4 == 0 for sp in entry_stacks))
        entry_stacks = sorted(entry_stacks)
        row['reference'] = dict(cases=64, returned=64, stack_delta_bytes=8,
            visited_instructions=len(coverage), total_instructions=len(nodes),
            uncovered_instruction_rvas=[hex(a-BASE) for a in sorted(nodes) if a-(BASE+RVA) not in coverage],
            explicit_global_operand_access_counts={hex(a-BASE): accesses.count((a, 4))
                for a in (0xA104F958, 0xA104F95C, 0xA10DFCAC)})
        row['timings']['reference'] = time.monotonic()-start
        (output/'input.bin').write_bytes(inputs)
        (output/'reference.json').write_text(json.dumps(expected))
        row['reference_sha256'] = digest(output/'reference.json')
        stage = 'lift'
        row['attempted'] = True
        command('lift', [sys.executable, ROOT/'scripts/recomp/measure_startup.py', '--rva', format(RVA,'X'),
            '--index', index, '--output', output/'lift'], expected=2)
        row['lift'] = json.loads((output/'lift/metrics.jsonl').read_text())
        require(row['lift']['lifted'] and row['lift']['compiled_for_aarch64'])
        row.update(lifted=True, compiled_for_aarch64=True)
        body = output/'lift/lifted.c'
        require(digest(body) == row['lift']['lifted_sha256'])
        (output/'transport.c').write_text(assemble(body.read_text()))
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        for isa in ('host','arm64'):
            stage = isa+'-compile'
            binary = output/isa
            command(stage, ['zig-cc', *([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                '-D_POSIX_C_SOURCE=200809L','-std=c11','-O0','-Werror=implicit-function-declaration',
                '-DTS2_ENTRY_SP_A='+str(entry_stacks[0])+'u', '-DTS2_ENTRY_SP_B='+str(entry_stacks[1])+'u',
                '-I'+str(upstream/'runtime/recomp32'),output/'transport.c','-o',binary])
            header = binary.read_bytes()[:20]
            require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little') == (62 if isa=='host' else 183))
            row.setdefault('binary_sha256', {})[isa] = digest(binary)
            row['linked_isas'].append(isa)
            row['linked'] = len(row['linked_isas']) == 2
            stage = isa+'-execute'
            command(stage, [binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary], bytes(inputs))
            if isa == 'arm64':
                row['executed_under_qemu'] = True
            stage = isa+'-compare'
            start = time.monotonic()
            row['runs'][isa] = compare((output/(isa+'-execute.stdout')).read_text(), expected)
            row['timings'][isa+'_comparison'] = time.monotonic()-start
        require((output/'host-execute.stdout').read_bytes() == (output/'arm64-execute.stdout').read_bytes())
        require(digest(image) == IMAGE_SHA)
        row.update(success=True, linked=True, matched_x86_reference=True, executed_under_qemu=True)
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'metrics.json').write_text(json.dumps(row, indent=2)+'\n')
        (output/'metrics.jsonl').write_text(json.dumps(row)+'\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--caller-index', type=Path, help='optional private caller envelope; native still executes leaf only')
    ap.add_argument('--global-states', action='store_true',
                    help='explicit zero/mapped-pointer globals and pointed-byte hypotheses; never inferred live state')
    ap.add_argument('--global-aliases', action='store_true',
                    help='with --global-states, use explicit pointee alias profiles')
    args = ap.parse_args()
    try:
        run(args.output, args.index.resolve(), args.caller_index, global_states=args.global_states,
            global_aliases=args.global_aliases)
    except Exception:
        print('Leaf pipeline rejected; inspect private metrics', file=sys.stderr)
        return 1
    print('64/64 original-reference matches on host and AArch64 Linux/QEMU; not Android')
    return 0


if __name__ == '__main__':
    sys.exit(main())
