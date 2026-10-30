#!/usr/bin/env python3
"""Diagnose bounded original 3700 nonempty prefixes; never supply callees.

Authored checking/transport only. Original bytes and CPU states stay private.
A diagnostic fault is evidence of a rejected fixture, NOT a behavior match.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_mode_empty as m
from inspect_startup_dependency import crosscheck_index
c = m.c
TEXTS = (b'a', b'r', b'w', b'rb', b'wb', b'r+', b'wb+', b'x')


def state(n, *, bound_cursor=False):
    c.require(type(n) is int and 0 <= n < 64 and type(bound_cursor) is bool)
    regs, pages = m.state(n)
    # Unlike the empty-only corpus, leave room for a complete nonempty string.
    regs['eax'] = c.DATA_PAGES[2]+(0, 1, 128, 4088)[n % 4]
    text = TEXTS[n % len(TEXTS)]+b'\0'
    off = regs['eax']-c.DATA_PAGES[2]
    pages[c.DATA_PAGES[2]][off:off+len(text)] = text
    if bound_cursor:
        cursor = c.DATA_PAGES[3]+128
        struct.pack_into('<III', pages[c.DATA_PAGES[1]],
                         regs['esi']-c.DATA_PAGES[1]+0x1d8,
                         cursor+64, cursor, cursor)
    return regs, pages


def allowed(address, size, write=False):
    return (type(address) is int and type(size) is int and size > 0 and
            0 <= address <= 0x100000000-size and
            any(p <= address and address+size <= p+4096
                for p in (c.DATA_PAGES if write else c.PAGES)))


def trace(nodes, code_pages, regs, pages, entry=c.BASE+m.RVA, budget=128):
    """Single-step without Python Unicorn callbacks; stop BEFORE first call.

    Validate every explicit/implicit access before execution. Invalid access is
    captured with PC/address/width/direction and full private boundary state.
    It is not executed, repaired or counted as a successful original reference.
    Unknown instructions/targets and exhausted budgets raise, never pass.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    from capstone import CS_GRP_CALL, CS_AC_READ, CS_AC_WRITE
    from capstone.x86 import X86_OP_MEM, X86_OP_IMM
    c.require(type(budget) is int and 0 < budget <= 4096 and entry in nodes)
    c.require(set(regs) == set(c.REGS) and set(pages) == set(c.PAGES))
    c.require(not set(code_pages) & (set(c.PAGES) | {c.RETURN}))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, data in {**code_pages, **pages, c.RETURN: bytes(4096)}.items():
        c.require(type(p) is int and p % 4096 == 0 and len(data) == 4096)
        u.mem_map(p, 4096); u.mem_write(p, bytes(data))
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in c.REGS}
    for r in c.REGS:
        c.require(type(regs[r]) is int and 0 <= regs[r] <= 0xffffffff)
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    visited, pc = [], entry

    def result(kind, **detail):
        for p, data in code_pages.items():
            c.require(bytes(u.mem_read(p, 4096)) == bytes(data))
        for p in c.PAGES:
            if p not in c.DATA_PAGES:
                c.require(bytes(u.mem_read(p, 4096)) == bytes(pages[p]))
        return dict(kind=kind, site=pc, visited=visited,
                    regs={r: u.reg_read(ids[r]) for r in c.REGS},
                    pages={p: bytes(u.mem_read(p, 4096)) for p in c.PAGES}, **detail)

    for _ in range(budget):
        c.require(pc in nodes)
        i = nodes[pc]
        c.require(bytes(u.mem_read(pc, i.size)) == bytes(i.bytes))
        if i.group(CS_GRP_CALL):
            c.require(len(i.operands) == 1 and i.operands[0].type == X86_OP_IMM)
            return result('call', target=i.operands[0].imm & 0xffffffff)
        c.require(i.mnemonic in ('nop','mov','movzx','movsx','lea','push','pop','ret',
            'cmp','test','add','sub','inc','dec','and','or','xor','shl','shr','sar',
            'jmp','je','jne','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns',
            'jo','jno','jp','jnp','setne'))
        for op in i.operands:
            if op.type != X86_OP_MEM or i.mnemonic == 'lea':
                continue
            mem = op.mem
            c.require(not mem.segment and op.access & (CS_AC_READ | CS_AC_WRITE))
            address = mem.disp
            for reg, scale in ((mem.base, 1), (mem.index, mem.scale)):
                if reg:
                    name = i.reg_name(reg); c.require(name in ids)
                    address += u.reg_read(ids[name])*scale
            address &= 0xffffffff
            write = bool(op.access & CS_AC_WRITE)
            if not allowed(address, op.size, write):
                return result('invalid-memory', address=address, size=op.size,
                              write=write, base=i.reg_name(mem.base), displacement=mem.disp)
        if i.mnemonic in ('push', 'pop', 'ret'):
            write = i.mnemonic == 'push'
            sp = u.reg_read(ids['esp'])
            address = (sp-4 if write else sp) & 0xffffffff
            if not allowed(address, 4, write):
                return result('invalid-memory', address=address, size=4,
                              write=write, base='esp', displacement=-4 if write else 0)
        visited.append(pc)
        u.emu_start(pc, 0, count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
        if pc == c.RETURN:
            return result('return')
    raise ValueError('prefix execution budget exhausted')


def boundary_contract(regs, pages, observed, *, bound_cursor):
    """Independent memory/ABI subset, not a volatile-GPR or callee oracle."""
    c.require(type(bound_cursor) is bool)
    h = regs['esi']-c.DATA_PAGES[1]
    c.require(0 <= h <= 4096-528)
    cursor = struct.unpack_from('<I', pages[c.DATA_PAGES[1]], h+0x1dc)[0]
    after = {p: bytearray(b) for p,b in pages.items()}
    if not bound_cursor:
        c.require(observed['kind'] == 'invalid-memory' and observed['site'] == c.BASE+0x38b8)
        c.require(observed['address'] == cursor and observed['size'] == 1 and
                  observed['write'] is True and not allowed(cursor, 1, True))
    else:
        c.require(observed['kind'] == 'call' and observed['site'] == c.BASE+0x3903 and
                  observed['target'] == c.BASE+0x1820)
        offset = regs['eax']-c.DATA_PAGES[2]
        c.require(0 <= offset < 4096)
        end = pages[c.DATA_PAGES[2]].index(0, offset)
        sample = pages[c.DATA_PAGES[2]][offset:end+1]
        c.require(1 < len(sample) <= 4 and cursor == c.DATA_PAGES[3]+128)
        after[c.DATA_PAGES[3]][128:128+len(sample)] = sample
        struct.pack_into('<I', after[c.DATA_PAGES[1]], h+0x1dc, cursor+len(sample))
        sp = observed['regs']['esp']
        c.require(sp == regs['esp']-24)
        c.require(struct.unpack_from('<II', observed['pages'][c.DATA_PAGES[0]],
                                     sp-c.DATA_PAGES[0]) == (cursor, 0))
    for name in ('esi', 'ebx'):
        c.require(observed['regs'][name] == regs[name])
    c.require(all(observed['pages'][p] == after[p]
                  for p in c.PAGES if p != c.DATA_PAGES[0]))


def reject_controls(regs, pages, observed, *, bound_cursor):
    """Every case must reject both a boundary and a memory/address mutation."""
    import copy
    bad_boundary = copy.deepcopy(observed)
    bad_memory = copy.deepcopy(observed)
    if bound_cursor:
        bad_boundary['target'] ^= 4
        page = c.DATA_PAGES[3]
        data = bytearray(bad_memory['pages'][page]); data[128] ^= 1
        bad_memory['pages'][page] = bytes(data)
    else:
        bad_boundary['site'] ^= 4
        bad_memory['address'] ^= 1
    for bad in (bad_boundary, bad_memory):
        try:
            boundary_contract(regs, pages, bad, bound_cursor=bound_cursor)
        except ValueError:
            continue
        raise ValueError('negative control accepted')


def run(index, output):
    output = c.private_output(output)
    sources = (Path(__file__), Path(m.__file__), Path(c.__file__),
               Path(c.state.__code__.co_filename), Path(m.decode_flow.__code__.co_filename),
               Path(crosscheck_index.__code__.co_filename))
    row = dict(schema='ts2-mode-prefix/1', success=False, stub=False,
        image_sha256=c.IMAGE_SHA, invocation=[sys.executable, *sys.argv],
        source_sha256={str(p): c.digest(p) for p in sources}, index_sha256=c.digest(index),
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, external_callee_executed=False,
        dependencies_newly_resolved=0, whole_function_verified=False,
        limits=['Dirty receiver vs synthetic bounded descriptor; no caller-produced handle/lifetime proof',
                'Dirty invalid-memory cases are localized fixture failures, never behavior matches',
                'Bounded descriptor permits copying input+NUL before pending 1820 call; subset contract only',
                'No callee responses, complete return equivalence, native execution or Android/gameplay'])
    try:
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(m.RVA, m.SIZE)
        c.require(hashlib.sha256(code).hexdigest() == m.PIN)
        _, nodes, _, flow = m.decode_flow(code, c.BASE+m.RVA, lambda i: i)
        c.require(len(nodes) == m.COUNT and flow['size_bytes'] == m.SIZE)
        row['index'] = crosscheck_index(json.loads(index.read_text()),
            dict(flow, instruction_rvas=[hex(a-c.BASE) for a in sorted(nodes)]), m.RVA)
        cp = bytearray(4096); cp[m.RVA % 4096:m.RVA % 4096+m.SIZE] = code
        results, counts, sites = [], {}, set()
        for bound_cursor in (False, True):
            for n in range(64):
                regs, pages = state(n, bound_cursor=bound_cursor)
                observed = trace(nodes, {c.BASE+0x3000: cp}, regs, pages)
                boundary_contract(regs, pages, observed, bound_cursor=bound_cursor)
                reject_controls(regs, pages, observed, bound_cursor=bound_cursor)
                key = ('bound' if bound_cursor else 'dirty')+':'+observed['kind']+':'+hex(observed['site']-c.BASE)
                counts[key] = counts.get(key, 0)+1
                sites.update(observed['visited'])
                results.append(dict(case=n, bound_cursor=bound_cursor, input_regs=regs,
                    input_pages={hex(p): bytes(b).hex() for p,b in pages.items()},
                    observed=dict(observed, pages={hex(p): b.hex() for p,b in observed['pages'].items()})))
        private = output/'diagnostics.json'; private.write_text(json.dumps(results)+'\n')
        c.require(c.digest(image) == c.IMAGE_SHA and c.digest(index) == row['index_sha256'])
        c.require(all(c.digest(Path(p)) == sha for p,sha in row['source_sha256'].items()))
        row.update(success=True, diagnosed_cases=128, stop_counts=counts,
                   boundary_subset_matches=64, dirty_fixture_faults_localized=64,
                   rejecting_controls=dict(boundary=128, memory_or_address=128),
                   coverage=dict(visited=len(sites), total=len(nodes)),
                   diagnostics_sha256=c.digest(private))
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        row = run(a.index, a.output)
    except Exception:
        p.exit(1, '3700 prefix diagnosis rejected; inspect private receipt.\n')
    print(json.dumps({k: row[k] for k in ('success','diagnosed_cases','stop_counts','coverage')}))


if __name__ == '__main__':
    main()
