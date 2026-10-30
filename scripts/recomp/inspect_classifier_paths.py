#!/usr/bin/env python3
"""Bounded F2 feasibility trace. No external target executes or receives a response.

Metadata only is public; all instruction/state observations stay under work/.
This is not a whole-function differential or a replacement for service contracts.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_initialization_producer as producer
c = producer.common
TABLE_PAGE = c.BASE+0x1050000
PAGES = (*c.DATA_PAGES, TABLE_PAGE, c.IMAGE_PAGES[1])


def state(n, table_page):
    regs, pages = c.state(n, c.CLASSIFIER)
    values = (1, 6, 0xffffffff, 0x80000000, c.PAGES[2]+128, 1252, 65001, 1200)
    regs['edi'] = values[n % len(values)]
    c.require(len(table_page) == 4096)
    del pages[c.IMAGE_PAGES[0]]
    pages[TABLE_PAGE] = bytearray(table_page)
    return regs, pages


def trace(nodes, code_pages, entry, regs, pages, budget=128):
    """Independent checked single-step trace; never executes outside supplied nodes."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from capstone import CS_AC_READ, CS_AC_WRITE, CS_GRP_CALL
    from capstone.x86 import X86_OP_MEM, X86_OP_IMM
    import unicorn.x86_const as x
    c.require(set(pages) == set(PAGES) and set(regs) == set(c.REGS))
    c.require(type(budget) is int and 0 < budget <= 128 and entry in nodes)
    c.require(not set(code_pages) & (set(PAGES) | {c.RETURN}))
    mapped = {**code_pages, **pages, c.RETURN: bytes(4096)}
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, data in mapped.items():
        c.require(p % 4096 == 0 and len(data) == 4096)
        u.mem_map(p, 4096); u.mem_write(p, bytes(data))
    ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in c.REGS}
    for r, value in regs.items():
        c.require(type(value) is int and 0 <= value <= 0xffffffff)
        u.reg_write(ids[r], value)
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    visited, pc, outcome = [], entry, 'budget'
    def allowed(address, size, write=False):
        return (size in (1, 4) and address % size == 0 and
                any(p <= address <= p+4096-size for p in (c.DATA_PAGES if write else PAGES)))
    for _ in range(budget):
        if pc == c.RETURN:
            c.require(visited and nodes[visited[-1]].mnemonic == 'ret')
            outcome = 'returned'; break
        if pc not in nodes:
            outcome = 'outside-closure'; break
        i = nodes[pc]
        c.require(i.mnemonic in ('mov','movzx','movsx','lea','push','pop','ret','call',
            'cmp','test','add','sub','inc','dec','and','or','xor','shl','shr','sar',
            'jmp','je','jne','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns','jo','jno','jp','jnp','setne'))
        safe = True
        for op in i.operands:
            if op.type != X86_OP_MEM or i.mnemonic == 'lea': continue
            m = op.mem
            c.require(not m.segment and op.access & (CS_AC_READ | CS_AC_WRITE))
            address = m.disp
            for reg, scale in ((m.base, 1), (m.index, m.scale)):
                if reg:
                    name = i.reg_name(reg); c.require(name in ids)
                    address += u.reg_read(ids[name])*scale
            safe &= allowed(address & 0xffffffff, op.size, bool(op.access & CS_AC_WRITE))
        if i.mnemonic in ('push','pop','ret') or i.group(CS_GRP_CALL):
            pushing = i.mnemonic == 'push' or i.group(CS_GRP_CALL)
            sp = u.reg_read(ids['esp'])
            safe &= allowed((sp-4 if pushing else sp) & 0xffffffff, 4, pushing)
        if not safe:
            outcome = 'unsafe-access'; break
        if i.group(CS_GRP_CALL):
            c.require(len(i.operands) == 1 and i.operands[0].type == X86_OP_IMM)
            if (i.operands[0].imm & 0xffffffff) not in nodes:
                outcome = 'external-call'; break
        visited.append(pc)
        u.emu_start(pc, 0, count=1); pc = u.reg_read(x.UC_X86_REG_EIP)
    if pc == c.RETURN:
        c.require(visited and nodes[visited[-1]].mnemonic == 'ret')
        outcome = 'returned'
    for p in set(code_pages) | {TABLE_PAGE, c.IMAGE_PAGES[1], c.RETURN}:
        c.require(bytes(u.mem_read(p, 4096)) == bytes(mapped[p]))
    return dict(outcome=outcome, pc=pc, visited=visited,
        regs=[u.reg_read(ids[r]) for r in c.REGS],
        pages=b''.join(bytes(u.mem_read(p, 4096)) for p in PAGES).hex())


def run(output, index):
    output = c.private_output(output)
    image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
    c.require(c.digest(image) == c.IMAGE_SHA)
    context = c.check_index(json.loads(index.read_text()), c.CLASSIFIER)
    import pefile
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    import hashlib
    pe = pefile.PE(data=image.read_bytes())
    c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
    code = pe.get_data(c.CLASSIFIER, 49)
    c.require(hashlib.sha256(code).hexdigest() == c.CLASSIFIER_SHA)
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    nodes = {i.address:i for i in md.disasm(code, c.BASE+c.CLASSIFIER)}
    c.require(len(nodes) == 21 and sum(i.size for i in nodes.values()) == 49)
    page = c.BASE+0x10000
    code_pages = {page:bytearray(4096)}
    code_pages[page][0x700:0x731] = code
    table_page = pe.get_data(0x1050000,4096)
    c.require(len(table_page) == 4096 and hashlib.sha256(table_page).hexdigest() ==
              '419271c57b49a1eed170832185a7b7fb799185309517c611b439d4cdafc92ee2')
    rows = [dict(case=n, **trace(nodes, code_pages, c.BASE+c.CLASSIFIER, *state(n,table_page))) for n in range(64)]
    (output/'traces.json').write_text(json.dumps(rows)+'\n')
    summary = dict(schema='ts2-classifier-path-feasibility/1',
        image_sha256=c.IMAGE_SHA, harness_sha256=c.digest(Path(__file__)),
        index_sha256=c.digest(index), index=context, invocation=[sys.executable,*sys.argv],
        cases=64, outcomes={key:sum(r['outcome']==key for r in rows) for key in sorted({r['outcome'] for r in rows})},
        stopping_rvas=sorted({hex(r['pc']-c.BASE) for r in rows}),
        external_callee_rvas=sorted({hex((nodes[r['pc']].operands[0].imm & 0xffffffff)-c.BASE)
                                    for r in rows if r['outcome']=='external-call'}),
        table_page_sha256=hashlib.sha256(table_page).hexdigest(),
        table_page_rva=hex(TABLE_PAGE-c.BASE),
        table_semantics_established=False,
        visited_instructions=len(set(a for r in rows for a in r['visited'])),
        external_target_executed=False, host_executed=False, arm64_executed=False,
        android_executed=False, stub=False, whole_function_verified=False,
        limits=['Authored incoming nonzero EDI values, not a proven caller input contract',
                'Read/write checked bounded original-x86 trace only; no service response or external body',
                'No host/AArch64 differential claim from this feasibility trace'])
    c.require(c.digest(image) == c.IMAGE_SHA)
    (output/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--index',type=Path,required=True)
    a = p.parse_args()
    r = run(a.output,a.index)
    print(json.dumps({k:r[k] for k in ('cases','outcomes','stopping_rvas','visited_instructions')}))

if __name__ == '__main__': main()
