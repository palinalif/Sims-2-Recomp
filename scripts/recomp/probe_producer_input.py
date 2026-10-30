#!/usr/bin/env python3
"""Bounded original-x86 20D0 first-call contract; no callee or native execution."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from execute_initialization_setter import require
from execute_cache_dispatch import BASE, REGS
from execute_cache_skip import private_output
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import decode_flow
from inspect_startup_dependency import crosscheck_index

RVA = 0x20d0
SIZE = 68
FUNCTION_SHA = 'd9b07486c58c7be6d13e8334dc9a849b93983a7d08836e9110b766fe6ad56829'
STACK, OBJECT = 0x21000000, 0x22000000
PAGES = (STACK, OBJECT)


def state(n):
    require(type(n) is int and 0 <= n < 64)
    rng = random.Random(0x20d000+n)
    pages = {p:bytearray(rng.randbytes(4096)) for p in PAGES}
    regs = {r:rng.getrandbits(32) for r in REGS}
    regs['esp'] = STACK+(0xc00 if n % 2 else 0x800)
    regs['eax'] = OBJECT+(0x100 if n % 2 else 0x600)
    selector = (0, 1, 0x80000000, 0xffffffff)[n % 4]
    struct.pack_into('<I', pages[OBJECT], regs['eax']-OBJECT+0xd4, selector)
    pointer = 0 if n % 5 == 0 else OBJECT+0xe00
    struct.pack_into('<I', pages[OBJECT], regs['eax']-OBJECT+0xd0, pointer)
    pages[OBJECT][0xe00:0xe07] = b'module\0'
    return regs, pages


def prefix_reference(nodes, entry, code_pages, regs, pages, budget=64):
    """Single step original instructions; STOP BEFORE first CALL (not a stub).

    No instruction hooks, endpoint responses, PC rewriting or callee entry.
    All instruction fetches and explicit/implicit memory ranges checked first.
    Each invocation has a new CPU. Only stack writes are permitted.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    from capstone import CS_AC_READ, CS_AC_WRITE, CS_GRP_CALL
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
    require(type(budget) is int and 0 < budget <= 256)
    require(set(regs) == set(REGS) and set(pages) == set(PAGES))
    require(entry in nodes and not set(code_pages) & set(PAGES))
    require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
    mapped = {**code_pages, **pages}
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, data in mapped.items():
        require(p % 4096 == 0 and len(data) == 4096)
        u.mem_map(p, 4096)
        u.mem_write(p, bytes(data))
    ids = {r:getattr(x, 'UC_X86_REG_'+r.upper()) for r in REGS}
    for r in REGS: u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    pc, visited, stopped = entry, set(), False

    def check(address, size, write):
        require(type(size) is int and size in (1, 2, 4))
        allowed = (STACK,) if write else PAGES
        require(0 <= address <= 0xffffffff-size+1 and
                any(p <= address <= p+4096-size for p in allowed))

    for _ in range(budget):
        require(pc in nodes)
        i = nodes[pc]
        require(bytes(u.mem_read(pc, i.size)) == bytes(i.bytes))
        if i.group(CS_GRP_CALL):
            op = i.operands[0]
            require(op.type in (X86_OP_REG, X86_OP_IMM))
            target = (u.reg_read(ids[i.reg_name(op.reg)]) if op.type == X86_OP_REG
                      else op.imm & 0xffffffff)
            stopped = True
            break
        require(i.mnemonic in ('mov', 'lea', 'push', 'test', 'jne', 'je', 'jmp', 'xor'))
        for op in i.operands:
            if op.type != X86_OP_MEM or i.mnemonic == 'lea': continue
            m = op.mem
            require(not m.segment and op.access & (CS_AC_READ | CS_AC_WRITE))
            address = m.disp
            for r, scale in ((m.base, 1), (m.index, m.scale)):
                if r:
                    name = i.reg_name(r)
                    require(name in ids)
                    address += u.reg_read(ids[name])*scale
            check(address & 0xffffffff, op.size, bool(op.access & CS_AC_WRITE))
        if i.mnemonic == 'push': check((u.reg_read(ids['esp'])-4) & 0xffffffff, 4, True)
        visited.add(pc)
        u.emu_start(pc, 0, count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
    require(stopped)
    for p, data in code_pages.items(): require(bytes(u.mem_read(p, 4096)) == bytes(data))
    return dict(site=pc, target=target,
                regs={r:u.reg_read(ids[r]) for r in REGS},
                pages={p:bytes(u.mem_read(p, 4096)) for p in PAGES}), visited


def contract(regs, pages, result):
    """Independent partial ABI oracle; NOT an oracle for scratch GPR values."""
    obj, sp = regs['eax'], regs['esp']
    selector = struct.unpack_from('<I', pages[OBJECT], obj-OBJECT+0xd4)[0]
    target = BASE+(0x10b60 if selector else 0x109d0)
    require(result['site'] == BASE+0x20f6 and result['target'] == target)
    require(result['regs']['esp'] == sp-16)
    for r in ('ebx', 'edi', 'ebp'):
        require(result['regs'][r] == regs[r])
    require(result['regs']['esi'] == obj)
    require(set(result['pages']) == set(PAGES) and
            all(len(b) == 4096 for b in result['pages'].values()))
    expected = {p:bytearray(b) for p,b in pages.items()}
    pointer = struct.unpack_from('<I', pages[OBJECT], obj-OBJECT+0xd0)[0]
    struct.pack_into('<4I', expected[STACK], sp-STACK-16,
                     obj+0x7c, obj+0x78, pointer, regs['esi'])
    require(all(result['pages'][p] == bytes(expected[p]) for p in PAGES))
    return target


def run(index, output):
    output = private_output(output)
    row = dict(schema='ts2-producer-input-prefix/1', success=False,
               rva=hex(RVA), image_sha256=IMAGE_SHA,
               harness_sha256=digest(Path(__file__)), invocation=[sys.executable,*sys.argv],
               lifted=False, host_native_executed=False, arm64_executed=False,
               android_executed=False, callee_executed=False, stub=False,
               limits=['Original x86 prefix only, stopped before CALL, no callee responses',
                       'Synthetic receiver/stack; not incoming caller ownership or lifetime proof',
                       'Partial independent ABI oracle; no complete GPR/flags/FP/PC oracle',
                       'No whole 20D0 return, 1460, alternate producer or production integration'])
    try:
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(RVA, SIZE)
        require(hashlib.sha256(code).hexdigest() == FUNCTION_SHA)
        _, nodes, _, flow = decode_flow(code, BASE+RVA, lambda i:i)
        body = dict(flow, instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
        row['index'] = crosscheck_index(json.loads(index.read_text()), body, RVA)
        row['index_sha256'] = digest(index)
        code_pages = {BASE+0x2000:bytearray(4096)}
        code_pages[BASE+0x2000][RVA%4096:RVA%4096+SIZE] = code
        cases, visited, counts = [], set(), {}
        rejected = {'wrong-target':0, 'wrong-input':0, 'wrong-stack':0}
        for n in range(64):
            regs, pages = state(n)
            result, seen = prefix_reference(nodes, BASE+RVA, code_pages, regs, pages)
            target = contract(regs, pages, result)
            import copy
            for fault in rejected:
                bad = copy.deepcopy(result)
                if fault == 'wrong-target': bad['target'] ^= 4
                elif fault == 'wrong-stack': bad['regs']['esp'] += 4
                else:
                    data = bytearray(bad['pages'][STACK])
                    data[regs['esp']-STACK-8] ^= 1
                    bad['pages'][STACK] = bytes(data)
                try: contract(regs, pages, bad)
                except ValueError: rejected[fault] += 1
                else: raise ValueError('Faulty boundary accepted')
            counts[hex(target-BASE)] = counts.get(hex(target-BASE), 0)+1
            visited |= seen
            cases.append(dict(case=n, input_regs=regs,
                              input_pages={hex(p):bytes(b).hex() for p,b in pages.items()},
                              result=dict(result, pages={hex(p):b.hex() for p,b in result['pages'].items()})))
        require(counts == {'0x109d0':16, '0x10b60':48})
        require(all(count == 64 for count in rejected.values()))
        require(digest(image) == IMAGE_SHA)
        private = output/'reference.json'
        private.write_text(json.dumps(cases)+'\n')
        row.update(success=True, original_x86_cases=64, matched_partial_contract=64,
                   target_counts=counts, rejected_boundary_mutations=rejected,
                   prefix_instructions_covered=len(visited),
                   reference_sha256=digest(private),
                   contract=dict(receiver_register='eax', selector_offset='0xd4',
                                 outgoing_arguments=['receiver+0x7c', 'receiver+0x78', '[receiver+0xd0]'],
                                 incoming_edi_preserved=True, callee_entry_edi_not_inferred=True))
    except Exception as exc:
        row['error_type'] = type(exc).__name__
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try: run(a.index, a.output)
    except Exception: p.exit(1, 'Prefix contract failed; see private receipt.\n')
    print('64 original-x86 prefixes satisfy partial ABI contract; no callee/native execution')


if __name__ == '__main__': main()
