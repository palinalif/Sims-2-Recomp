#!/usr/bin/env python3
"""Bounded 1460 nonnull-provider prefix; stop BEFORE indirect service call.

Synthetic pointer values are data, never service implementations. No service,
allocator, callback, native translation or whole-caller verification is claimed.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_service_guard as g
c = g.c
STACK, OBJECT = c.DATA_PAGES[:2]
PAGES = (STACK, OBJECT)
# Deliberately unmapped markers, not resolved original targets or stubs.
MARKERS = (0x71300000, 0x81300000, 0xf1300000, 0xfffffff0)


def state(n):
    regs, all_pages = g.state(n)
    pages = {p:all_pages[p] for p in PAGES}
    target = MARKERS[n % len(MARKERS)]
    struct.pack_into('<I', pages[OBJECT], regs['esi']-OBJECT+0x74, target)
    return regs, pages


def oracle(regs, pages):
    """Independent complete boundary state; NOT a service-return oracle."""
    c.require(set(regs) == set(c.REGS) and set(pages) == set(PAGES))
    c.require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
    c.require(all(len(b) == 4096 for b in pages.values()))
    sp, obj = regs['esp'], regs['esi']
    c.require(sp in (STACK+0x800, STACK+0xc00))
    c.require(OBJECT <= obj <= OBJECT+4096-0xe4 and obj % 4 == 0)
    target = struct.unpack_from('<I', pages[OBJECT], obj-OBJECT+0x74)[0]
    context = struct.unpack_from('<I', pages[OBJECT], obj-OBJECT+0xe0)[0]
    argument = struct.unpack_from('<I', pages[STACK], sp-STACK+4)[0]
    c.require(target != 0)
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<I', after[STACK], sp-STACK-4, regs['ebp'])
    struct.pack_into('<I', after[STACK], sp-STACK-1056, regs['edi'])
    after[STACK][sp-STACK-1048:sp-STACK-24] = b'\xff'*1024
    struct.pack_into('<3I', after[STACK], sp-STACK-24, 0, 0, 0)
    struct.pack_into('<3I', after[STACK], sp-STACK-1068, context, argument, sp-1048)
    out = dict(regs, eax=context, ecx=argument, edx=target, edi=sp-24,
               ebp=sp-4, esp=sp-1068)
    return dict(site=c.BASE+0x14b7, target=target, regs=out,
                pages={p:bytes(b) for p,b in after.items()})


def contract(regs, pages, result):
    c.require(result == oracle(regs, pages))


def prefix_reference(nodes, code_pages, regs, pages, budget=512):
    """Fresh hook-free CPU; validate accesses; never execute the first CALL."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    from capstone import CS_AC_READ, CS_AC_WRITE, CS_GRP_CALL
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
    c.require(type(budget) is int and 0 < budget <= 1024)
    c.require(set(regs) == set(c.REGS) and set(pages) == set(PAGES))
    c.require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
    c.require(not set(code_pages) & set(PAGES))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, data in {**code_pages, **pages}.items():
        c.require(type(p) is int and p % 4096 == 0 and len(data) == 4096)
        u.mem_map(p, 4096); u.mem_write(p, bytes(data))
    ids = {r:getattr(x, 'UC_X86_REG_'+r.upper()) for r in c.REGS}
    for r in c.REGS: u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    pc, visited, stopped = c.BASE+g.RVA, set(), False

    def check(address, size, write=False):
        allowed = (STACK,) if write else PAGES
        c.require(type(size) is int and size in (1, 2, 4))
        c.require(0 <= address <= 0x100000000-size and
                  any(p <= address <= p+4096-size for p in allowed))

    def address(i, op):
        m = op.mem
        c.require(not m.segment)
        value = m.disp
        for reg, scale in ((m.base, 1), (m.index, m.scale)):
            if reg:
                name = i.reg_name(reg); c.require(name in ids)
                value += u.reg_read(ids[name])*scale
        return value & 0xffffffff

    for _ in range(budget):
        c.require(pc in nodes)
        i = nodes[pc]
        c.require(bytes(u.mem_read(pc, i.size)) == bytes(i.bytes))
        if i.group(CS_GRP_CALL):
            op = i.operands[0]
            if op.type == X86_OP_REG:
                name = i.reg_name(op.reg); c.require(name in ids)
                target = u.reg_read(ids[name])
            elif op.type == X86_OP_MEM:
                a = address(i, op); check(a, 4)
                target = int.from_bytes(u.mem_read(a, 4), 'little')
            else:
                c.require(op.type == X86_OP_IMM); target = op.imm & 0xffffffff
            stopped = True
            break
        if i.mnemonic == 'rep stosd':
            # Unicorn single-steps REP iterations. Check the complete remaining
            # forward range before each one, including the final zero-count step.
            count, dest = u.reg_read(ids['ecx']), u.reg_read(ids['edi'])
            c.require(count <= 256 and not u.reg_read(x.UC_X86_REG_EFLAGS) & 0x400)
            c.require(STACK <= dest <= STACK+4096-count*4)
            visited.add(pc)
            u.emu_start(pc, 0, count=1)
            pc = u.reg_read(x.UC_X86_REG_EIP)
            continue
        c.require(i.mnemonic in ('mov', 'lea', 'push', 'test', 'jne', 'je', 'jmp',
                                 'xor', 'sub', 'add', 'and', 'or', 'cmp'))
        for op in i.operands:
            if op.type != X86_OP_MEM or i.mnemonic == 'lea': continue
            c.require(op.access & (CS_AC_READ | CS_AC_WRITE))
            check(address(i, op), op.size, bool(op.access & CS_AC_WRITE))
        if i.mnemonic == 'push': check((u.reg_read(ids['esp'])-4) & 0xffffffff, 4, True)
        visited.add(pc)
        u.emu_start(pc, 0, count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
    c.require(stopped)
    for p, data in code_pages.items(): c.require(bytes(u.mem_read(p, 4096)) == bytes(data))
    return dict(site=pc, target=target, regs={r:u.reg_read(ids[r]) for r in c.REGS},
                pages={p:bytes(u.mem_read(p, 4096)) for p in PAGES}), visited


def run(index, output):
    output = c.private_output(output)
    row = dict(schema='ts2-service-input-prefix/1', success=False, rva=hex(g.RVA),
        image_sha256=c.IMAGE_SHA, harness_sha256=c.digest(Path(__file__)),
        guard_helper_sha256=c.digest(Path(g.__file__)),
        invocation=[sys.executable, *sys.argv], lifted=False, host_native_executed=False,
        arm64_executed=False, android_executed=False, callee_executed=False, stub=False,
        dependencies_newly_resolved=0,
        limits=['Original x86 prefix ONLY; stop before first call; no return-state verification',
                'Synthetic nonnull unmapped pointer markers; real service target NOT resolved',
                'No allocation/callback execution, ownership/lifetime or whole 1460/20D0/1AB665 proof',
                'No native, AArch64, Android or production integration evidence'])
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(g.RVA, g.SIZE)
        c.require(hashlib.sha256(code).hexdigest() == g.FUNCTION_SHA)
        _, nodes, _, flow = g.decode_flow(code, c.BASE+g.RVA, lambda i:i)
        body = dict(flow, instruction_rvas=[hex(a-c.BASE) for a in sorted(nodes)])
        row['index'] = g.crosscheck_index(json.loads(index.read_text()), body, g.RVA)
        row['index_sha256'] = c.digest(index)
        code_pages = {c.BASE+0x1000:bytearray(4096)}
        code_pages[c.BASE+0x1000][0x460:0x460+g.SIZE] = code
        cases, visited = [], set()
        rejected = dict.fromkeys(('wrong-target', 'wrong-argument-order', 'wrong-frame', 'wrong-fill'), 0)
        for n in range(64):
            regs, pages = state(n)
            result, seen = prefix_reference(nodes, code_pages, regs, pages)
            contract(regs, pages, result)
            for fault in rejected:
                bad = copy.deepcopy(result)
                if fault == 'wrong-target': bad['target'] ^= 4
                elif fault == 'wrong-frame': bad['regs']['esp'] += 4
                else:
                    data = bytearray(bad['pages'][STACK])
                    offset = regs['esp']-STACK
                    if fault == 'wrong-fill': data[offset-1048] ^= 1
                    else:
                        a, b = struct.unpack_from('<2I', data, offset-1068)
                        c.require(a != b)
                        struct.pack_into('<2I', data, offset-1068, b, a)
                    bad['pages'][STACK] = bytes(data)
                try: contract(regs, pages, bad)
                except ValueError: rejected[fault] += 1
                else: raise ValueError('Boundary mutation accepted')
            visited |= seen
            cases.append(dict(case=n, input_regs=regs,
                input_pages={hex(p):bytes(b).hex() for p,b in pages.items()},
                result=dict(result, pages={hex(p):b.hex() for p,b in result['pages'].items()})))
        c.require(all(v == 64 for v in rejected.values()))
        private = output/'reference.json'; private.write_text(json.dumps(cases)+'\n')
        c.require(c.digest(image) == c.IMAGE_SHA)
        row.update(success=True, original_x86_cases=64, matched_complete_boundary_oracle=64,
                   rejected_boundary_mutations=rejected, prefix_instructions_covered=len(visited),
                   contract=dict(receiver_register='esi', target_field='0x74', call_rva='0x14b7',
                       outgoing_arguments=['[receiver+0xe0]', 'incoming stack arg0', 'local 1024-byte buffer'],
                       buffer_initial_byte=255, pre_call_stack_delta=-1068,
                       stops_before_return_address_push=True),
                   reference_sha256=c.digest(private))
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
    except Exception: p.exit(1, 'Service prefix failed; inspect private receipt.\n')
    print('64 original-x86 prefixes match full boundary oracle; four controls reject; no service/native execution')


if __name__ == '__main__': main()
