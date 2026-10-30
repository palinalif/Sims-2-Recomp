#!/usr/bin/env python3
"""Bounded original-x86 capacity path: stop BEFORE unresolved heap transfers.

No callee responses, lift, native execution or allocation implementation.
Only authored infrastructure is public; CPU states remain private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_handle_input as h
import execute_initialization_setter as c
from inspect_startup_dependency import crosscheck_index
from measure_startup import decode_flow

RVA = 0x1af0
SIZE = 362
UNITS = {**h.UNITS, RVA: (SIZE, 148,
    'b584ad0a50f9b9890656c218499554c94786fd16bde5ae5ba59fc337f3c270de')}
EXTERNAL = {c.BASE+0x8413b0, c.BASE+0x831a6f}


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    regs, pages = h.state(n)
    sp = regs['esp']-c.DATA_PAGES[0]
    obj = struct.unpack_from('<I', pages[c.DATA_PAGES[0]], sp+4)[0]
    off = obj-c.DATA_PAGES[1]+0x1d8
    _, cursor, start = struct.unpack_from('<III', pages[c.DATA_PAGES[1]], off)
    # Explicit default-allocator selector, not the unrelated random word from
    # the sufficient-capacity fixture (that path never read this field).
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off-4, 0)
    # Previously verified sufficient-capacity fixtures never reached 1AF0.
    # Alternating a full owned buffer and a genuinely empty descriptor does.
    struct.pack_into('<III', pages[c.DATA_PAGES[1]], off,
                     *((cursor, cursor, start) if n % 2 else (0, 0, 0)))
    return regs, pages


def trace(nodes, code_pages, regs, pages, budget=2048):
    """Fresh CPU, checked instruction fetch/data accesses, bounded first CALL.

    Known caller edges execute original bytes. An unknown transfer rejects;
    the two named external CALLs are observed BEFORE they execute, never stubbed.
    Explicit and implicit stack accesses are checked BEFORE execution. Unsupported
    string instructions reject; no Unicorn Python callbacks (host SIGBUS).
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    import unicorn.x86_const as x
    from capstone import CS_GRP_CALL, CS_AC_READ, CS_AC_WRITE
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    c.require(type(budget) is int and 0 < budget <= 4096)
    c.require(set(regs) == set(c.REGS) and set(pages) == set(c.PAGES))
    c.require(not set(code_pages) & set(c.PAGES))
    u = Uc(UC_ARCH_X86, UC_MODE_32)
    for p, data in {**code_pages, **pages}.items():
        c.require(p % 4096 == 0 and len(data) == 4096)
        u.mem_map(p, 4096); u.mem_write(p, bytes(data))
    ids = {r:getattr(x, 'UC_X86_REG_'+r.upper()) for r in c.REGS}
    for r in c.REGS:
        c.require(type(regs[r]) is int and 0 <= regs[r] <= 0xffffffff)
        u.reg_write(ids[r], regs[r])
    u.reg_write(x.UC_X86_REG_EFLAGS, 0x202)
    visited, calls, stopped = set(), [], []

    def memory(write, address, size):
        allowed = c.DATA_PAGES if write else c.PAGES
        c.require(type(size) is int and size > 0 and 0 <= address <= 0x100000000-size)
        c.require(any(p <= address and address+size <= p+4096 for p in allowed))

    pc = c.BASE+h.ROOT_RVA
    for _ in range(budget):
        c.require(pc in nodes)
        insn = nodes[pc]
        c.require(bytes(u.mem_read(pc, insn.size)) == bytes(insn.bytes))
        if insn.group(CS_GRP_CALL):
            c.require(len(insn.operands) == 1 and insn.operands[0].type == X86_OP_IMM)
            target = insn.operands[0].imm & 0xffffffff
            calls.append((pc, target))
            if target in EXTERNAL:
                stopped.append((pc, target)); break
            c.require(target in nodes)
        c.require(insn.mnemonic in ('mov','movzx','lea','push','pop','ret','call',
            'cmp','test','add','sub','inc','dec','and','or','xor','shl','shr','sar',
            'jmp','je','jne','ja','jae','jb','jbe','jg','jge','jl','jle','js','jns'))
        for op in insn.operands:
            if op.type != X86_OP_MEM or insn.mnemonic == 'lea': continue
            mem = op.mem
            c.require(not mem.segment and op.access & (CS_AC_READ | CS_AC_WRITE))
            address = mem.disp
            for reg,scale in ((mem.base,1),(mem.index,mem.scale)):
                if reg:
                    name = insn.reg_name(reg);c.require(name in ids)
                    address += u.reg_read(ids[name])*scale
            memory(bool(op.access & CS_AC_WRITE),address & 0xffffffff,op.size)
        if insn.mnemonic in ('push','pop','ret','call'):
            pushing = insn.mnemonic in ('push','call')
            sp = u.reg_read(ids['esp'])
            memory(pushing,(sp-4 if pushing else sp) & 0xffffffff,4)
        visited.add(pc)
        u.emu_start(pc, 0, count=1)
        pc = u.reg_read(x.UC_X86_REG_EIP)
    c.require(len(stopped) == 1)
    for p, data in code_pages.items(): c.require(bytes(u.mem_read(p,4096)) == bytes(data))
    return dict(site=stopped[0][0], target=stopped[0][1],
                regs={r:u.reg_read(ids[r]) for r in c.REGS},
                pages={p:bytes(u.mem_read(p,4096)) for p in c.PAGES}, calls=calls), visited


def boundary_contract(regs, pages, observed):
    """Measured null-selector corpus invariants, NOT a callee/native oracle.

    At the pending cdecl CALL, ESP points to arg0 (no return PC pushed yet).
    This checks the narrow observed request, not general allocator semantics.
    """
    c.require(observed['target'] == c.BASE+0x831a6f)
    c.require(observed['site'] == c.BASE+0x1c00)
    c.require([target for _, target in observed['calls']] ==
              [c.BASE+0x26b0, c.BASE+RVA, c.BASE+0x831a6f])
    sp = observed['regs']['esp']
    c.require(sp == regs['esp']-36)
    stack = c.DATA_PAGES[0]
    c.require(stack <= sp <= stack+4096-4)
    c.require(struct.unpack_from('<I',observed['pages'][stack],sp-stack)[0] == 1032)
    c.require(all(observed['pages'][p] == bytes(pages[p])
                  for p in c.PAGES if p != stack))


def run(index_dir, output, caller_index, buffer_index):
    output = c.private_output(output)
    row = dict(schema='ts2-capacity-service-prefix/1', success=False,
        image_sha256=c.IMAGE_SHA, harness_sha256=c.digest(Path(__file__)),
        invocation=[sys.executable,*sys.argv], functions={},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, external_callee_executed=False, stub=False,
        dependencies_newly_resolved=0, whole_function_verified=False,
        helper_sha256={p.name:c.digest(p) for p in
            (Path(h.__file__), Path(c.__file__),
             Path(__file__).with_name('inspect_startup_dependency.py'),
             Path(__file__).with_name('measure_startup.py'))},
        limits=['Original-x86 prefix only; stop BEFORE external heap CALL, never author a response',
                'Synthetic disjoint full/empty descriptors with null allocator selector; no ownership/lifetime/heap semantics proof',
                'No complete function return or host/AArch64/Android equivalence',
                'No whole openers/1AB665/E3/E4 or game startup'])
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        nodes, code_pages = {}, {}
        for rva, (size, count, pin) in UNITS.items():
            code = pe.get_data(rva,size)
            sha = hashlib.sha256(code).hexdigest()
            c.require(pin is None or sha == pin)
            _, ns, _, flow = decode_flow(code,c.BASE+rva,lambda i:i)
            c.require(len(ns) == count and flow['size_bytes'] == size)
            index = (caller_index if rva == h.ROOT_RVA else buffer_index if rva == 0x26b0
                     else index_dir/f'{rva:x}.json.env.json')
            checked = crosscheck_index(json.loads(index.read_text()),
                dict(flow,instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)]),rva)
            row['functions'][hex(rva)] = dict(function_sha256=sha,index=checked,index_sha256=c.digest(index))
            nodes.update(ns)
            p = c.BASE+rva//4096*4096
            code_pages.setdefault(p,bytearray(4096))[rva%4096:rva%4096+size] = code
        cases, visited, counts = [], set(), {}
        for n in range(64):
            regs,pages = state(n)
            result, seen = trace(nodes,code_pages,regs,pages)
            boundary_contract(regs,pages,result)
            visited |= seen
            key = hex(result['target']-c.BASE)
            counts[key] = counts.get(key,0)+1
            cases.append(dict(case=n,input_regs=regs,input_pages={hex(p):bytes(b).hex() for p,b in pages.items()},
                result=dict(result,pages={hex(p):b.hex() for p,b in result['pages'].items()})))
        private = output/'reference.json';private.write_text(json.dumps(cases)+'\n')
        c.require(c.digest(image) == c.IMAGE_SHA)
        row.update(success=True,original_x86_prefixes=64,target_counts=counts,
                   boundary_contract_matches=64,
                   pending_call=dict(site_rva='0x1c00',target_rva='0x831a6f',
                                     stack_delta=-36,request_bytes=1032,
                                     nonstack_pages_unchanged=True),
                   coverage=dict(visited=len(visited),total=len(nodes)),reference_sha256=c.digest(private))
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index-dir',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--caller-index',type=Path,required=True)
    p.add_argument('--buffer-index',type=Path,required=True)
    a = p.parse_args()
    try: run(a.index_dir,a.output,a.caller_index,a.buffer_index)
    except Exception: p.exit(1,'Capacity prefix rejected; inspect private receipt.\n')
    print('Original-x86 capacity prefixes recorded; no external callee/native/Android execution.')


if __name__ == '__main__':main()
