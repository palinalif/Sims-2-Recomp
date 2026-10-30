"""Bounded diagnostic call metadata; no generated-instruction rewriting.

Target-only lifter calls cannot distinguish repeated targets in one caller.
Reject those rather than guessing an execution order. Outputs stay private.
"""
from measure_startup import BASE, BOUND, decode_flow
from measure_leaf import ROOT, IMAGE_SHA, digest


def call_sites(caller, nodes):
    from capstone import CS_GRP_CALL
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM
    rows, seen = [], set()
    for insn in sorted(nodes.values(), key=lambda i: i.address):
        if not insn.group(CS_GRP_CALL):
            continue
        op = insn.operands[0]
        slot = False
        if op.type == X86_OP_IMM:
            target = op.imm & 0xFFFFFFFF
        elif op.type == X86_OP_MEM and not op.mem.base and not op.mem.index:
            target, slot = op.mem.disp & 0xFFFFFFFF, True
        else:
            raise ValueError('Unresolved call operand')
        key = (slot, target)
        if key in seen:
            raise ValueError('Ambiguous repeated call target')
        seen.add(key)
        rows.append(dict(caller=caller, target=target, slot=slot,
                         return_va=insn.address + insn.size))
    return rows


def derive(*, entry=False):
    if type(entry) is not bool:
        raise ValueError('Invalid entry scope')
    import pefile
    image = ROOT/'work/interop-legacy-002/analysis-image.bin'
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image pin mismatch')
    pe = pefile.PE(data=image.read_bytes())
    if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14C:
        raise ValueError('Wrong PE mapping')
    rows = []
    for rva in (0x8258A9, 0x82585C):
        code = pe.get_data(rva, BOUND)
        if len(code) != BOUND:
            raise ValueError('Short code window')
        _, nodes, _, _ = decode_flow(code, BASE+rva, lambda i: i)
        rows.extend(call_sites(BASE+rva, nodes))
    if len(rows) != 5:
        raise ValueError('Unexpected call inventory')
    if entry:
        from reference_startup import ENTRY, entry_flow
        nodes = entry_flow(pe.get_data(ENTRY-BASE, 10))
        entry_rows = call_sites(ENTRY, {i.address: i for i in nodes})
        if len(entry_rows) != 1:
            raise ValueError('Unexpected entry call inventory')
        rows.extend(entry_rows)
    return rows


def seam(rows):
    if not rows:
        raise ValueError('Missing call metadata')
    entries = ',\n'.join('{%du,%du,%du,%du}' %
        (r['caller'], r['target'], r['return_va'], r['slot']) for r in rows)
    return '''/* Authored diagnostic CALL ABI, not upstream or lifted code. */
static const struct { uint32_t caller,target,ret,slot; } calls[]={
''' + entries + '''};
static uint32_t call_return(uint32_t caller,uint32_t target) {
    uint32_t ret=0, found=0;
    for(unsigned j=0;j<sizeof calls/sizeof calls[0];j++) {
        if(calls[j].caller!=caller) continue;
        uint32_t va=calls[j].slot?MEM32(calls[j].target):calls[j].target;
        if(va==target) { ret=calls[j].ret; found++; }
    }
    if(found!=1) reject("call-metadata");
    return ret;
}
#undef RECOMP_ICALL
#define RECOMP_ICALL(target_va) do { \\
    uint32_t call_va=(uint32_t)(target_va), caller_va=g_cur_func; \\
    uint32_t return_va=call_return(caller_va,call_va); \\
    recomp_func_t call_fn=recomp_lookup(call_va); \\
    if(!call_fn) reject("unresolved-target"); \\
    PUSH32(esp,return_va); \\
    RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); \\
    call_fn(); \\
    RECOMP_REGS_IN(); g_cur_func=caller_va; \\
} while(0)
'''
