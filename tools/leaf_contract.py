"""Strict memory contract for the first executable leaf probe.

Only fixed accesses into three caller-seeded 32-bit stack slots are accepted.
This deliberately excludes most real functions; do not relax it to advance startup.
"""
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM, X86_REG_ESP, X86_REG_SP, X86_REG_EIP, X86_REG_IP

def validate(code):
    if not 1<=len(code)<=4096:raise ValueError('Leaf exceeds 4096-byte execution budget')
    decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
    instructions=list(decoder.disasm(code,0x400000))
    if not instructions or sum(i.size for i in instructions)!=len(code) or instructions[-1].bytes!=b'\xc3':
        raise ValueError('Leaf must fully decode and end in plain ret')
    allowed={'mov','movzx','movsx','lea','add','sub','and','or','xor','not','neg','inc','dec','shl','shr','sar','imul','nop'}
    for insn in instructions[:-1]:
        if insn.mnemonic not in allowed:raise ValueError('Instruction outside leaf execution contract')
        _,writes=insn.regs_access()
        if any(reg in (X86_REG_ESP,X86_REG_SP,X86_REG_EIP,X86_REG_IP) for reg in writes):
            raise ValueError('Leaf may not modify stack/instruction pointer')
        for operand in insn.operands:
            if operand.type!=X86_OP_MEM:continue
            mem=operand.mem
            if mem.base!=X86_REG_ESP or mem.index or mem.segment or operand.size not in (1,2,4) or not 4<=mem.disp or mem.disp+operand.size>16:
                raise ValueError('Memory operand outside fixed caller stack slots')
    return instructions
