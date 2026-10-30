#!/usr/bin/env python3
"""Extract a manually selected, hash-pinned x86 leaf for local upstream lift tests."""
import argparse
import json
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from analyze_install import ROOT, sha256, MAX_PE_BYTES
from report_output import write_new


def extract(path,digest,rva,size,catalog=None):
    path=Path(path)
    if path.stat().st_size>MAX_PE_BYTES or sha256(path)!=digest.lower(): raise ValueError('Executable hash mismatch or over budget')
    if catalog is None:
        catalog=json.loads((ROOT/'config/versions.json').read_text())
    for record in catalog.get('versions',[]):
        if record.get('sha256')==digest.lower() and record.get('recompilation_ready') is False:
            raise ValueError(record.get('blocker','Known build is not ready for recompilation'))
    if size<=0 or size>4096: raise ValueError('Leaf size must be 1..4096 bytes')
    pe=pefile.PE(str(path),fast_load=True)
    try:
        if pe.FILE_HEADER.Machine!=0x14c or pe.OPTIONAL_HEADER.Magic!=0x10b: raise ValueError('Requires PE32 x86')
        section=pe.get_section_by_rva(rva)
        if section is None or not section.Characteristics & 0x20000000: raise ValueError('RVA is not executable')
        relative=rva-section.VirtualAddress
        if relative<0 or relative+size>min(section.Misc_VirtualSize,section.SizeOfRawData): raise ValueError('Probe crosses raw section boundary')
        code=pe.get_data(rva,size)
        decoder=Cs(CS_ARCH_X86,CS_MODE_32);decoder.detail=True
        instructions=list(decoder.disasm(code,pe.OPTIONAL_HEADER.ImageBase+rva))
        if sum(i.size for i in instructions)!=size: raise ValueError('Undecodable/incomplete instruction')
        # First experiment is deliberately straight-line, import-free and caller-seeded.
        allowed={'mov','movzx','movsx','lea','add','sub','and','or','xor','not','neg','inc','dec','shl','shr','sar','imul','push','pop','ret','nop'}
        if not instructions or instructions[-1].mnemonic!='ret': raise ValueError('Probe must terminate in ret')
        if any(i.mnemonic not in allowed or (i.mnemonic=='ret' and n!=len(instructions)-1) for n,i in enumerate(instructions)):
            raise ValueError('Only a reviewed straight-line leaf is allowed in this experiment')
        if any('fs:' in i.op_str or 'gs:' in i.op_str for i in instructions): raise ValueError('TLS/segment access needs a different experiment')
        return code
    finally: pe.close()


def verify_record(path,record):
    code=extract(path,record['sha256'],record['rva'],record['size'])
    if code.hex()!=record['code_hex'].lower():raise ValueError('Probe bytes do not match original input')
    return code


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--exe',required=True,type=Path);p.add_argument('--sha256',required=True)
    p.add_argument('--rva',required=True,type=lambda v:int(v,0));p.add_argument('--size',required=True,type=lambda v:int(v,0))
    p.add_argument('--out',required=True,type=Path);a=p.parse_args()
    if not a.out.resolve().is_relative_to((ROOT/'work').resolve()):p.error('--out must be inside ignored work/')
    try: code=extract(a.exe,a.sha256,a.rva,a.size)
    except (ValueError,OSError,pefile.PEFormatError) as e:p.exit(2,f'Probe rejected: {e}\n')
    try:
        write_new(a.out,json.dumps({'sha256':a.sha256.lower(),'rva':a.rva,'size':a.size,'code_hex':code.hex(),
            'warning':'Local proprietary artifact. Review all memory operands and seed reference state before lifting.'},indent=2))
    except (OSError,ValueError) as e:p.exit(2,f'Output rejected: {e}\n')


if __name__=='__main__':main()
