#!/usr/bin/env python3
"""Read-only, bounded installation inventory. Never loads or executes a PE."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import pefile
from report_output import write_new

ROOT = Path(__file__).resolve().parents[1]
MAX_PE_BYTES = 256 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def tls_report(pe):
    tls=getattr(pe,'DIRECTORY_ENTRY_TLS',None)
    if tls is None:return None
    result={name:getattr(tls.struct,name) for name in ['StartAddressOfRawData','EndAddressOfRawData',
            'AddressOfIndex','AddressOfCallBacks','SizeOfZeroFill']}
    result.update(callbacks=[],callbacks_truncated=False,callback_errors=[])
    address=tls.struct.AddressOfCallBacks
    if not address:return result
    width=8 if pe.OPTIONAL_HEADER.Magic==0x20b else 4
    rva=address-pe.OPTIONAL_HEADER.ImageBase
    try:
        for i in range(64):
            offset=rva+i*width
            section=pe.get_section_by_rva(offset)
            if section is None or offset+width>section.VirtualAddress+section.SizeOfRawData:
                raise ValueError('TLS callback table is outside mapped raw section data')
            raw=pe.get_data(offset,width)
            if len(raw)!=width:raise ValueError('Truncated TLS callback table')
            value=int.from_bytes(raw,'little')
            if value==0:break
            result['callbacks'].append(value)
        else:result['callbacks_truncated']=True
    except (ValueError,pefile.PEFormatError) as e:result['callback_errors'].append(str(e))
    return result


def inspect_pe(path, catalog=None):
    path = Path(path)
    if path.stat().st_size > MAX_PE_BYTES:
        raise ValueError('PE exceeds 256 MiB inspection budget')
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except (pefile.PEFormatError, IndexError, struct.error) as error:
        raise ValueError(f'Invalid PE: {error}') from error
    try:
        digest = sha256(path)
        if catalog is None:
            catalog = json.loads((ROOT/'config/versions.json').read_text())
        matches = [v for v in catalog['versions'] if v['sha256'].lower() == digest]
        def imports(attribute):
            return [{'dll': item.dll.decode('ascii', errors='replace'), 'symbols': [
                symbol.name.decode('ascii', errors='replace') if symbol.name else f'ordinal:{symbol.ordinal}'
                for symbol in item.imports], 'entries':[
                    {'name':symbol.name.decode('ascii',errors='replace') if symbol.name else None,
                     'ordinal':symbol.ordinal,'hint':getattr(symbol,'hint',None),'iat_va':symbol.address}
                    for symbol in item.imports]} for item in getattr(pe, attribute, [])]
        version_strings = {}
        for group in getattr(pe, 'FileInfo', []):
            for item in group:
                for table in getattr(item, 'StringTable', []):
                    version_strings.update({k.decode(errors='replace'): v.decode(errors='replace') for k,v in table.entries.items()})
        return {
            'path': str(path), 'sha256': digest, 'size': path.stat().st_size,
            'machine': {0x14c:'x86',0x8664:'x86_64',0xaa64:'arm64'}.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
            'pe_magic': hex(pe.OPTIONAL_HEADER.Magic),
            'image_base': pe.OPTIONAL_HEADER.ImageBase, 'entry_rva': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'timestamp': pe.FILE_HEADER.TimeDateStamp, 'image_size': pe.OPTIONAL_HEADER.SizeOfImage,
            'large_address_aware': bool(pe.FILE_HEADER.Characteristics & 0x20),
            'subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'sections': [{'name':s.Name.rstrip(b'\0').decode(errors='replace'), 'rva':s.VirtualAddress,
                'virtual_size':s.Misc_VirtualSize,'raw_offset':s.PointerToRawData,'raw_size':s.SizeOfRawData,
                'executable':bool(s.Characteristics & 0x20000000), 'entropy':round(s.get_entropy(),3)} for s in pe.sections],
            'imports': imports('DIRECTORY_ENTRY_IMPORT'),
            'delay_imports': imports('DIRECTORY_ENTRY_DELAY_IMPORT'),
            'tls': tls_report(pe),
            'version_strings':version_strings,
            'status':'recognized' if matches else 'unknown', 'version_id':matches[0]['id'] if matches else None,
            'execution_supported':False,
            'warnings':pe.get_warnings(),
        }
    finally:
        pe.close()


def inspect_dbpf(path):
    path=Path(path)
    with path.open('rb') as f: header=f.read(96)
    if len(header)<96 or header[:4]!=b'DBPF': raise ValueError('Invalid or truncated DBPF header')
    major,minor=struct.unpack_from('<II',header,4)
    if major!=1: raise ValueError(f'Unsupported DBPF major {major}; this inspector covers TS2 DBPF 1.x')
    index_major,count,offset,size=struct.unpack_from('<IIII',header,32)
    index_minor=struct.unpack_from('<I',header,60)[0]
    if offset+size>path.stat().st_size or (count and (offset<96 or not size)):
        raise ValueError('DBPF index outside file')
    if index_major==7 and index_minor in (0,1,2):
        width=24 if index_minor>=2 else 20
        if count*width!=size: raise ValueError('DBPF index count/size mismatch')
    return {'path':str(path),'major':major,'minor':minor,'entries':count,
            'index_major':index_major,'index_minor':index_minor,'index_offset':offset,'index_size':size,
            'resources_loaded':False}


def discover(root, max_entries=50000):
    root=Path(root).resolve(strict=True)
    if not root.is_dir(): raise ValueError('Installation root must be a directory')
    pending=[root]; executables=[]; libraries=[]; packages=[]; errors=[]; count=0; truncated=False
    while pending and not truncated:
        folder=pending.pop()
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    count+=1
                    if count>max_entries: truncated=True; break
                    if entry.is_symlink(): continue
                    if entry.is_dir(follow_symlinks=False): pending.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        name=entry.name.casefold()
                        if name.endswith('.exe') and name.startswith('sims2'): executables.append(str(Path(entry.path).relative_to(root)))
                        elif name.endswith('.dll'): libraries.append(str(Path(entry.path).relative_to(root)))
                        elif name.endswith('.package'): packages.append(str(Path(entry.path).relative_to(root)))
        except OSError as e: errors.append({'path':str(folder.relative_to(root)),'error':str(e)})
    return {'root':str(root),'executables':sorted(executables),'libraries':sorted(libraries),'packages':sorted(packages),
            'entries_scanned':count,'truncated':truncated,'errors':errors}


def analyze_tree(root,include_dlls=False,max_binaries=128,max_binary_bytes=1024**3):
    if max_binaries<=0 or max_binary_bytes<=0:raise ValueError('Binary analysis budgets must be positive')
    root=Path(root);inventory=discover(root);result={'discovery':inventory,'binaries':[],
            'analysis_truncated':inventory['truncated'],'binary_bytes_inspected':0}
    candidates=inventory['executables']+(inventory['libraries'] if include_dlls else [])
    for name in candidates:
        if len(result['binaries'])>=max_binaries:result['analysis_truncated']=True;break
        try:
            size=(root/name).stat().st_size
            if result['binary_bytes_inspected']+size>max_binary_bytes:
                result['analysis_truncated']=True;break
            result['binary_bytes_inspected']+=size
            result['binaries'].append(inspect_pe(root/name))
        except (ValueError,OSError) as e:result['binaries'].append({'path':name,'error':str(e)})
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install', type=Path, default=os.environ.get('TS2_INSTALL'))
    parser.add_argument('--exe', type=Path)
    parser.add_argument('--package', type=Path)
    parser.add_argument('--include-dlls',action='store_true',help='Inspect discovered DLL imports as well as Sims2 executables')
    parser.add_argument('--max-binaries',type=int,default=128)
    parser.add_argument('--output', type=Path, help='Write local report under ignored work/ directory')
    args=parser.parse_args()
    try:
        result={'schema':1,'execution_supported':False}
        if args.install:
            result.update(analyze_tree(args.install,include_dlls=args.include_dlls,max_binaries=args.max_binaries))
        if args.exe: result['binary']=inspect_pe(args.exe)
        if args.package: result['package']=inspect_dbpf(args.package)
        if not any([args.install,args.exe,args.package]): parser.error('Supply --install, TS2_INSTALL, --exe, or --package')
        report=json.dumps(result,indent=2)
        if args.output:
            write_new(args.output,report,install=args.install)
        else: print(report)
        return 0
    except (ValueError,OSError) as e: parser.exit(2,f'Inspection failed: {e}\n')


if __name__=='__main__': raise SystemExit(main())
