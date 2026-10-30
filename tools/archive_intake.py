#!/usr/bin/env python3
"""Preview a user-provided ZIP; optionally stage only EXE/DLL analysis inputs.

Never runs files or modifies the source archive. Full asset extraction is not
implemented. A preview reads central-directory metadata, not payload CRCs.
"""
import argparse
from dataclasses import dataclass,field
import hashlib
import json
from pathlib import Path
import shutil
import stat
import unicodedata
import zipfile
from report_output import ROOT, write_new

MANIFEST='intake-manifest.json'


@dataclass(frozen=True)
class Limits:
    max_members:int=200000
    max_total_bytes:int=64*1024**3
    max_binary_bytes:int=256*1024**2
    max_analysis_bytes:int=1024**3
    reserve_free_bytes:int=64*1024**2
    max_path_bytes:int=2048
    max_path_depth:int=64
    max_total_path_bytes:int=32*1024**2
    max_path_nodes:int=300000


@dataclass
class _PathNode:
    spelling:str
    directory:bool
    explicit:bool
    children:dict=field(default_factory=dict)


def _name(info,limits):
    name=info.orig_filename.replace('\\','/')
    if not name or name.startswith('/') or any(ord(c)<32 or ord(c)==127 for c in name):
        raise ValueError('Empty, absolute, or control-character path')
    if name.endswith('/'):name=name[:-1]
    if len(name.encode('utf-8'))>limits.max_path_bytes or name.count('/')+1>limits.max_path_depth:
        raise ValueError('ZIP path length/depth exceeds limit')
    parts=name.split('/')
    reserved={'CON','PRN','AUX','NUL'}|{f'{prefix}{i}' for prefix in ('COM','LPT') for i in range(1,10)}
    for part in parts:
        if len(part.encode('utf-8'))>255:raise ValueError('Path component exceeds native filesystem limit')
        if part in ('','.','..') or part.endswith((' ','.')) or any(c in part for c in ':<>"|?*'):
            raise ValueError('Unsafe or ambiguous Windows path')
        if part.split('.')[0].upper() in reserved:raise ValueError('Reserved Windows device name')
    mode=stat.S_IFMT(info.external_attr>>16)
    if mode not in (0,stat.S_IFREG,stat.S_IFDIR):raise ValueError('Symlink or special file')
    if mode==stat.S_IFDIR and not info.is_dir():raise ValueError('Directory metadata/name mismatch')
    return name


def _inventory(archive,path,limits):
    if any(getattr(limits,field)<=0 for field in limits.__dataclass_fields__):raise ValueError('Intake limits must be positive')
    infos=archive.infolist();members=[];errors=[];tree={}
    total=analysis_bytes=packages=path_bytes=path_nodes=0;analysis_files=[]
    def error(message):
        if len(errors)<256:errors.append(message)
    if len(infos)>limits.max_members:error('ZIP member count exceeds limit')
    for index,info in enumerate(infos[:limits.max_members]):
        try:name=_name(info,limits)
        except ValueError as e:error(f'{info.orig_filename!r}: {e}');continue
        path_bytes+=len(name.encode('utf-8'))
        if path_bytes>limits.max_total_path_bytes:error('ZIP path byte budget exceeded');break
        key=unicodedata.normalize('NFC',name).casefold()
        parts=name.split('/');children=tree;node_budget_exceeded=False
        for position,part in enumerate(parts):
            part_key=unicodedata.normalize('NFC',part).casefold();last=position==len(parts)-1
            directory=not last or info.is_dir();node=children.get(part_key)
            if node is None:
                if path_nodes>=limits.max_path_nodes:
                    error('ZIP path index node budget exceeded');node_budget_exceeded=True;break
                node=_PathNode(part,directory,last);children[part_key]=node;path_nodes+=1
            else:
                if node.spelling!=part:error(f'Case/Unicode path component alias: {name}');break
                if node.directory!=directory:error(f'File/directory path collision: {name}');break
                if last:
                    if node.explicit:error(f'Duplicate path: {name}')
                    node.explicit=True
            children=node.children
        if node_budget_exceeded:break
        if info.flag_bits & 1:error(f'Encrypted member cannot be staged: {name}')
        if info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED,zipfile.ZIP_BZIP2,zipfile.ZIP_LZMA):
            error(f'Unsupported ZIP compression: {name}')
        selected=not info.is_dir() and Path(name).suffix.casefold() in ('.exe','.dll')
        if selected:
            analysis_files.append(name);analysis_bytes+=info.file_size
            if info.file_size>limits.max_binary_bytes:error(f'Binary exceeds inspection size limit: {name}')
            if key==MANIFEST or key.startswith(MANIFEST+'/'):error(f'Path conflicts with intake manifest: {name}')
        if not info.is_dir():total+=info.file_size
        if name.casefold().endswith('.package') and not info.is_dir():packages+=1
        members.append({'index':index,'path':name,'directory':info.is_dir(),'bytes':info.file_size,
                        'compressed_bytes':info.compress_size,'crc32':f'{info.CRC:08x}','analysis_binary':selected})
    if total>limits.max_total_bytes:error('ZIP uncompressed size exceeds limit')
    if analysis_bytes>limits.max_analysis_bytes:error('Selected binaries exceed aggregate inspection budget')
    return {'schema':1,'archive':str(Path(path).resolve()),'archive_bytes':Path(path).stat().st_size,
            'member_count':len(infos),'uncompressed_bytes':total,'binary_count':len(analysis_files),
            'analysis_bytes':analysis_bytes,'analysis_files':sorted(analysis_files),'package_count':packages,
            'safe_to_extract_binaries':not errors,'crc_verified':False,'errors':errors,'members':members,
            'path_bytes_indexed':path_bytes,'path_nodes_indexed':path_nodes,
            'execution_supported':False}


def inspect_archive(path,limits=Limits()):
    with zipfile.ZipFile(path) as archive:return _inventory(archive,path,limits)


def extract_binaries(path,destination,limits=Limits()):
    destination=Path(destination).resolve()
    if not any(destination.is_relative_to(ROOT/root) for root in ('game-files','work')):
        raise ValueError('Destination must be a new directory inside ignored game-files/ or work/')
    if destination.exists():raise FileExistsError('Destination already exists; choose a new directory')
    with zipfile.ZipFile(path) as archive:
        inventory=_inventory(archive,path,limits)
        if not inventory['safe_to_extract_binaries']:raise ValueError('; '.join(inventory['errors'][:5]))
        if not inventory['binary_count']:raise ValueError('ZIP has no EXE/DLL files to stage')
        ancestor=destination.parent
        while not ancestor.exists():ancestor=ancestor.parent
        if shutil.disk_usage(ancestor).free<inventory['analysis_bytes']+limits.reserve_free_bytes:
            raise ValueError('Insufficient free space for selected binaries and reserve')
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.mkdir(mode=0o700) # exclusive: no original tree or existing staging area is reused
        report={'schema':1,'archive':inventory['archive'],'archive_bytes':inventory['archive_bytes'],
                'status':'incomplete','files':[],'execution_supported':False}
        # Keep a failed/partial directory for diagnosis; never silently call it complete.
        with (destination/MANIFEST).open('x+',encoding='utf-8') as manifest:
            def save():
                manifest.seek(0);json.dump(report,manifest,indent=2);manifest.write('\n');manifest.truncate();manifest.flush()
            save();actual_total=0
            try:
                for member in inventory['members']:
                    if not member['analysis_binary']:continue
                    target=destination/member['path'];target.parent.mkdir(parents=True,exist_ok=True)
                    digest=hashlib.sha256();count=0
                    with archive.open(archive.infolist()[member['index']]) as src,target.open('xb') as out:
                        while chunk:=src.read(1024*1024):
                            count+=len(chunk);actual_total+=len(chunk)
                            if count>limits.max_binary_bytes or actual_total>limits.max_analysis_bytes:
                                raise ValueError('Actual decompressed bytes exceed inspection budget')
                            digest.update(chunk);out.write(chunk)
                    if count!=member['bytes']:raise ValueError('ZIP declared/actual binary size mismatch')
                    target.chmod(0o600) # analysis input, never an executable launch artifact
                    report['files'].append({'path':member['path'],'bytes':count,'sha256':digest.hexdigest(),'crc_verified':True})
                report['status']='complete';save()
            except Exception as e:
                report['status']='failed';report['error']=str(e);save();raise
        return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive',type=Path)
    parser.add_argument('--report',type=Path,help='New JSON preview report under ignored work/')
    parser.add_argument('--extract-binaries',type=Path,metavar='NEW_DIRECTORY',help='Opt in to EXE/DLL staging; full assets stay in ZIP')
    args=parser.parse_args()
    try:
        preview=inspect_archive(args.archive)
        if args.report:write_new(args.report,json.dumps(preview,indent=2))
        if args.extract_binaries:
            result=extract_binaries(args.archive,args.extract_binaries)
            print(json.dumps({'status':result['status'],'files_staged':len(result['files']),
                              'manifest':str(args.extract_binaries/MANIFEST),'execution_supported':False},indent=2))
        else:
            print(json.dumps({k:v for k,v in preview.items() if k!='members'},indent=2))
        return 0 if preview['safe_to_extract_binaries'] else 2
    except (ValueError,OSError,zipfile.BadZipFile,NotImplementedError,RuntimeError) as e:
        parser.exit(2,f'Archive intake failed: {e}\n')


if __name__=='__main__':raise SystemExit(main())
