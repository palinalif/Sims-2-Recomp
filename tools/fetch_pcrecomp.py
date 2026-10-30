#!/usr/bin/env python3
"""Fetch the reviewed upstream archive; keep dependencies outside tracked source."""
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
def verify(source):
    spec=json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
    for name,digest in spec['files'].items():
        if hashlib.sha256((source/name).read_bytes()).hexdigest()!=digest:
            raise ValueError(f'Upstream source differs from reviewed revision: {name}')

def main():
    spec=json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']
    dest=ROOT/'work/deps';dest.mkdir(parents=True,exist_ok=True)
    archive=dest/'pcrecomp.tar.gz'
    if not archive.exists(): urllib.request.urlretrieve(spec['archive_url'],archive)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=spec['archive_sha256']:
        raise SystemExit('Archive hash mismatch. Remove local archive and investigate; do not disable verification.')
    target=dest/'pcrecomp'
    if not target.exists():
        target.mkdir()
        with tarfile.open(archive) as tar: tar.extractall(target,filter='data')
    children=[p for p in target.iterdir() if p.is_dir()]
    if len(children)!=1: raise SystemExit('Unexpected archive layout')
    source=children[0];verify(source);print(source)

if __name__=='__main__':main()
