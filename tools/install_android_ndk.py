#!/usr/bin/env python3
"""Install only the pinned official Linux NDK archive; no download or Android run."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import zipfile

REVISION = '27.2.12479018'
ROOT = 'android-ndk-r27c'
URL = 'https://dl.google.com/android/repository/android-ndk-r27c-linux.zip'
METADATA = 'https://dl.google.com/android/repository/repository2-3.xml'
SIZE = 663987688
# Size and SHA-1 published in Google's repository XML (2026-10-24).
SHA1 = '090e8083a715fdb1a3e402d0763c388abb03fb4e'
# Locally measured after size + published SHA-1 verification; not a Google SHA-256 claim.
SHA256 = '59c2f6dc96743b5daf5d1626684640b20a6bd2b1d85b13156b90333741bad5cc'


def verify(archive):
    if archive.stat().st_size != SIZE:
        raise ValueError('NDK archive size mismatch')
    for algorithm, expected in (('sha1', SHA1), ('sha256', SHA256)):
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream, algorithm).hexdigest() != expected:
                raise ValueError('NDK archive ' + algorithm + ' mismatch')


def members(archive):
    """Preflight paths and links before any archive member is written."""
    items = archive.infolist()
    names, links = set(), set()
    for item in items:
        path = PurePosixPath(item.filename)
        if (path.is_absolute() or not path.parts or path.parts[0] != ROOT or
                '..' in path.parts or '\\' in item.filename or path in names):
            raise ValueError('unsafe or duplicate NDK member')
        names.add(path)
        mode = item.external_attr >> 16
        if stat.S_ISLNK(mode):
            target = archive.read(item).decode('utf-8')
            # Lexical normalization permits official relative ../ links, not escapes.
            normalized = PurePosixPath(os.path.normpath(str(path.parent / target)))
            if (PurePosixPath(target).is_absolute() or '\\' in target or
                    not normalized.parts or normalized.parts[0] != ROOT):
                raise ValueError('unsafe NDK symlink')
            links.add(path)
        elif stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError('unsupported NDK member type')
    if any(parent in links for path in names for parent in path.parents):
        raise ValueError('NDK member nested under symlink')
    return items


def install(archive, sdk):
    verify(archive)  # Never extract even a partially verified archive.
    parent = sdk / 'ndk'
    destination = parent / REVISION
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('refusing to replace existing NDK')
    parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        items = members(z)
        needed = sum(i.file_size for i in items) + 256 * 1024 * 1024
        if shutil.disk_usage(parent).free < needed:
            raise OSError('insufficient free space for NDK staging')
        with tempfile.TemporaryDirectory(prefix='.ndk-stage-', dir=parent) as stage:
            stage = Path(stage)
            for item in items:
                path = stage / item.filename
                mode = item.external_attr >> 16
                path.parent.mkdir(parents=True, exist_ok=True)
                if item.is_dir():
                    path.mkdir(exist_ok=True)
                elif stat.S_ISLNK(mode):
                    path.symlink_to(z.read(item).decode('utf-8'))
                else:
                    with z.open(item) as source, path.open('xb') as output:
                        shutil.copyfileobj(source, output)
                    path.chmod(mode & 0o777)
            root = stage / ROOT
            props = (root / 'source.properties').read_text()
            if 'Pkg.Revision = ' + REVISION not in props:
                raise ValueError('extracted NDK revision mismatch')
            clang = root / 'toolchains/llvm/prebuilt/linux-x86_64/bin/clang'
            if not clang.is_file() or not os.access(clang, os.X_OK):
                raise ValueError('extracted NDK clang missing/not executable')
            receipt = dict(schema='ts2-ndk-install/1', revision=REVISION,
                url=URL, metadata_url=METADATA, size=SIZE, sha1=SHA1, sha256=SHA256,
                sha256_provenance='local replay pin after published size/SHA-1 verification',
                android_executed=False)
            (root / 'ts2-install-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
            # Same-filesystem rename publishes only the fully validated staged tree.
            root.rename(destination)
    return destination


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--sdk', type=Path, required=True)
    a = p.parse_args()
    print(install(a.archive, a.sdk))


if __name__ == '__main__':
    main()
