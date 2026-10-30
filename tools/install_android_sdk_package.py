#!/usr/bin/env python3
"""Install three pinned official SDK archives offline; never accept licenses or run tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import zipfile

BASE = 'https://dl.google.com/android/repository/'
METADATA = BASE + 'repository2-3.xml'
# Published size/SHA-1, then local SHA-256 replay pins (not Google SHA-256 claims).
PACKAGES = {
    'platform': dict(archive='platform-35_r02.zip', size=64273788,
        sha1='0bb560a90a7a2cbd0dd8348224d518b638fe7949',
        sha256='0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0',
        root='android-35', destination='platforms/android-35', revision='2',
        required={'android.jar': False}),
    'build-tools': dict(archive='build-tools_r35_linux.zip', size=61958799,
        sha1='2cfaa0bbb2336e9ec18ed3ecea84fa2e2af607bc', sha256='bd3a4966912eb8b30ed0d00b0cda6b6543b949d5ffe00bea54c04c81e1561d88',
        root='android-15', destination='build-tools/35.0.0', revision='35.0.0',
        required={'aapt2': True, 'apksigner': True, 'zipalign': True}),
    'cmake': dict(archive='cmake-3.31.6-linux.zip', size=30771638,
        sha1='a54551dabd5daf8cc99f7f51769fd00ca759be0a', sha256='ce136bb4b02580b36e53d9ccfe5275069655e6ef7d46d6fe2fcf88cfdf8fb761',
        root='', destination='cmake/3.31.6', revision='3.31.6',
        required={'bin/cmake': True, 'bin/ninja': True}),
}


def verify(archive, pin):
    if archive.stat().st_size != pin['size']:
        raise ValueError('SDK archive size mismatch')
    for algorithm in ('sha1', 'sha256'):
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream, algorithm).hexdigest() != pin[algorithm]:
                raise ValueError('SDK archive ' + algorithm + ' mismatch')


def preflight(z, root):
    """These archives require no symlinks; reject all links/special files."""
    names, files = set(), set()
    items = z.infolist()
    for item in items:
        path = PurePosixPath(item.filename)
        mode = item.external_attr >> 16
        if (not path.parts or (root and path.parts[0] != root) or path.is_absolute() or
                '..' in path.parts or '\\' in item.filename or path in names or
                item.flag_bits & 1 or
                stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError('unsafe, duplicate or unsupported SDK member')
        names.add(path)
        if not item.is_dir():
            files.add(path)
    if any(parent in files for path in names for parent in path.parents):
        raise ValueError('SDK file/directory collision')
    return items


def install(package, archive, sdk):
    pin = PACKAGES[package]
    verify(archive, pin)  # Integrity failure must not write anything.
    destination = sdk / pin['destination']
    # Refuse redirected SDK paths, including dangling links, before staging.
    if any(p.is_symlink() for p in (destination, *destination.parents)):
        raise ValueError('symlinked SDK destination')
    if destination.exists():
        raise FileExistsError('refusing to replace existing SDK package')
    with zipfile.ZipFile(archive) as z:
        items = preflight(z, pin['root'])
        destination.parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(destination.parent).free < sum(i.file_size for i in items) + 64*1024*1024:
            raise OSError('insufficient space for SDK staging')
        with tempfile.TemporaryDirectory(prefix='.sdk-stage-', dir=destination.parent) as tmp:
            stage = Path(tmp)
            for item in items:
                path = stage / item.filename
                path.parent.mkdir(parents=True, exist_ok=True)
                if item.is_dir():
                    path.mkdir(exist_ok=True)
                else:
                    with z.open(item) as source, path.open('xb') as target:
                        shutil.copyfileobj(source, target)
                    path.chmod((item.external_attr >> 16) & 0o777)
            root = stage / pin['root']
            props = (root / 'source.properties').read_text()
            match = re.search(r'^Pkg.Revision\s*=\s*(\S+)\s*$', props, re.M)
            if not match or match[1] != pin['revision']:
                raise ValueError('SDK revision mismatch')
            for name, executable in pin['required'].items():
                path = root / name
                if not path.is_file() or (executable and not os.access(path, os.X_OK)):
                    raise ValueError('SDK required file missing/not executable: ' + name)
            receipt = dict(schema='ts2-sdk-package-install/1', package=package,
                url=BASE+pin['archive'], metadata_url=METADATA, pins=pin,
                sha256_provenance='local replay pin after published size/SHA-1 verification',
                licenses_accepted=False, android_executed=False)
            (root / 'ts2-install-receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
            root.rename(destination)
    return destination


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package', choices=PACKAGES, required=True)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--sdk', type=Path, required=True)
    a = p.parse_args()
    print(install(a.package, a.archive, a.sdk))


if __name__ == '__main__':
    main()
