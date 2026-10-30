#!/usr/bin/env python3
"""Compare native decoded DBPF payloads with a pinned, independent host decoder.

Never writes game data. Reference source stays under ignored work/ and is compiled
only for this host-side check, not linked into Android or the runtime.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 16 * 1024 * 1024


def compare(package_path, probe, reference):
    if package_path.stat().st_size > LIMIT:
        raise ValueError('Package exceeds 16 MiB verification budget')
    data = package_path.read_bytes()
    if len(data) < 96 or data[:4] != b'DBPF':
        raise ValueError('Invalid DBPF header')
    major, count, offset, index_size = struct.unpack_from('<4I', data, 32)
    minor = struct.unpack_from('<I', data, 60)[0]
    if major != 7 or minor not in (0, 1, 2):
        raise ValueError('Unsupported reference index')
    wide = minor == 2
    width = 24 if wide else 20
    if count > 100000 or index_size != count * width or offset < 96 or offset + index_size > len(data):
        raise ValueError('Invalid reference index bounds')
    entries = []
    compressed = {}
    for pos in range(offset, offset + index_size, width):
        fields = struct.unpack_from('<6I' if wide else '<5I', data, pos)
        key = fields[:2] + (fields[2] | ((fields[3] << 32) if wide else 0),)
        start, size = fields[-2:]
        if start + size > len(data):
            raise ValueError('Invalid reference payload bounds')
        entries.append((key, data[start:start + size]))
    for key, payload in entries:
        if key[0] != 0xe86b1eef:
            continue
        record_width = 20 if wide else 16
        if len(payload) % record_width:
            raise ValueError('Invalid reference compression directory')
        for pos in range(0, len(payload), record_width):
            fields = struct.unpack_from('<5I' if wide else '<4I', payload, pos)
            resource = fields[:2] + (fields[2] | ((fields[3] << 32) if wide else 0),)
            compressed[resource] = fields[-1]
    results = []
    total = 0
    for key, stored in entries:
        if key[0] == 0xe86b1eef:
            continue
        expected = compressed.get(key, len(stored))
        total += expected
        if expected > LIMIT or total > 64 * 1024 * 1024 or len(results) >= 256:
            raise ValueError('Reference comparison budget exceeded')
        if key in compressed:
            # Supplied TS2 samples use the explicit four-byte Maxis prefix.
            # The independent decoder consumes the underlying standard bitstream.
            if len(stored) < 9 or stored[4:6] != b'\x10\xfb':
                raise ValueError('Reference check currently requires prefixed TS2 QFS')
            src = ctypes.create_string_buffer(stored[4:])
            dst = ctypes.create_string_buffer(expected)
            read = ctypes.c_size_t()
            written = ctypes.c_size_t()
            declared = ctypes.c_uint32()
            status = reference(src, len(stored) - 4, ctypes.byref(read), dst, expected,
                               ctypes.byref(written), None, ctypes.byref(declared), 0)
            if status != 0 or written.value != expected or declared.value != expected or read.value != len(stored) - 4:
                raise ValueError('Independent reference rejected the resource')
            decoded = dst.raw
        else:
            decoded = stored
        native = subprocess.run([str(probe), str(package_path), *(hex(v) for v in key)],
                                check=True, capture_output=True, timeout=15).stdout
        if native != decoded:
            raise ValueError('Native/reference byte mismatch')
        results.append({'key': [hex(v) for v in key], 'compressed': key in compressed,
                        'decoded_bytes': len(native), 'match': True,
                        'sha256': hashlib.sha256(native).hexdigest()})
    return {'package': str(package_path), 'resources': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, action='append', required=True)
    parser.add_argument('--reference-source', type=Path, required=True)
    parser.add_argument('--probe', type=Path, default=ROOT / 'build/host/ts2_dbpf_probe')
    args = parser.parse_args()
    spec = json.loads((ROOT / 'config/dependencies.lock.json').read_text())['qfs_reference']
    source = args.reference_source.resolve()
    if not source.is_relative_to((ROOT / 'work').resolve()):
        parser.error('Keep the independent reference source inside ignored work/')
    if source.stat().st_size > 65536 or hashlib.sha256(source.read_bytes()).hexdigest() != spec['sha256']:
        parser.error('Independent reference source hash mismatch')
    with tempfile.TemporaryDirectory(prefix='qfs-reference-', dir=ROOT / 'work') as tmp:
        library = Path(tmp) / 'librefpack.so'
        subprocess.run(['cc', '-std=c99', '-O2', '-shared', '-fPIC', str(source), '-o', str(library)],
                       check=True, capture_output=True, timeout=60)
        reference = ctypes.CDLL(str(library)).refpack_decompress_safe
        pointer_size = ctypes.POINTER(ctypes.c_size_t)
        pointer_u32 = ctypes.POINTER(ctypes.c_uint32)
        reference.argtypes = [ctypes.c_void_p, ctypes.c_size_t, pointer_size, ctypes.c_void_p,
                             ctypes.c_size_t, pointer_size, pointer_u32, pointer_u32, ctypes.c_int]
        reference.restype = ctypes.c_int
        print(json.dumps({'reference_revision': spec['revision'],
                          'results': [compare(p, args.probe.resolve(), reference) for p in args.package]}, indent=2))


if __name__ == '__main__':
    main()
