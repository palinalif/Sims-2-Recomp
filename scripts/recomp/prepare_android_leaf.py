#!/usr/bin/env python3
"""F3 private-only JNI fixture staging and owner bundle preparation. No new lift."""
import argparse
import json
from pathlib import Path
import shutil
import struct
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compile_ndk_fixture import ROOT, PINS, audit, digest

HEADER_SHA = '1ab5b031e600cbfbc97649e3958b45014de99e812addb165728fdf2c90508cf9'
JNI_SYMBOL = b'Java_org_ts2native_diagnostic_MainActivity_nativeLeafDifferential'


def expected_bytes(rows):
    if not isinstance(rows, list) or len(rows) != 64:
        raise ValueError('expected 64 x86 states')
    data = bytearray()
    for n, row in enumerate(rows):
        if set(row) != {'case', 'regs', 'pages'} or type(row['case']) is not int or row['case'] != n:
            raise ValueError('invalid x86 case')
        regs = row['regs']
        if not isinstance(regs, list) or len(regs) != 8 or any(type(v) is not int or not 0 <= v <= 0xffffffff for v in regs):
            raise ValueError('invalid x86 registers')
        pages = bytes.fromhex(row['pages'])
        if len(pages) != 6 * 4096:
            raise ValueError('invalid x86 pages')
        data += struct.pack('<8I', *regs) + pages
    return bytes(data)


def array(name, data):
    return 'static const unsigned char '+name+'[]={\n'+',\n'.join(
        ','.join(str(b) for b in data[i:i+128]) for i in range(0, len(data), 128))+'\n};\n'


def source(transport, inputs, expected):
    marker = 'int main() {'
    if transport.count(marker) != 1:
        raise ValueError('unexpected pinned transport main')
    # Retain all generated instructions and exact-VA adapters; replace only CLI IO.
    prefix = transport.split(marker)[0]
    return prefix + '\n#include "leaf_differential.hpp"\n' + array('inputs', inputs) + array('expected', expected) + r'''
static void execute_leaf(uint32_t* regs,unsigned char* pages) {
    g_flag_k=g_flag_a=g_flag_b=g_flag_cf=0;g_fs_base=g_gs_base=0;
    cache_reset(pages);
    cache_invoke(0xA0009550u,regs,adapter_009550);
    cache_copy(pages);
#if TS2_PROBE_FAULT == 1
    regs[0]^=1;
#elif TS2_PROBE_FAULT == 2
    pages[6*4096-1]^=1;
#endif
}
extern "C" unsigned ts2_private_leaf_check() {
    auto r=ts2_probe::check(inputs,sizeof inputs,expected,sizeof expected,execute_leaf);
    return r.complete?r.matched:65;
}
'''


def new_private(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT/'work') or output.exists():
        raise ValueError('use a new ignored work/ directory')
    return output


def prepare(fixture, output):
    output = new_private(output)
    audit(fixture)
    header = ROOT/'work/interop-legacy-002/pcrecomp/runtime/recomp32/recomp_types.h'
    if digest(header) != HEADER_SHA:
        raise ValueError('runtime header pin mismatch')
    inputs = (fixture/'input.bin').read_bytes()
    expected = expected_bytes(json.loads((fixture/'reference.json').read_text()))
    if len(inputs) != len(expected):
        raise ValueError('input record size mismatch')
    text = source((fixture/'transport.cpp').read_text(), inputs, expected)
    body = (fixture/'switch/lifted.c').read_text()
    if text.count(body) != 1:
        raise ValueError('lift is not verbatim in JNI transport')
    output.mkdir(parents=True, mode=0o700)
    (output/'probe.cpp').write_text(text)
    shutil.copyfile(header, output/'recomp_types.h')
    (output/'cli.cpp').write_text('extern "C" unsigned ts2_private_leaf_check();\nint main(){return ts2_private_leaf_check()==64?0:1;}\n')
    receipt = dict(schema='ts2-private-jni-leaf/1', rva='0x9550', cases=64,
        fixture_pins=PINS, runtime_header_sha256=HEADER_SHA, probe_sha256=digest(output/'probe.cpp'),
        generated_body_verbatim=True, android_executed=False,
        compared=['eight GPRs', 'six complete pages'],
        limits='Saved bounded x86 reference. No flags/FP/PC/transient writes, game binding or gameplay.')
    (output/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    return receipt


def bundle(prepared, apk, output):
    output = new_private(output)
    receipt = json.loads((prepared/'receipt.json').read_text())
    if (receipt['fixture_pins'] != PINS or receipt['runtime_header_sha256'] != HEADER_SHA or
        digest(prepared/'probe.cpp') != receipt['probe_sha256'] or
        digest(prepared/'recomp_types.h') != HEADER_SHA):
        raise ValueError('private staging audit failed')
    # Build evidence only. Symbol inspection is not proof of execution/correctness.
    with zipfile.ZipFile(apk) as archive:
        library = archive.read('lib/arm64-v8a/libts2_android.so')
    if JNI_SYMBOL not in library or b'ts2_private_leaf_check' not in library:
        raise ValueError('APK lacks named JNI private probe')
    output.mkdir(parents=True, mode=0o700)
    shutil.copyfile(apk, output/'probe.apk')
    shutil.copyfile(ROOT/'scripts/recomp/run_android_leaf.py', output/'run_probe.py')
    shutil.copyfile(ROOT/'tools/android_probe.py', output/'android_probe.py')
    names = ('probe.apk', 'run_probe.py', 'android_probe.py')
    manifest = dict(schema='ts2-jni-device-bundle/1', cases=64, rva='0x9550',
        sha256={n: digest(output/n) for n in names}, staging=receipt,
        android_executed=False, phase1_complete=False)
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('prepare')
    p.add_argument('--fixture', type=Path, default=ROOT/'work/recomp-bench/leaf-d1')
    p.add_argument('--output', type=Path, required=True)
    p = sub.add_parser('bundle')
    p.add_argument('--prepared', type=Path, required=True)
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    if a.command == 'prepare':
        prepare(a.fixture, a.output)
    else:
        bundle(a.prepared, a.apk, a.output)
    print('Private staging/preflight only; android_executed: false')
