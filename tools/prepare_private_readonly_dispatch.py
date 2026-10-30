#!/usr/bin/env python3
"""Adapt only the existing hash-pinned private read-only group (no PE/lift/recovery).

Generated source and native stdout MUST stay in ignored work/. Original lifted
bodies and the 96 saved input cases are unchanged. Legacy globals remain fixture
infrastructure, not a thread-safe or reentrant runtime ABI.
"""
import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_SHA = 'c7502ad58ae1a887b06673a5ca44a1ce15e741e2746dcc8560da9174b8e60591'
REFERENCE_SHA = '5fabc47aa506575ffec923212d120f2fbfa3fa897e5446f07b1137afc5e6bb34'
REGS = ('eax','ecx','edx','ebx','esp','ebp','esi','edi')


def prepare(source, output):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work').resolve()):
        raise ValueError('Output must be under private work/')
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Private source pin mismatch')
    text = data.decode('utf-8')
    before = '#define MEM32(addr) ts2_checked_read32(&query_view, (uint32_t)(addr))'
    if text.count(before) != 1 or text.count('ts2_dispatch(') != 96:
        raise ValueError('Unexpected fixture structure')
    text = text.replace(before, '#define MEM32(addr) ts2_bridge_read32((uint32_t)(addr))')
    text = text.replace('#include "guest_query_guard.h"',
                        '#include "guest_query_guard.h"\n#include "readonly_dispatch_bridge.h"')
    text = text.replace('ts2_dispatch(', 'runtime_dispatch(')
    wrapper = ''
    for rva in (0x1240,0x1250,0x1270):
        wrapper += f'static void bridge_{rva:x}(uint32_t *s) {{\n'
        wrapper += ''.join(f'    g_{reg} = s[{i}];\n' for i,reg in enumerate(REGS))
        wrapper += f'    object_query_{rva:x}();\n'
        wrapper += ''.join(f'    s[{i}] = g_{reg};\n' for i,reg in enumerate(REGS))
        wrapper += '    s[8] = recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);\n}\n'
    wrapper += '''static void runtime_dispatch(uint32_t va, const Ts2GuestEntry *unused, size_t count) {
    (void)unused;
    if (count != 3) exit(104);
    Ts2ReadSpan spans[2];
    for (size_t i=0; i<2; ++i) {
        spans[i].address=query_spans[i].guest_start;
        spans[i].size=query_spans[i].byte_count;
        spans[i].bytes=query_spans[i].host;
    }
    const Ts2ReadEntry entries[] = {
        {0xA0001240u,bridge_1240}, {0xA0001250u,bridge_1250}, {0xA0001270u,bridge_1270}
    };
'''
    wrapper += '    uint32_t s[9] = {' + ','.join('g_'+r for r in REGS) + ',recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1)};\n'
    wrapper += '    if (ts2_read_dispatch(va,s,spans,2,entries,3) != TS2_READ_OK) exit(105);\n'
    wrapper += ''.join(f'    g_{reg} = s[{i}];\n' for i,reg in enumerate(REGS))
    wrapper += '    out_eflags = s[8];\n}\n\n'
    marker = 'static void case_0(void) {'
    if text.count(marker) != 1:
        raise ValueError('Unexpected fixture marker')
    text = text.replace(marker, wrapper + marker)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with output.open('x', encoding='utf-8') as f:
        output.chmod(0o600)
        f.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT/'work/interop-legacy-002/group.c')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError):
        parser.exit(1, 'Private fixture unavailable, pin/structure mismatch, or unsafe/existing output\n')
    print('Prepared pinned private read-only dispatch fixture (96 cases); no code emitted to stdout')


if __name__ == '__main__':
    main()
