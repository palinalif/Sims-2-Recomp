#!/usr/bin/env python3
"""Adapt ONLY the previously validated private cache fixture; no PE/lift/recovery.

Outputs stay in ignored work/. Explicit store sites and stack/call macros are
adapted, not instruction semantics or saved cases. Legacy lazy flags/globals
remain fixture-specific, single-threaded infrastructure, NOT a general ABI.
"""
import argparse
import hashlib
from pathlib import Path
import re
from prepare_private_readonly_dispatch import ROOT, REGS

SOURCE_SHA = '8f2528e6fabe017d13c25fac6e01c44356125b6eab85b71cd01f9b62909eec56'
REFERENCE_SHA = '0666f5c3145298ceade249b10f4c1bd95f7498c52597379f8090656bf03a7865'


def state_out():
    return 'uint32_t s[9] = {' + ','.join('g_'+r for r in REGS) + ',recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1)};\n'


def state_in():
    return ''.join(f'    g_{reg} = s[{i}];\n' for i, reg in enumerate(REGS))


def scaffold():
    text = '''
#undef MEM32
#define MEM32(addr) ts2_scoped_read32((uint32_t)(addr))
#undef PUSH32
#define PUSH32(sp,val) do { uint32_t pv_=(uint32_t)(val); (sp)-=4; ts2_scoped_write32((sp),pv_); } while(0)
static void runtime_nested(uint32_t va);
#define bridge_va_sub_A0001250 0xA0001250u
#define bridge_va_sub_A0001270 0xA0001270u
#undef RECOMP_CALL
#define RECOMP_CALL(func) do { \\
    uint32_t caller_=g_cur_func; PUSH32(esp,RECOMP_RETADDR); \\
    RECOMP_FLAGS_OUT(); RECOMP_REGS_OUT(); \\
    runtime_nested(bridge_va_##func); RECOMP_REGS_IN(); g_cur_func=caller_; \\
} while(0)
'''
    return text


def wrappers():
    text = ''
    for name in ('sub_A0001250', 'sub_A0001270', 'cache_1ab770', 'cache_1ab78c'):
        text += f'static void bridge_{name}(uint32_t *s) {{\n' + state_in()
        text += f'    {name}();\n'
        text += ''.join(f'    s[{i}] = g_{reg};\n' for i, reg in enumerate(REGS))
        text += '    s[8]=recomp_eflags(g_flag_k,g_flag_a,g_flag_b,g_flag_cf,1);\n}\n'
    text += 'static void runtime_nested(uint32_t va) {\n    ' + state_out()
    text += '    if (ts2_scoped_call(va,s)!=TS2_SCOPED_OK) exit(105);\n' + state_in() + '}\n'
    text += '''static uint32_t host_word(uint32_t a) {
    uint32_t v; memcpy(&v,win+(a-WIN_BASE),4); return v;
}
static void runtime_dispatch(uint32_t va) {
    const uint32_t cache = 0xA0010000u + (va==0xA01AB770u ? 0x90u : 0x8Cu);
    const uint32_t handle = host_word(0xA0010034u);
    const uint32_t sp = g_esp;
    Ts2ScopedWrite expected[4] = {
        {sp-4,host_word(sp-4),g_esi},
        {sp-8,host_word(sp-8),handle},
        {sp-12,host_word(sp-12),va==0xA01AB770u ? 0xA01AB785u : 0xA01AB7A1u},
        {cache,host_word(cache),0}
    };
    Ts2ScopedSpan spans[5]; size_t n=0;
    spans[n++] = (Ts2ScopedSpan){0xA0010000u,cache-0xA0010000u,win+0x10000,NULL};
    spans[n++] = (Ts2ScopedSpan){cache,4,win+(cache-WIN_BASE),win+(cache-WIN_BASE)};
    if (cache+4<0xA0010094u)
        spans[n++] = (Ts2ScopedSpan){cache+4,0xA0010094u-cache-4,win+(cache+4-WIN_BASE),NULL};
    spans[n++] = (Ts2ScopedSpan){0xA0011000u,0x210,win+0x11000,NULL};
    spans[n++] = (Ts2ScopedSpan){0xA001FFF0u,0x14,win+0x1FFF0,win+0x1FFF0};
    const Ts2ScopedEntry entries[] = {
        {0xA0001250u,bridge_sub_A0001250}, {0xA0001270u,bridge_sub_A0001270},
        {0xA01AB770u,bridge_cache_1ab770}, {0xA01AB78Cu,bridge_cache_1ab78c}
    };
    Ts2ScopedReport report;
'''
    text += '    ' + state_out()
    text += '''    if (ts2_scoped_dispatch(va,s,spans,n,entries,4,&report)!=TS2_SCOPED_OK) exit(106);
    expected[3].after=s[0];
    if (report.calls!=(handle ? 2u : 1u) || report.writes!=(handle ? 4u : 1u)) exit(107);
    for (uint32_t i=0;i<report.writes;++i)
        if (report.journal[i].address!=expected[i].address ||
            report.journal[i].before!=expected[i].before ||
            report.journal[i].after!=expected[i].after) exit(108);
'''
    text += state_in() + '    out_eflags=s[8];\n}\n\n'
    return text


def prepare(source, output):
    output = output.resolve()
    if not output.is_relative_to((ROOT/'work').resolve()):
        raise ValueError('Output must be under private work/')
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Private source pin mismatch')
    text = data.decode('utf-8')
    marker = 'static void case_0(void) {'
    define = '#define MEM32(addr) (*checked_ptr32((uint32_t)(addr)))'
    # Reject unexpected structures before creating any output. No generated body
    # is stored here: the one pinned source supplies both bodies and test cases.
    if (text.count(define)!=1 or text.count(marker)!=1 or
            text.count('    cache_1ab770();')!=32 or text.count('    cache_1ab78c();')!=32):
        raise ValueError('Unexpected fixture structure')
    bodies, cases = text.split(marker)
    # The pinned fixture contains precisely two explicit stores (stack stores
    # are in PUSH32). Only the memory access site changes; comments stay intact.
    bodies, stores = re.subn(r'MEM32\((\w+)\) = (\w+);',
                            r'ts2_scoped_write32(\1,\2);', bodies)
    if stores != 2:
        raise ValueError('Unexpected store structure')
    bodies = bodies.replace(define, define + '\n#include "scoped_dispatch_bridge.h"\n' + scaffold())
    cases = cases.replace('    cache_1ab770();', '    runtime_dispatch(0xA01AB770u);')
    cases = cases.replace('    cache_1ab78c();', '    runtime_dispatch(0xA01AB78Cu);')
    text = bodies + wrappers() + marker + cases
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with output.open('x', encoding='utf-8') as f:
        output.chmod(0o600)
        f.write(text)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, default=ROOT/'work/interop-legacy-002/wrapper.c')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, ValueError):
        p.exit(1, 'Private fixture unavailable, pin/structure mismatch, or unsafe/existing output\n')
    print('Prepared pinned private scoped dispatch fixture (64 cases); no code emitted')


if __name__ == '__main__':
    main()
