#!/usr/bin/env python3
"""Fresh composed 3C50 short-input lift against continuous original x86.

Private bodies/states stay in work/. Portable heap, NOT Windows or gameplay.
"""
import argparse
from functools import lru_cache
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_continuous_opener as reference
rig, c, heap = reference.value.capacity, reference.c, reference.heap
UNITS = reference.UNITS
ROOT_RVA, RVA, WRAPPER = 0x3c50, heap.RVA, heap.WRAPPER
PAGES, IMAGES, EXTRA_PAGES = reference.ORDER, reference.b.IMAGES, (reference.EXTRA,)
TAIL_WRAPPERS = {WRAPPER:RVA, reference.calloc.WRAPPER:reference.calloc.RVA}
REFERENCE_OPTIONS = dict(checked_integer_multiply=True, checked_calloc_arithmetic=True)
SCHEMA = 'ts2-continuous-opener-native/1'
BEHAVIOUR = 'continuous 3C50 short single-key success entry to sentinel'
# Pin all loaded local Python dependencies, not only immediate imports.
HELPERS = tuple(sorted({Path(module.__file__).resolve()
    for module in tuple(sys.modules.values())
    if getattr(module, '__file__', None) and
    Path(module.__file__).resolve().parent == Path(__file__).resolve().parent}))
LIMITS = [
    'Source lengths0,1,7,15,31,55,63,127; fixed image-backed key=value, eight markers',
    'Continuous original entry, no segmented resumption or synthetic internal returns',
    'Independent occupied-cell MODEL vs production GuestHeap; NOT Windows heap',
    'Observed callsite sequence restricts this path; unknown/excess/missing calls reject',
    'Eight final GPRs/eight full pages; no flags/FP/PC/native transient-write comparison',
    'Unvisited arms, long inputs, failure, cleanup, callback, realloc/lifetime unverified',
    'No whole-function/all-path/E3/E4/Android/game menu/gameplay proof']
SERVICE_BOUNDARY = dict(x86='independent occupied-cell allocation model',
    native='production GuestHeap starts EMPTY, 8192 bytes',
    original_windows_import_executed=False, expected_calls_per_case=9)
# Pinned from the previous continuous reference receipt, not native outcomes.
COVERAGE = {'0x3a50':124, '0x831a6f':5, '0x8461f2':19, '0x2570':18,
    '0x1a40':7, '0x1a00':6, '0x122f0':5, '0x10960':2, '0x109d0':16,
    '0x10700':4, '0x26b0':26, '0x1af0':44, '0x3c50':27, '0x10b60':16,
    '0x10af0':2, '0x3700':113, '0x1820':47, '0x1800':12, '0x17d0':0,
    '0x1330':75, '0x849a00':26, '0x83a371':5}


@lru_cache(maxsize=1)
def mode_page():
    import pefile
    image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
    c.require(c.digest(image) == c.IMAGE_SHA)
    return pefile.PE(data=image.read_bytes()).get_data(reference.b.MODE_PAGE-c.BASE,4096)


def state(n):
    return reference.state(n, mode_page())


def model():
    return reference.ArenaModel()


def contract(regs,pages,result,service):
    # n only selects the marker in this subset contract. Derive it from the
    # authored input argument, never from the result or allocator responses.
    import struct
    marker = struct.unpack_from('<I',pages[c.DATA_PAGES[0]],
                                regs['esp']-c.DATA_PAGES[0]+8)[0]
    n = reference.b.MODE_BYTES.index(marker)
    reference.contract(n,regs,pages,result,service)
    c.require(len(service.requests) == 9)
    service.calls = len(service.requests)


def schedule(edges,traces):
    """Bind observed CALL sites to independently decoded direct edges.

    No sorting/cycling guessed return PCs: repeated sites retain execution order.
    All 64 cases must exercise the identical call sequence for this transport.
    """
    c.require(len(traces) == 64 and traces[0] and all(t == traces[0] for t in traces))
    known = set(edges)
    groups = {}
    for site,target,ret in traces[0]:
        owners = [c.BASE+r for r,(size,_,_) in UNITS.items()
                  if c.BASE+r <= site < ret <= c.BASE+r+size]
        c.require(len(owners) == 1 and ret-site in range(2,8))
        caller = owners[0]
        if target == heap.SERVICE:
            c.require(caller-c.BASE in (RVA,reference.calloc.RVA))
        else:
            c.require((caller,target,ret) in known)
        groups.setdefault((caller,target),[]).append(ret)
    declarations,cases,resets,checks = [],[],[],[]
    for n,((caller,target),returns) in enumerate(sorted(groups.items())):
        name = f'continuous_edge_{n}'
        declarations.append(f'static unsigned {name};')
        resets.append(f'{name}=0;')
        checks.append(f'if({name}!={len(returns)}) reject();')
        cases.append(f'if(caller==0x{caller:08X}u && target==0x{target:08X}u) {{ switch({name}++) {{'+
            ''.join(f'case {i}:return 0x{ret:08X}u;' for i,ret in enumerate(returns))+
            'default:reject();} }')
    return '\n'.join(declarations), '\n'.join(cases), ''.join(resets), ''.join(checks)


def assemble_traced(bodies,edges,indirect_return,traces):
    # Retain every fresh lifted body verbatim, including unvisited fail-closed arms.
    targets = {int(s,16)-c.BASE for body in bodies.values()
               for s in re.findall(r'\bsub_([0-9A-Fa-f]{8})\b',body)}
    text = rig.assemble(bodies,edges,indirect_return,units=UNITS,
                        entry_rva=ROOT_RVA,direct_targets=targets)
    declarations,cases,resets,checks = schedule(edges,traces)
    old = '\n'.join(f'if(caller==0x{caller:08X}u && target==0x{target:08X}u) return 0x{ret:08X}u;'
                    for caller,target,ret in edges)
    c.require(text.count(old) == 1)
    text = text.replace(old,cases)
    old = f'if(caller==0x{c.BASE+RVA:08X}u && target==0x{heap.SERVICE:08X}u) return 0x{indirect_return:08X}u;'
    c.require(text.count(old) == 1)
    text = text.replace(old,'return direct_return(caller,target);')
    helper = '''static void checked_rep(uint32_t dst,uint32_t src,uint32_t n,uint32_t width,int df) {
    if((width!=1 && width!=4) || df!=1 || n>4096/width) reject();
    for(uint32_t i=0;i<n;++i) {
        uint32_t v=0;
        for(uint32_t j=0;j<width;++j) v|=cache_read(src+j,1)<<(8*j);
        for(uint32_t j=0;j<width;++j) cache_write(dst+j,1,v>>(8*j));
        src+=width;dst+=width;
    }
}
#define recomp_rep_movs checked_rep
'''
    text = text.replace('static uint32_t direct_return(',helper+declarations+'\nstatic uint32_t direct_return(')
    old = f'if(g_cur_func!=0x{c.BASE+WRAPPER:08X}u || target!=0x{c.BASE+RVA:08X}u) reject();'
    allowed = ' || '.join(f'(g_cur_func==0x{c.BASE+w:08X}u && target==0x{c.BASE+t:08X}u)'
                          for w,t in TAIL_WRAPPERS.items())
    c.require(text.count(old) == 1)
    text = text.replace(old,f'if(!({allowed})) reject();')
    text = text.replace('cache_reset(pages);',resets+'cache_reset(pages);')
    text = text.replace('cache_copy(pages);',checks+'cache_copy(pages);')
    text = text.replace('unsigned char pages[6*4096]',f'unsigned char pages[{len(PAGES)}*4096]')
    c.require(all(text.count(body) == 1 for body in bodies.values()))
    return text


def bridge_source(mode):
    text = rig.bridge_source(mode)
    replacements = {
        'constexpr std::array<uint32_t,6> bases{'+','.join(f'0x{p:08X}u' for p in heap.PAGES)+'};':
            f'constexpr std::array<uint32_t,{len(PAGES)}> bases{{'+','.join(f'0x{p:08X}u' for p in PAGES)+'};',
        'constexpr std::array<uint32_t,'+str(len(rig.UNITS)+1)+'> targets{'+','.join(f'0x{a:08X}u' for a in [c.BASE+r for r in rig.UNITS]+[heap.SERVICE])+'};':
            f'constexpr std::array<uint32_t,{len(UNITS)+1}> targets{{'+','.join(f'0x{a:08X}u' for a in [c.BASE+r for r in UNITS]+[heap.SERVICE])+'};',
        f'0x{heap.ARENA:08X}u,4096)':f'0x{heap.ARENA:08X}u,{reference.SIZE})',
        '(write?4u:6u)':f'(write?5u:{len(PAGES)}u)',
        'p<6;':f'p<{len(PAGES)};',
    }
    for old,new in replacements.items():
        c.require(text.count(old) >= 1)
        text = text.replace(old,new)
    return text


assess = reference.value.assess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indexes',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    rig.run({int(r,16):Path(p) for r,p in json.loads(args.indexes.read_text()).items()},
            args.output,scenario=sys.modules[__name__])


if __name__ == '__main__': main()
