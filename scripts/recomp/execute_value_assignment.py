#!/usr/bin/env python3
"""Fresh 1330 lift using saved live 3700 arguments and portable owned heap.

No invented callee responses. Callback/reuse/realloc/failure paths reject.
Private caller states and derived code must remain under ignored work/.
"""
import argparse
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_capacity_success as capacity
import probe_key_publication as key
c, heap, g = capacity.c, capacity.heap, key.g
ROOT_RVA = 0x1330
RVA, WRAPPER = heap.RVA, heap.WRAPPER
UNITS = {ROOT_RVA: (299, 116, '841c02261fb2e297c27cfcc9cc64e9be3d719348ea5e50ef9f8a7fece8983a75'),
         WRAPPER: (heap.WRAPPER_SIZE, heap.WRAPPER_COUNT, heap.WRAPPER_PIN),
         RVA: (heap.SIZE, heap.COUNT, heap.PIN)}
PAGES, IMAGES, EXTRA_PAGES = g.ORDER, g.b.IMAGES, (g.EXTRA,)
BOUNDARIES = c.ROOT/'work/recomp-bench/key-publish-reviewed/boundaries.json'
BOUNDARY_SHA = 'a95f79dfe6205d68ce14adf4046080c7f5a59728fa012e34362ebf72f62244a9'
INPUT_PINS = {BOUNDARIES: BOUNDARY_SHA}
SCHEMA = 'ts2-live-value-assignment-native/1'
HELPERS = (Path(key.__file__), Path(g.__file__))
SERVICE_BOUNDARY = dict(x86='independent occupied-cell allocation model',
    native='production GuestHeap with explicit occupied-prefix allocation',
    original_windows_import_executed=False, expected_calls_per_case=2)
BEHAVIOUR = '1330 value/list publication using live 3700 pending arguments, null callback/free list'
LIMITS = ['Pinned live caller arguments/pages; CALL return replaced by test sentinel only',
    'Two successful dirty allocations; portable heap MODEL not Windows HeapAlloc',
    'Null callback/free list only; reuse/realloc/failure/callback paths unverified',
    'Two repeated allocator calls use a fail-closed path-specific return-PC sequence',
    'Eight final GPRs/eight pages; no flags/FP/PC/native transient writes',
    'Segment upstream resets EFLAGS; no full3700/3C50/1AB665/E3/E4/Android/gameplay']
# Exact exercised sites are fixed after independent original-x86 exploration.
COVERAGE = {'0x1330': 75, '0x831a6f': 5, '0x8461f2': 19}
OCCUPIED = g.p.OCCUPIED+g.p.REQUEST


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    c.require(c.digest(BOUNDARIES) == BOUNDARY_SHA)
    rows = json.loads(BOUNDARIES.read_text())
    c.require(len(rows) == 64 and rows[n]['case'] == n)
    before = rows[n]['after']
    c.require(before['boundary'] == dict(site=key.STOP[0], target=key.STOP[1]))
    raw = bytes.fromhex(before['pages'])
    c.require(len(raw) == len(PAGES)*4096 and len(before['regs']) == 8)
    pages = {p:bytearray(raw[i*4096:(i+1)*4096]) for i,p in enumerate(PAGES)}
    regs = dict(zip(c.REGS, before['regs']))
    # Enter just the pending callee: synthesize CALL's return word, not args,
    # receiver, allocator output or any behavior response.
    regs['esp'] -= 4
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0], c.RETURN)
    return regs, pages


class AllocationModel:
    target = heap.SERVICE

    def __init__(self):
        self.cells = [True]*(OCCUPIED//8)+[False]*((g.SIZE-OCCUPIED)//8)
        self.calls = 0
        self.requests = []

    def invoke(self, cpu, ids, return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4080 and sp%4 == 0)
        ret, handle, flags, size = struct.unpack('<4I', bytes(cpu.mem_read(sp,16)))
        c.require(ret == return_pc and handle == heap.HANDLE and flags == 0)
        c.require(self.calls < 2 and 0 < size <= 4096)
        units = (size+7)//8
        start = next((i for i in range(len(self.cells)-units+1)
                      if not any(self.cells[i:i+units])), None)
        c.require(start is not None)
        self.cells[start:start+units] = [True]*units
        cpu.reg_write(ids['eax'], heap.ARENA+start*8)
        cpu.reg_write(ids['esp'], sp+16)
        cpu.reg_write(x.UC_X86_REG_EIP, ret)
        self.calls += 1
        self.requests.append(size)


def model():
    return AllocationModel()


def contract(regs, pages, result, service):
    """Predict list links, payload and every nonstack byte from live inputs."""
    sp = regs['esp']-c.DATA_PAGES[0]
    ret, obj, node, context, source, head = struct.unpack_from('<6I',pages[c.DATA_PAGES[0]],sp)
    c.require(ret == c.RETURN and obj == heap.ARENA and context == 0)
    old = pages[heap.ARENA]+pages[g.EXTRA]
    word = lambda a: struct.unpack_from('<I',old,a-heap.ARENA)[0]
    c.require(word(obj+0x1b4) == 0 and word(obj+0x60) == 0)
    src = source-heap.ARENA
    c.require(0 <= src < OCCUPIED)
    end = old.index(0,src)
    marker = old[0x204]
    # Marker zero excludes the NUL; nonzero marker replaces that NUL.
    value = old[src:end]+(bytes([marker]) if marker else b'')
    c.require(service.calls == 2 and service.requests == [28,24+len(value)])
    record, payload = heap.ARENA+OCCUPIED, heap.ARENA+OCCUPIED+32
    expected = bytearray(old)
    struct.pack_into('<7I',expected,record-heap.ARENA,
        node,word(head),word(node+4),context,payload,len(value),24+len(value))
    expected[payload-heap.ARENA:payload-heap.ARENA+len(value)] = value
    # Empty sentinel node is special; the live key fixture is nonempty.
    c.require(src < end)
    struct.pack_into('<I',expected,node-heap.ARENA+4,record)
    struct.pack_into('<I',expected,head-heap.ARENA,record)
    after = {p:bytearray(v) for p,v in pages.items()}
    after[heap.ARENA], after[g.EXTRA] = expected[:4096], expected[4096:]
    c.require(result['regs'][0] == 1 and result['regs'][7] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == len(PAGES)*4096)
    c.require(raw[4096:] == b''.join(after[p] for p in PAGES[1:]))


def assemble(bodies, direct_returns, indirect_return):
    # The same target is called twice. The shared caller/target-only return
    # adapter is ambiguous here; admit exactly the independently decoded sites
    # for this null-free-list success path, in their observed x86 order.
    calls = [edge for edge in direct_returns if edge[0] == c.BASE+ROOT_RVA]
    c.require(calls == [(c.BASE+ROOT_RVA,c.BASE+WRAPPER,c.BASE+0x1397),
                        (c.BASE+ROOT_RVA,c.BASE+WRAPPER,c.BASE+0x13a9)])
    text = capacity.assemble(bodies,[e for e in direct_returns if e not in calls],
        indirect_return,units=UNITS,entry_rva=ROOT_RVA,direct_targets=(0x831a54,))
    # Keep generated body verbatim. Route upstream REP helper through the same
    # checked guest-byte boundary rather than upstream raw host pointer mapping.
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
    old = 'static uint32_t direct_return(uint32_t caller,uint32_t target) {'
    c.require(text.count(old) == 1)
    sequence = f'''static unsigned value_calls;
{old}
    if(caller==0x{c.BASE+ROOT_RVA:08X}u && target==0x{c.BASE+WRAPPER:08X}u) {{
        if(value_calls>=2) reject();
        return value_calls++==0 ? 0x{c.BASE+0x1397:08X}u : 0x{c.BASE+0x13a9:08X}u;
    }}'''
    text = text.replace(old,helper+sequence)
    text = text.replace('cache_reset(pages);','value_calls=0;cache_reset(pages);')
    text = text.replace('cache_copy(pages);','if(value_calls!=2) reject();cache_copy(pages);')
    text = text.replace('unsigned char pages[6*4096]',f'unsigned char pages[{len(PAGES)}*4096]')
    old = 'if(in[7]!=0x70000800u && in[7]!=0x70000C00u) return 91;'
    c.require(text.count(old) == 1)
    text = text.replace(old,'if(in[7]<0x70000080u || in[7]>0x70000FE8u || in[7]%4) return 91;')
    c.require(all(text.count(body) == 1 for body in bodies.values()))
    return text


def bridge_source(mode):
    text = capacity.bridge_source(mode)
    old = 'constexpr std::array<uint32_t,6> bases{'+','.join(f'0x{p:08X}u' for p in heap.PAGES)+'};'
    c.require(text.count(old) == 1)
    text = text.replace(old,f'constexpr std::array<uint32_t,{len(PAGES)}> bases{{'+','.join(f'0x{p:08X}u' for p in PAGES)+'};')
    old = 'constexpr std::array<uint32_t,'+str(len(capacity.UNITS)+1)+'> targets{'+','.join(f'0x{a:08X}u' for a in [c.BASE+r for r in capacity.UNITS]+[heap.SERVICE])+'};'
    c.require(text.count(old) == 1)
    text = text.replace(old,f'constexpr std::array<uint32_t,{len(UNITS)+1}> targets{{'+','.join(f'0x{a:08X}u' for a in [c.BASE+r for r in UNITS]+[heap.SERVICE])+'};')
    text = text.replace('(write?4u:6u)',f'(write?5u:{len(PAGES)}u)').replace('p<6;',f'p<{len(PAGES)};')
    old = f'    if(!heap) heap=std::make_unique<ts2::GuestHeap>(*memory,0x{heap.HANDLE:08X}u,0x{heap.ARENA:08X}u,4096);'
    setup = f'''    if(!heap) {{
        heap=std::make_unique<ts2::GuestHeap>(*memory,0x{heap.HANDLE:08X}u,0x{heap.ARENA:08X}u,{g.SIZE});
        if(heap->allocate(0x{heap.HANDLE:08X}u,0,{OCCUPIED})!=0x{heap.ARENA:08X}u)
            throw std::runtime_error("occupied prefix");
    }}'''
    c.require(text.count(old) == 1)
    return text.replace(old,setup)


def assess(text, expected, mode):
    """Strict eight-page protocol; crashed/malformed mutants never count."""
    c.require(mode in capacity.MODES and len(expected) == 64)
    rows = [json.loads(line) for line in text.splitlines()]
    for records in (rows, expected):
        c.require(len(records) == 64)
        for n, row in enumerate(records):
            c.require(type(row) is dict and set(row) == {'case','regs','pages'})
            c.require(type(row['case']) is int and row['case'] == n)
            c.require(type(row['regs']) is list and len(row['regs']) == 8)
            c.require(all(type(v) is int and 0 <= v <= 0xffffffff for v in row['regs']))
            raw = row['pages']
            c.require(type(raw) is str and len(raw) == len(PAGES)*8192 and
                      all(v in '0123456789abcdef' for v in raw))
    differences = sum(a != b for a,b in zip(rows,expected))
    c.require(differences == 0 if mode == 'valid' else differences > 0)
    return dict(executed=True,cases=64,matched=64-differences,
                differing_cases=differences,negative_control=mode != 'valid')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    try:
        capacity.run({int(k,16):Path(v) for k,v in json.loads(a.indexes.read_text()).items()},
                     a.output,scenario=sys.modules[__name__])
    except Exception:
        p.exit(1,'Live value assignment rejected; inspect private receipt.\n')
    print('Live value assignment compared host/Linux-AArch64; NOT full caller/Android.')


if __name__ == '__main__': main()
