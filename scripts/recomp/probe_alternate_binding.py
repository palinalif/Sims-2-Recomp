#!/usr/bin/env python3
"""Measure real 3C50/3A50 ownership at the pending 3700 -> 1820 edge.

Authored fixture/checking only. No callee response at the stop boundary, no
native or complete-function claim. Original states stay in ignored work/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_opener_text as t
import execute_mode_empty as m
from inspect_startup_dependency import crosscheck_index
from measure_startup import decode_flow
c, heap = t.c, t.heap
UNITS = {**t.UNITS,
    0x3c50: (100, 33, '4fc9af5c85c0b3047465aa8553cf3cc588a0c61e7de83fc2106b0198f738d149'),
    0x10b60: (61, 18, '820273871703ba7086e823c5f6dd7edb5ce80486b47ca694e48c579302ed5426'),
    0x10af0: (6, 2, '1525a5b6814a6e6761a02d6f5ac702b00b7c3f8c4c021c892b51d8f7e497f3d5'),
    m.RVA: (m.SIZE, m.COUNT, m.PIN)}
MODE_PAGE = c.BASE+0xe16000
MODE_TEXT = c.BASE+0xe16fb0
IMAGES = (*heap.IMAGES, MODE_PAGE)
MODE_BYTES = (0, 1, 2, 3, 0x7f, 0x80, 0xfe, 0xff)
STOP = (c.BASE+0x378a, c.BASE+0x1820)


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    regs, pages = t.state(n)
    # 3C50 consumes a byte option, NOT a pointer to a mode string.
    struct.pack_into('<I', pages[c.DATA_PAGES[0]],
                     regs['esp']-c.DATA_PAGES[0]+8, MODE_BYTES[n % 8])
    return regs, pages


def contract(n, regs, pages, observed, service_calls):
    """Independent ownership/copy/frame subset; scratch GPRs are not an oracle."""
    c.require(type(n) is int and 0 <= n < 64 and service_calls == 4)
    c.require(observed['boundary'] == dict(site=STOP[0],target=STOP[1]))
    raw = bytes.fromhex(observed['pages'])
    order = (*heap.PAGES,MODE_PAGE)
    c.require(len(raw) == 4096*len(order))
    after = {p: raw[i*4096:(i+1)*4096] for i,p in enumerate(order)}
    c.require(all(after[p] == pages[p] for p in order
                  if p not in (heap.ARENA,c.DATA_PAGES[0])))
    arena = after[heap.ARENA]
    word = lambda off: struct.unpack_from('<I',arena,off)[0]
    chunk = sum(t.opener.REQUESTS)
    text = heap.ARENA+chunk+8
    source = pages[c.DATA_PAGES[3]]
    end = source.index(0,t.SOURCE_OFFSET)
    sample = source[t.SOURCE_OFFSET:end+1]
    key = text+len(sample)
    # The fixed image-backed mode begins with a three-byte key and a delimiter.
    # Validate that bounded input grammar instead of inventing parser responses.
    literal = pages[MODE_PAGE][MODE_TEXT-MODE_PAGE:]
    c.require(len(literal) >= 4 and 0 not in literal[:3] and literal[3] in b' =:;\t\n')
    token = literal[:3]+b'\0'
    c.require(arena[chunk+8:chunk+8+len(sample)] == sample)
    c.require(arena[key-heap.ARENA:key-heap.ARENA+len(token)] == token)
    c.require(word(0xd0) == text and word(0x1d0) == heap.ARENA+chunk and word(0x1d4) == 0)
    c.require(word(0x1d8) == heap.ARENA+sum(t.REQUESTS) and
              word(0x1dc) == key+len(token) and word(0x1e0) == key)
    c.require(struct.unpack_from('<II',arena,chunk) == (0,1024))
    c.require(arena[0x160:0x170] == bytes(16))
    c.require(word(0x78) == heap.ARENA+0x7c and word(0xc8) == heap.ARENA+0x78)
    c.require(word(0xb0) == c.BASE+0xfcf0 and arena[0xc5] == 6)
    c.require(word(0xd4) == 1 and arena[0x204] == MODE_BYTES[n%8])
    c.require(arena[key-heap.ARENA+len(token):] == pages[heap.ARENA][key-heap.ARENA+len(token):])
    out = dict(zip(c.REGS,observed['regs']))
    c.require(len(observed['regs']) == 8 and out['esi'] == heap.ARENA and
              out['edi'] == heap.ARENA+0x160 and out['esp'] == regs['esp']-32)
    sp = out['esp']-c.DATA_PAGES[0]
    c.require(struct.unpack_from('<II',after[c.DATA_PAGES[0]],sp) == (key,8))
    initial_sp = regs['esp']-c.DATA_PAGES[0]
    c.require(after[c.DATA_PAGES[0]][initial_sp:] == pages[c.DATA_PAGES[0]][initial_sp:])


def reject_controls(n, regs, pages, observed, service_calls):
    import copy
    for kind in ('target','create-argument','cursor'):
        bad = copy.deepcopy(observed)
        if kind == 'target':
            bad['boundary']['target'] ^= 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            if kind == 'create-argument':
                off = bad['regs'][7]-c.DATA_PAGES[0]+4
            else:
                off = heap.PAGES.index(heap.ARENA)*4096+0x1dc
            raw[off] ^= 1
            bad['pages'] = raw.hex()
        try:
            contract(n,regs,pages,bad,service_calls)
        except ValueError:
            continue
        raise ValueError('Binding negative control accepted')


def load_units(pe, indexes, units=UNITS):
    """Decode pinned private units and cross-check persistent index boundaries."""
    nodes, cp, metadata = {}, {heap.SERVICE: bytes(4096)}, {}
    for r,(size,count,pin) in units.items():
        code = pe.get_data(r,size)
        c.require(hashlib.sha256(code).hexdigest() == pin)
        if r == heap.WRAPPER:
            _, ns, flow = heap.decode_wrapper(code,lambda i:i,rva=r,size=size,
                count=count,pin=pin,target=heap.RVA)
        else:
            _, ns, _, flow = decode_flow(code,c.BASE+r,lambda i:i)
            flow = dict(flow,instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)])
        c.require(len(ns) == count and flow['size_bytes'] == size)
        metadata[hex(r)] = crosscheck_index(json.loads(indexes[r].read_text()),flow,r)
        c.require(not set(nodes)&set(ns)); nodes.update(ns)
        page = c.BASE+(r//4096)*4096
        cp.setdefault(page,bytearray(4096))[r%4096:r%4096+size] = code
    return nodes, cp, metadata


def run(indexes, output):
    output = c.private_output(output)
    sources = [Path(__file__), Path(t.__file__), Path(t.opener.__file__),
               Path(t.rig.__file__), Path(c.reference.__code__.co_filename),
               Path(crosscheck_index.__code__.co_filename), Path(decode_flow.__code__.co_filename),
               Path(m.__file__), Path(heap.__file__),
               Path(c.__file__), Path(c.state.__code__.co_filename), *t.HELPERS]
    row = dict(schema='ts2-alternate-binding/1', success=False, stub=False,
        image_sha256=c.IMAGE_SHA, invocation=[sys.executable,*sys.argv],
        source_sha256={str(p): c.digest(p) for p in sources},
        index_sha256={hex(r): c.digest(p) for r,p in indexes.items()},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False,
        dependencies_newly_resolved=0,
        service_boundary=t.SERVICE_BOUNDARY, functions={},
        limits=['Original x86 prefixes only; no lifts or native/Android execution',
                'Four successful allocations via explicit portable occupancy MODEL, not Windows heap',
                'Real caller-produced table/cursor; bounded source lengths0..255, fixed image-backed mode',
                'Independent ownership/copy/frame subset; not all volatile GPRs, stack scratch or handle bytes',
                'No 1820 execution/response: second argument8 excludes the prior no-create-zero fixture',
                'No full 3700/3C50/1AB665, cleanup/lifetime/flags/FP/PC/transient-write proof'])
    try:
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        nodes, cp, row['functions'] = load_units(pe, indexes)
        mode_page = pe.get_data(MODE_PAGE-c.BASE,4096)
        c.require(len(mode_page) == 4096)
        row['mode_page_sha256'] = hashlib.sha256(mode_page).hexdigest()
        results, seen_all = [], set()
        entry_cases = {r: 0 for r in UNITS}
        start = time.monotonic()
        for n in range(64):
            regs,pages = state(n); service = t.model()
            pages[MODE_PAGE] = mode_page
            result,seen = c.reference(nodes,cp,c.BASE+0x3c50,regs,pages,
                image_pages=IMAGES,heap_service=service,checked_repeat_copy=True,
                stop_before_call=STOP)
            contract(n,regs,pages,result,service.calls)
            reject_controls(n,regs,pages,result,service.calls)
            c.require(sum(service.occupied)*8 == sum(t.REQUESTS))
            seen_all |= seen
            for r in UNITS:
                entry_cases[r] += int(c.BASE+r in seen)
            results.append(dict(case=n,initial_regs=regs,observed=result,service_calls=service.calls))
        (output/'boundaries.json').write_text(json.dumps(results)+'\n')
        c.require(all(count >= 32 for count in entry_cases.values()))
        row.update(boundary_subset_matches=64,reference_seconds=time.monotonic()-start,
            entry_cases={hex(r):count for r,count in entry_cases.items()},
            rejecting_controls=dict(target=64,create_argument=64,cursor=64),
            coverage={hex(r):dict(visited=sum(c.BASE+r<=a<c.BASE+r+s for a in seen_all),total=n)
                      for r,(s,n,_) in UNITS.items()})
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(p)) == sha for p,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row['boundaries_sha256'] = c.digest(output/'boundaries.json')
        row['success'] = True
    except Exception as exc:
        row.update(error_type=type(exc).__name__, failed_case=locals().get('n'))
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    try:
        run({int(r,16):Path(path) for r,path in json.loads(a.indexes.read_text()).items()},a.output)
    except Exception:
        p.exit(1,'Alternate binding rejected; inspect private receipt.\n')
    print('Original caller boundary captured; NOT native/whole opener/Android.')


if __name__ == '__main__': main()
