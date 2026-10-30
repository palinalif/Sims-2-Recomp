#!/usr/bin/env python3
"""Measure first 1820 creation request from real alternate-opener ownership.

No allocator response, native execution or whole-function verification claimed.
Original bytes and captured boundary states are private, ignored outputs only.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_alternate_binding as b
import execute_table_lookup as table
c = b.c
RVA = 0x1820
UNITS = {**b.UNITS, RVA: (*table.UNITS[RVA], table.PINS[RVA])}
STOP = (c.BASE+0x183d, c.BASE+0x83a371)


def contract(before, after):
    """Independent subset: first bucket allocation, untouched owned data/frame."""
    c.require(before['boundary'] == dict(site=b.STOP[0], target=b.STOP[1]))
    c.require(after['boundary'] == dict(site=STOP[0], target=STOP[1]))
    a, z = (dict(zip(c.REGS, v['regs'])) for v in (before, after))
    raw_before, raw_after = (bytes.fromhex(v['pages']) for v in (before, after))
    c.require(len(raw_before) == len(raw_after) == len(b.IMAGES+c.DATA_PAGES)*4096)
    # All non-stack pages must be byte-identical. No table publication can be
    # credited before any actual allocation has completed.
    c.require(raw_after[4096:] == raw_before[4096:])
    c.require(z['esp'] == a['esp']-36 and z['edi'] == a['edi'])
    off = z['esp']-c.DATA_PAGES[0]
    c.require(0 <= off <= 4096-8)
    c.require(struct.unpack_from('<2I',raw_after,off) == (64,4))
    incoming = a['esp']-c.DATA_PAGES[0]
    c.require(raw_after[incoming:4096] == raw_before[incoming:4096])


def resume_state(boundary):
    """Reload exact live boundary state; never synthesize a call/return frame.

    The reference resets EFLAGS to 0x202 on segment entry. This is a GPR/page
    prefix check, not full flag equivalence or a single uninterrupted run.
    """
    c.require(boundary['boundary'] == dict(site=b.STOP[0],target=b.STOP[1]))
    c.require(len(boundary['regs']) == len(c.REGS))
    raw = bytes.fromhex(boundary['pages'])
    order = (*c.DATA_PAGES,*b.IMAGES)
    c.require(len(raw) == 4096*len(order))
    return dict(zip(c.REGS,boundary['regs'])), {
        p:bytearray(raw[i*4096:(i+1)*4096]) for i,p in enumerate(order)}


def reject_controls(before, after):
    for kind in ('target', 'count', 'width', 'table', 'cleanup'):
        bad = copy.deepcopy(after)
        if kind == 'target': bad['boundary']['target'] ^= 4
        elif kind == 'cleanup': bad['regs'][7] += 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            off = (bad['regs'][7]-c.DATA_PAGES[0]+(4 if kind == 'width' else 0)
                   if kind != 'table' else b.heap.PAGES.index(b.heap.ARENA)*4096+0x160)
            raw[off] ^= 1
            bad['pages'] = raw.hex()
        try: contract(before,bad)
        except ValueError: continue
        raise ValueError('Create-prefix negative control accepted')


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(b.__file__), Path(table.__file__),
               Path(b.t.__file__), Path(b.t.opener.__file__), Path(b.t.rig.__file__),
               Path(b.heap.__file__), Path(c.__file__), *b.t.HELPERS,
               Path(c.reference.__code__.co_filename), Path(b.decode_flow.__code__.co_filename),
               Path(b.crosscheck_index.__code__.co_filename), Path(c.state.__code__.co_filename)}
    row = dict(schema='ts2-table-create-prefix/1',success=False,stub=False,
        image_sha256=c.IMAGE_SHA,invocation=[sys.executable,*sys.argv],
        source_sha256={str(p):c.digest(p) for p in sources},
        index_sha256={hex(r):c.digest(p) for r,p in indexes.items()},
        lifted=False,host_native_executed=False,arm64_executed=False,android_executed=False,
        dependencies_newly_resolved=0,whole_function_verified=False,
        service_boundary=b.t.SERVICE_BOUNDARY,
        limits=['Original x86 prefixes; no allocator response at 83A371',
                'Four earlier allocations use explicit portable occupancy MODEL, not Windows',
                'Real 3C50 caller-produced table/cursor; no synthetic receiver repair',
                'Independent subset covers first creation request and unchanged non-stack pages',
                'Two bounded segments: startup <=4096 steps, original CALL/creation prefix <=128 steps',
                'Exact live GPR/page handoff; EFLAGS resets to 0x202, no full flag equivalence',
                'No full 1820/3700/3C50/1AB665, native execution, flags/FP or gameplay'])
    results, seen_all = [], set()
    try:
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        nodes,cp,row['functions'] = b.load_units(pe,indexes,UNITS)
        mode_page = pe.get_data(b.MODE_PAGE-c.BASE,4096)
        c.require(len(mode_page) == 4096)
        start = time.monotonic()
        for n in range(64):
            regs,pages = b.state(n); pages[b.MODE_PAGE] = mode_page
            service = b.t.model()
            before,seen = c.reference(nodes,cp,c.BASE+0x3c50,regs,pages,
                image_pages=b.IMAGES,heap_service=service,checked_repeat_copy=True,
                stop_before_call=b.STOP)
            c.require(service.calls == 4)
            seen_all |= seen
            b.contract(n,regs,pages,before,4)
            live_regs,live_pages = resume_state(before)
            after,seen = c.reference(nodes,cp,b.STOP[0],live_regs,live_pages,
                budget=128,image_pages=b.IMAGES,stop_before_call=STOP)
            seen_all |= seen
            # Save diagnostics even when an experimental contract rejects.
            results.append(dict(case=n,binding=before,creation=after))
            contract(before,after); reject_controls(before,after)
        row.update(success=True,subset_matches=64,reference_seconds=time.monotonic()-start,
            rejecting_controls={k:64 for k in ('target','count','width','table','cleanup')},
            allocation_count=64,allocation_element_bytes=4,
            coverage={hex(r):dict(visited=sum(c.BASE+r<=a<c.BASE+r+s for a in seen_all),total=n)
                      for r,(s,n,_) in UNITS.items()})
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(p)) == sha for p,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
    except Exception as exc:
        row.update(success=False,error_type=type(exc).__name__,failed_case=locals().get('n'))
        raise
    finally:
        private = output/'boundaries.json'; private.write_text(json.dumps(results)+'\n')
        row['boundaries_sha256'] = c.digest(private)
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes',type=Path,required=True)
    p.add_argument('--index-1820',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    indexes = {int(r,16):Path(path) for r,path in json.loads(a.indexes.read_text()).items()}
    indexes[RVA] = a.index_1820
    try: run(indexes,a.output)
    except Exception: p.exit(1,'Creation prefix rejected; inspect private receipt.\n')
    print('Original creation request measured; NOT allocator/native/Android verification.')


if __name__ == '__main__': main()
