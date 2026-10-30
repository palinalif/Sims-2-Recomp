#!/usr/bin/env python3
"""Resume caller-owned 1820 through calloc; bounded x86 composition, NOT native.

Original bytes/states remain private. Prior occupancy is carried forward, not
replaced by an empty heap. The service is a portable MODEL, not Windows.
"""
import argparse
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_table_create as p
import execute_calloc_success as calloc
c, b = p.c, p.b
STOP = (c.BASE+0x1861, c.BASE+0x1800)


class AllocationModel(b.t.opener.AllocationModel):
    """Four original requests followed by the independently checked zero service."""
    def __init__(self):
        super().__init__(b.t.REQUESTS)

    def invoke(self, cpu, ids, return_pc):
        if self.calls < len(self.requests):
            return super().invoke(cpu, ids, return_pc)
        c.require(self.calls == len(self.requests))
        zero = calloc.ZeroModel(256)
        zero.occupied = self.occupied
        zero.invoke(cpu, ids, return_pc)
        self.calls += zero.calls


def resume(boundary):
    c.require(boundary['boundary'] == dict(site=p.STOP[0], target=p.STOP[1]))
    c.require(len(boundary['regs']) == 8)
    raw = bytes.fromhex(boundary['pages'])
    order = (*c.DATA_PAGES, *b.IMAGES)
    c.require(len(raw) == len(order)*4096)
    return dict(zip(c.REGS, boundary['regs'])), {
        page: bytearray(raw[i*4096:(i+1)*4096]) for i,page in enumerate(order)}


def contract(before, after, service):
    c.require(after['boundary'] == dict(site=STOP[0], target=STOP[1]))
    c.require(service.calls == 5 and sum(service.occupied)*8 == sum(b.t.REQUESTS)+256)
    regs, pages = resume(before)
    c.require(len(after['regs']) == 8)
    final = dict(zip(c.REGS, after['regs']))
    c.require(final['edi'] == regs['edi'] and final['esp'] == regs['esp']+8)
    raw = bytes.fromhex(after['pages'])
    order = (*c.DATA_PAGES, *b.IMAGES)
    c.require(len(raw) == len(order)*4096)
    observed = {page:raw[i*4096:(i+1)*4096] for i,page in enumerate(order)}
    for page in set(order)-{c.DATA_PAGES[0], b.heap.ARENA}:
        c.require(observed[page] == pages[page])
    old, new = pages[b.heap.ARENA], observed[b.heap.ARENA]
    start = sum(b.t.REQUESTS)
    c.require(new[start:start+256] == bytes(256))
    c.require(new[:0x160] == old[:0x160] and new[0x170:start] == old[0x170:start])
    c.require(new[start+256:] == old[start+256:])
    # The original publishes the allocated bucket array in its table descriptor.
    c.require(struct.unpack_from('<I', new, 0x160)[0] == b.heap.ARENA+start)


def reject_controls(before, after, service):
    import copy
    for offset in (0x160, 0x78, sum(b.t.REQUESTS), sum(b.t.REQUESTS)+256):
        bad = copy.deepcopy(after)
        raw = bytearray.fromhex(bad['pages'])
        raw[c.DATA_PAGES.index(b.heap.ARENA)*4096+offset] ^= 1
        bad['pages'] = raw.hex()
        try: contract(before,bad,service)
        except ValueError: continue
        raise ValueError('Allocation composition mutation accepted')


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(p.__file__), Path(b.__file__), Path(calloc.__file__),
               Path(b.t.__file__), Path(b.t.opener.__file__), Path(b.heap.__file__),
               Path(c.reference.__code__.co_filename)}
    row = dict(schema='ts2-table-allocation-prefix/1',success=False,stub=False,
        original_behaviour_newly_executable=[],
        host_native_executed=False,arm64_executed=False,android_executed=False,
        dependencies_newly_resolved=0,whole_function_verified=False,
        invocation=[sys.executable,*sys.argv], image_sha256=c.IMAGE_SHA,
        source_sha256={str(f):c.digest(f) for f in sources},
        index_sha256={hex(r):c.digest(f) for r,f in indexes.items()},
        limits=['Original x86 segmented prefix only; no fresh lifts/native execution',
                'Persistent portable occupancy/zeroing MODEL, NOT Windows',
                'Exact GPR/page segment handoff; EFLAGS reset 0x202',
                'No full 1820/3700/3C50/1AB665, lifetime, error/retry, flags/FP or gameplay'])
    results = []
    try:
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        units = {**p.UNITS,calloc.RVA:(calloc.SIZE,calloc.COUNT,calloc.PIN)}
        nodes,cp,row['functions'] = b.load_units(pe,indexes,units)
        code = pe.get_data(calloc.WRAPPER,calloc.WRAPPER_SIZE)
        _, ns, metadata = b.heap.decode_wrapper(code,lambda i:i,rva=calloc.WRAPPER,
            size=calloc.WRAPPER_SIZE,count=calloc.WRAPPER_COUNT,
            pin=calloc.WRAPPER_PIN,target=calloc.RVA)
        row['wrapper_index'] = b.crosscheck_index(json.loads(indexes[calloc.WRAPPER].read_text()),metadata,calloc.WRAPPER)
        nodes.update(ns)
        page = c.BASE+(calloc.WRAPPER//4096)*4096
        cp.setdefault(page,bytearray(4096))[calloc.WRAPPER%4096:calloc.WRAPPER%4096+len(code)] = code
        start = time.monotonic()
        for n in range(64):
            regs,pages = b.state(n); pages[b.MODE_PAGE] = pe.get_data(b.MODE_PAGE-c.BASE,4096)
            service = AllocationModel()
            binding,_ = c.reference(nodes,cp,c.BASE+0x3c50,regs,pages,
                image_pages=b.IMAGES,heap_service=service,checked_repeat_copy=True,stop_before_call=b.STOP)
            b.contract(n,regs,pages,binding,service.calls)
            regs,pages = p.resume_state(binding)
            creation,_ = c.reference(nodes,cp,b.STOP[0],regs,pages,budget=128,
                image_pages=b.IMAGES,stop_before_call=p.STOP)
            p.contract(binding,creation)
            regs,pages = resume(creation)
            after,_ = c.reference(nodes,cp,p.STOP[0],regs,pages,budget=256,
                image_pages=b.IMAGES,heap_service=service,checked_calloc_arithmetic=True,
                stop_before_call=STOP)
            results.append(dict(case=n,creation=creation,allocation=after))
            contract(creation,after,service); reject_controls(creation,after,service)
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(f)) == sha for f,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row.update(success=True,subset_matches=64,negative_controls_rejected=4*64,
                   original_behaviour_newly_executable=['Caller-owned 183D calloc through bucket publication before 1861 (x86 only)'],
                   reference_seconds=time.monotonic()-start)
    except Exception as exc:
        row.update(error_type=type(exc).__name__,failed_case=locals().get('n'))
        raise
    finally:
        (output/'boundaries.json').write_text(json.dumps(results)+'\n')
        row['boundaries_sha256'] = c.digest(output/'boundaries.json')
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indexes',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    try: run({int(r,16):Path(f) for r,f in json.loads(args.indexes.read_text()).items()},args.output)
    except Exception: parser.exit(1,'Caller-owned allocation rejected; inspect private receipt.\n')
    print('Caller-owned calloc prefix matched; NOT native/Android/whole-function verification.')


if __name__ == '__main__': main()
