#!/usr/bin/env python3
"""Live capacity allocation/link subset with explicit two-page portable MODEL.

Original x86 only. No whole-function/native translation/Windows/Android claim.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_live_capacity as p
c, b = p.c, p.b
heap = b.heap
EXTRA = heap.ARENA+4096
ORDER = (*c.DATA_PAGES, EXTRA, *b.IMAGES)
STOP_PC = c.BASE+0x37b2
DESCRIPTOR = 0x170
SIZE = 8192


class ArenaModel:
    """Independent cell occupancy, not GuestHeap's extent map; dirty allocation."""
    target = heap.SERVICE

    def __init__(self):
        self.occupied = [True]*(p.OCCUPIED//8)+[False]*((SIZE-p.OCCUPIED)//8)
        self.calls = 0

    def invoke(self, cpu, ids, return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4080 and sp % 4 == 0)
        ret, handle, flags, size = struct.unpack('<4I', bytes(cpu.mem_read(sp,16)))
        c.require((ret, handle, flags, size) == (return_pc, heap.HANDLE, 0, p.REQUEST))
        c.require(self.calls == 0)
        units = (size+7)//8
        start = next((i for i in range(len(self.occupied)-units+1)
                      if not any(self.occupied[i:i+units])), None)
        result = 0
        if start is not None:
            self.occupied[start:start+units] = [True]*units
            result = heap.ARENA+8*start
        cpu.reg_write(ids['eax'], result)
        cpu.reg_write(ids['esp'], sp+16)
        cpu.reg_write(x.UC_X86_REG_EIP, ret)
        self.calls += 1


def resume(before):
    c.require(before['boundary'] == dict(site=p.STOP[0], target=p.STOP[1]))
    c.require(len(before['regs']) == 8)
    raw = bytes.fromhex(before['pages'])
    c.require(len(raw) == len(p.node.ORDER)*4096)
    pages = {page: bytearray(raw[i*4096:(i+1)*4096])
             for i,page in enumerate(p.node.ORDER)}
    c.require(EXTRA not in pages)
    # New fixture storage only; no live page is moved, rewritten or reclaimed.
    pages[EXTRA] = bytearray([0xa5])*4096
    return dict(zip(c.REGS, before['regs'])), pages


def advance(before, nodes, code):
    regs, pages = resume(before)
    service = ArenaModel()
    after, seen = c.reference(nodes, code, p.STOP[0], regs, pages, budget=1024,
        image_pages=b.IMAGES, heap_service=service, extra_data_pages=(EXTRA,),
        checked_repeat_copy=True, stop_before_pc=STOP_PC)
    return after, seen, service


def contract(before, after, service):
    """Independent empty-descriptor publication and exact nonstack-byte subset."""
    regs, pages = resume(before)
    c.require(after['stop_pc'] == STOP_PC)
    c.require(len(after['regs']) == 8)
    raw = bytes.fromhex(after['pages'])
    c.require(len(raw) == len(ORDER)*4096)
    observed = {page: raw[i*4096:(i+1)*4096] for i,page in enumerate(ORDER)}
    end = p.OCCUPIED+p.REQUEST
    c.require(service.calls == 1 and service.occupied ==
              [True]*(end//8)+[False]*((SIZE-end)//8))
    for page in set(ORDER)-{c.DATA_PAGES[0], heap.ARENA, EXTRA}:
        c.require(observed[page] == pages[page])
    old = pages[heap.ARENA]+pages[EXTRA]
    arena = observed[heap.ARENA]+observed[EXTRA]
    allocated = heap.ARENA+p.OCCUPIED
    c.require(old[DESCRIPTOR:DESCRIPTOR+20] == bytes(20))
    expected = bytearray(old)
    key = struct.unpack_from('<I',old,0x1e0)[0]-heap.ARENA
    c.require(0 <= key <= p.OCCUPIED-4 and old[key+3] == 0 and 0 not in old[key:key+3])
    struct.pack_into('<II',expected,p.OCCUPIED,0,1024)
    expected[p.OCCUPIED+8:p.OCCUPIED+12] = old[key:key+4]
    struct.pack_into('<5I',expected,DESCRIPTOR,allocated,0,
                     allocated+p.REQUEST,allocated+12,allocated+12)
    # 26B0 copies the live four-byte key (including NUL) to this empty arena.
    # Remaining new payload, old source descriptor/text, table and node stay exact.
    c.require(arena == expected)
    c.require(after['regs'][7] == regs['esp']+32)
    initial = regs['esp']-c.DATA_PAGES[0]
    c.require(0 <= initial <= 4092)
    c.require(observed[c.DATA_PAGES[0]][initial+4:] == pages[c.DATA_PAGES[0]][initial+4:])


def reject_controls(before, after, service):
    for kind in ('pc', 'cleanup', 'header', 'link', 'end', 'copied-key', 'old-node', 'source', 'slack', 'image'):
        bad = copy.deepcopy(after)
        if kind == 'pc': bad['stop_pc'] ^= 4
        elif kind == 'cleanup': bad['regs'][7] += 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            arena = ORDER.index(heap.ARENA)*4096
            offset = {'header': arena+p.OCCUPIED+4, 'link': arena+p.OCCUPIED,
                      'end': arena+DESCRIPTOR+8, 'copied-key': arena+p.OCCUPIED+8,
                      'old-node': arena+p.node.START,
                      'source': ORDER.index(c.DATA_PAGES[3])*4096,
                      'slack': ORDER.index(EXTRA)*4096+40, 'image': len(raw)-1}[kind]
            raw[offset] ^= 1
            bad['pages'] = raw.hex()
        try: contract(before, bad, service)
        except ValueError: continue
        raise ValueError('Live growth mutation accepted')


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(p.__file__), Path(c.reference.__code__.co_filename),
               Path(b.load_units.__code__.co_filename), Path(heap.__file__)}
    row = dict(schema='ts2-live-growth-subset/1', success=False, stub=False,
        invocation=[sys.executable,*sys.argv], image_sha256=c.IMAGE_SHA,
        source_sha256={str(f):c.digest(f) for f in sources},
        index_sha256={hex(r):c.digest(f) for r,f in indexes.items()},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['Original x86 segmented prefix, explicit two-page portable heap MODEL NOT Windows',
                'New fixture page only; no prior page/ownership mutation, EFLAGS resets 0x202',
                'Exact nonstack pages, empty key-descriptor publication, source-derived four-byte copy, dirty slack and ESP; other GPR/scratch not independently predicted',
                'No fresh lift/native/whole 1AF0/26B0/3700/3C50/1AB665/E3/E4, lifetime/error/retry/flags/FP/PC/transient stores/gameplay'])
    results, visited = [], set()
    try:
        prefix = p.run(indexes, output/'prefix')
        c.require(prefix['success'])
        row['prefix_result_sha256'] = c.digest(output/'prefix/result.json')
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        units = {**p.node.p.UNITS, heap.RVA:(heap.SIZE,heap.COUNT,heap.PIN)}
        nodes, code, row['functions'] = b.load_units(pe, indexes, units)
        wrapper = pe.get_data(heap.WRAPPER,heap.WRAPPER_SIZE)
        _, ns, meta = heap.decode_wrapper(wrapper, lambda i:i)
        row['wrapper_index'] = b.crosscheck_index(json.loads(indexes[heap.WRAPPER].read_text()),meta,heap.WRAPPER)
        nodes.update(ns)
        page = c.BASE+(heap.WRAPPER//4096)*4096
        code.setdefault(page,bytearray(4096))[heap.WRAPPER%4096:heap.WRAPPER%4096+len(wrapper)] = wrapper
        code[heap.SERVICE] = bytes(4096)
        boundaries = json.loads((output/'prefix/boundaries.json').read_text())
        c.require(len(boundaries) == 64)
        start = time.monotonic()
        for n, boundary in enumerate(boundaries):
            before = boundary['after']
            after, seen, service = advance(before,nodes,code)
            results.append(dict(case=n,before=before,after=after))
            visited |= seen
            contract(before,after,service); reject_controls(before,after,service)
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(f)) == sha for f,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row.update(success=True,subset_matches=64,negative_controls_rejected=640,
            arena_bytes=SIZE,request_bytes=p.REQUEST,occupied_before=p.OCCUPIED,
            reference_seconds=time.monotonic()-start,
            coverage={hex(r):dict(visited=sum(c.BASE+r <= pc < c.BASE+r+s for pc in visited),total=count)
                      for r,(s,count,_) in units.items()})
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
    except Exception: parser.exit(1,'Live growth rejected; inspect private receipt.\n')
    print('Live growth ownership subset matched; NOT native/Windows/Android/whole-function.')


if __name__ == '__main__': main()
