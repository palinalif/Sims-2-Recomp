#!/usr/bin/env python3
"""Execute the live first-node request and linkage, with portable heap MODEL.

Original x86 only; no native, Windows, whole-function or Android claim.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_table_insertion as p
c, b, a = p.c, p.b, p.a
calloc = a.calloc
STOP = (c.BASE+0x37ad, c.BASE+0x26b0)
ORDER = (*c.DATA_PAGES, *b.IMAGES)
START = sum(b.t.REQUESTS)+256


def resume(boundary):
    c.require(boundary['boundary'] == dict(site=p.STOP[0], target=p.STOP[1]))
    c.require(len(boundary['regs']) == 8)
    raw = bytes.fromhex(boundary['pages'])
    c.require(len(raw) == len(ORDER)*4096)
    return dict(zip(c.REGS, boundary['regs'])), {
        page: bytearray(raw[i*4096:(i+1)*4096]) for i, page in enumerate(ORDER)}


def model():
    """Reconstitute checked prior occupancy, not an invented allocator result."""
    service = calloc.ZeroModel(8)
    c.require(START % 8 == 0 and START+8 <= 4096)
    service.occupied[:START//8] = [True]*(START//8)
    return service


def advance(before, nodes, code_pages):
    regs, pages = resume(before)
    service = model()
    # The hash segment is already complete. Enabling its three-operand IMUL
    # check here would incorrectly also constrain calloc's two-operand form.
    after, seen = c.reference(nodes, code_pages, p.STOP[0], regs, pages, budget=512,
        image_pages=b.IMAGES, heap_service=service, checked_calloc_arithmetic=True,
        stop_before_call=STOP)
    return after, seen, service


def contract(before, after, service):
    """Independent single-key topology/ownership subset; no hash-index oracle."""
    regs, pages = resume(before)
    old = pages[b.heap.ARENA]
    slots, capacity, count = struct.unpack_from('<3I', old, 0x160)
    c.require((slots, capacity, count) == (b.heap.ARENA+sum(b.t.REQUESTS), 64, 0))
    c.require(old[sum(b.t.REQUESTS):START] == bytes(256))
    sp = regs['esp']-c.DATA_PAGES[0]
    c.require(0 <= sp <= 4088 and struct.unpack_from('<II', pages[c.DATA_PAGES[0]], sp) == (1, 8))
    c.require(after['boundary'] == dict(site=STOP[0], target=STOP[1]))
    c.require(len(after['regs']) == 8)
    raw = bytes.fromhex(after['pages'])
    c.require(len(raw) == len(ORDER)*4096)
    observed = {page: raw[i*4096:(i+1)*4096] for i, page in enumerate(ORDER)}
    c.require(service.calls == 1 and service.occupied == [True]*((START+8)//8)+[False]*((4096-START-8)//8))
    for page in set(ORDER)-{c.DATA_PAGES[0], b.heap.ARENA}:
        c.require(observed[page] == pages[page])
    arena = observed[b.heap.ARENA]
    expected = bytearray(old)
    struct.pack_into('<I', expected, 0x168, 1)
    key = struct.unpack_from('<I', old, 0x1e0)[0]
    struct.pack_into('<II', expected, START, key, 0)
    buckets = struct.unpack_from('<64I', arena, sum(b.t.REQUESTS))
    c.require(buckets.count(b.heap.ARENA+START) == 1 and buckets.count(0) == 63)
    expected[sum(b.t.REQUESTS):START] = arena[sum(b.t.REQUESTS):START]
    c.require(arena == expected)


def reject_controls(before, after, service):
    for kind in ('target', 'count', 'key', 'link', 'bucket', 'slack', 'immutable'):
        bad = copy.deepcopy(after)
        if kind == 'target': bad['boundary']['target'] ^= 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            off = {'count': 0x168, 'key': START, 'link': START+4,
                   'bucket': sum(b.t.REQUESTS), 'slack': START+8}.get(kind)
            index = ORDER.index(b.heap.ARENA)*4096+off if off is not None else len(raw)-1
            raw[index] ^= 1
            bad['pages'] = raw.hex()
        try: contract(before, bad, service)
        except ValueError: continue
        raise ValueError('Node composition mutation accepted')


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(p.__file__), Path(a.__file__), Path(calloc.__file__),
               Path(b.__file__), Path(c.reference.__code__.co_filename),
               Path(b.load_units.__code__.co_filename), Path(b.heap.__file__)}
    row = dict(schema='ts2-table-node-prefix/1', success=False, stub=False,
        invocation=[sys.executable, *sys.argv], image_sha256=c.IMAGE_SHA,
        source_sha256={str(f): c.digest(f) for f in sources},
        index_sha256={hex(r): c.digest(f) for r, f in indexes.items()},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['Original x86 segmented prefix; no fresh lift or native execution',
                'Portable occupancy/zeroing MODEL, NOT Windows; exact GPR/pages, EFLAGS resets 0x202',
                'Single-key topology subset only; bucket index and final GPR/stack scratch not independently predicted',
                'No full1820/3700/3C50/1AB665, growth/error/retry/lifetime, flags/FP/PC/transient stores or gameplay'])
    results, visited = [], set()
    try:
        prefix = p.run(indexes, output/'prefix')
        c.require(prefix['success'])
        row['prefix_result_sha256'] = c.digest(output/'prefix/result.json')
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        units = {**p.UNITS, calloc.RVA: (calloc.SIZE, calloc.COUNT, calloc.PIN)}
        nodes, cp, row['functions'] = b.load_units(pe, indexes, units)
        code = pe.get_data(calloc.WRAPPER, calloc.WRAPPER_SIZE)
        _, ns, metadata = b.heap.decode_wrapper(code, lambda i: i, rva=calloc.WRAPPER,
            size=calloc.WRAPPER_SIZE, count=calloc.WRAPPER_COUNT,
            pin=calloc.WRAPPER_PIN, target=calloc.RVA)
        row['wrapper_index'] = b.crosscheck_index(json.loads(indexes[calloc.WRAPPER].read_text()), metadata, calloc.WRAPPER)
        nodes.update(ns)
        page = c.BASE+(calloc.WRAPPER//4096)*4096
        cp.setdefault(page, bytearray(4096))[calloc.WRAPPER%4096:calloc.WRAPPER%4096+len(code)] = code
        boundaries = json.loads((output/'prefix/boundaries.json').read_text())
        c.require(len(boundaries) == 64)
        start = time.monotonic()
        for n, boundary in enumerate(boundaries):
            before = boundary['after']
            after, seen, service = advance(before, nodes, cp)
            results.append(dict(case=n, before=before, after=after))
            visited |= seen
            contract(before, after, service); reject_controls(before, after, service)
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(f)) == sha for f, sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r, sha in row['index_sha256'].items()))
        row.update(success=True, subset_matches=64, negative_controls_rejected=7*64,
            original_behaviour_newly_executable=['Live first-node calloc/linkage/count through next 37AD capacity request (x86 only)'],
            reference_seconds=time.monotonic()-start,
            coverage={hex(r): dict(visited=sum(c.BASE+r <= pc < c.BASE+r+s for pc in visited), total=count)
                      for r, (s, count, _) in units.items()})
    except Exception as exc:
        row.update(error_type=type(exc).__name__, failed_case=locals().get('n'))
        raise
    finally:
        (output/'boundaries.json').write_text(json.dumps(results)+'\n')
        row['boundaries_sha256'] = c.digest(output/'boundaries.json')
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indexes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try: run({int(r,16): Path(f) for r, f in json.loads(args.indexes.read_text()).items()}, args.output)
    except Exception: parser.exit(1, 'Node composition rejected; inspect private receipt.\n')
    print('Live node subset matched; NOT native/Android/whole-function verification.')


if __name__ == '__main__': main()
