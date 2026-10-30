#!/usr/bin/env python3
"""Measure live post-insertion capacity request, without inventing heap space.

Original-x86 segmented prefix only. All original-derived states stay private.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_table_node as node
c, b = node.c, node.b
STOP = (c.BASE+0x1c00, c.BASE+0x831a6f)
REQUEST = 1032
OCCUPIED = node.START+8
FREE = 4096-OCCUPIED


def resume(boundary):
    c.require(boundary['boundary'] == dict(site=node.STOP[0], target=node.STOP[1]))
    c.require(len(boundary['regs']) == 8)
    raw = bytes.fromhex(boundary['pages'])
    c.require(len(raw) == len(node.ORDER)*4096)
    return dict(zip(c.REGS, boundary['regs'])), {
        page: bytearray(raw[i*4096:(i+1)*4096]) for i, page in enumerate(node.ORDER)}


def advance(before, nodes, code_pages):
    regs, pages = resume(before)
    # No service response: stop before the original allocator wrapper CALL.
    return c.reference(nodes, code_pages, node.STOP[0], regs, pages, budget=512,
        image_pages=b.IMAGES, stop_before_call=STOP)


def contract(before, after):
    """Independent pending-request/preservation subset, not successful growth."""
    regs, pages = resume(before)
    arena = pages[b.heap.ARENA]
    c.require(struct.unpack_from('<3I', arena, 0x160) ==
              (b.heap.ARENA+sum(b.t.REQUESTS), 64, 1))
    key = struct.unpack_from('<I', arena, 0x1e0)[0]
    c.require(struct.unpack_from('<II', arena, node.START) == (key, 0))
    buckets = struct.unpack_from('<64I', arena, sum(b.t.REQUESTS))
    c.require(buckets.count(b.heap.ARENA+node.START) == 1 and buckets.count(0) == 63)
    c.require(after['boundary'] == dict(site=STOP[0], target=STOP[1]))
    c.require(len(after['regs']) == 8)
    raw = bytes.fromhex(after['pages'])
    c.require(len(raw) == len(node.ORDER)*4096)
    c.require(raw[4096:] == bytes.fromhex(before['pages'])[4096:])
    out = dict(zip(c.REGS, after['regs']))
    c.require(out['esp'] == regs['esp']-32)
    sp = out['esp']-c.DATA_PAGES[0]
    initial = regs['esp']-c.DATA_PAGES[0]
    c.require(0 <= sp <= 4092 and 0 <= initial <= 4092)
    c.require(struct.unpack_from('<I', raw, sp)[0] == REQUEST)
    c.require(raw[initial:4096] == bytes.fromhex(before['pages'])[initial:4096])


def exhaustion_model():
    """Reuse independent occupancy algorithm; no invented larger guest arena."""
    service = b.heap.HeapModel(REQUEST)
    service.occupied[:OCCUPIED//8] = [True]*(OCCUPIED//8)
    c.require(OCCUPIED % 8 == 0 and REQUEST > FREE)
    count = (REQUEST+7)//8
    c.require(not any(not any(service.occupied[i:i+count]) for i in range(513-count)))
    return service


def reject_controls(before, after):
    for kind in ('site', 'target', 'size', 'cleanup', 'table', 'immutable', 'frame'):
        bad = copy.deepcopy(after)
        if kind in ('site', 'target'): bad['boundary'][kind] ^= 4
        elif kind == 'cleanup': bad['regs'][7] += 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            off = {'size': after['regs'][7]-c.DATA_PAGES[0],
                   'table': node.ORDER.index(b.heap.ARENA)*4096+0x168,
                   'immutable': len(raw)-1,
                   'frame': before['regs'][7]-c.DATA_PAGES[0]}[kind]
            raw[off] ^= 1
            bad['pages'] = raw.hex()
        try: contract(before, bad)
        except ValueError: continue
        raise ValueError('Capacity-boundary mutation accepted')


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(node.__file__), Path(b.__file__),
               Path(c.reference.__code__.co_filename), Path(b.heap.__file__),
               Path(b.load_units.__code__.co_filename)}
    row = dict(schema='ts2-live-capacity-boundary/1', success=False, stub=False,
        invocation=[sys.executable, *sys.argv], image_sha256=c.IMAGE_SHA,
        source_sha256={str(f): c.digest(f) for f in sources},
        index_sha256={hex(r): c.digest(f) for r, f in indexes.items()},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['Original x86 segmented prefix; no fresh lift/native execution',
                'No allocator response in new segment; prior portable heap MODEL is NOT Windows',
                'Exact GPR/pages cross segments; EFLAGS resets 0x202',
                'Pending request/preserved non-stack/frame subset only; volatile GPR/stack scratch not independently predicted',
                'Model exhaustion is fixture capacity, NOT original Windows OOM or successful growth',
                'No full 26B0/1AF0/3700/3C50/1AB665, lifetime/flags/FP/PC/transient stores/gameplay'])
    results, visited = [], set()
    try:
        prefix = node.run(indexes, output/'prefix')
        c.require(prefix['success'])
        row['prefix_result_sha256'] = c.digest(output/'prefix/result.json')
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        nodes, cp, row['functions'] = b.load_units(pefile.PE(data=image.read_bytes()), indexes, node.p.UNITS)
        boundaries = json.loads((output/'prefix/boundaries.json').read_text())
        c.require(len(boundaries) == 64)
        start = time.monotonic()
        for n, boundary in enumerate(boundaries):
            before = boundary['after']
            after, seen = advance(before, nodes, cp)
            results.append(dict(case=n, before=before, after=after))
            visited |= seen
            contract(before, after); reject_controls(before, after)
            c.require(all(c.BASE+r in seen for r in (0x26b0, 0x1af0)))
            c.require(c.BASE+b.heap.RVA not in seen)
        exhaustion_model()
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(f)) == sha for f, sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r, sha in row['index_sha256'].items()))
        row.update(success=True, subset_matches=64, negative_controls_rejected=7*64,
            reference_seconds=time.monotonic()-start, request_bytes=REQUEST,
            occupied_bytes=OCCUPIED, free_tail_bytes=FREE, fixture_shortfall_bytes=REQUEST-FREE,
            portable_model_has_fitting_span=False, allocator_response_supplied=False,
            original_behaviour_newly_executable=['Live 37AD capacity path to original 1C00 allocation request (x86 only)'],
            coverage={hex(r): dict(visited=sum(c.BASE+r <= pc < c.BASE+r+s for pc in visited), total=count)
                      for r, (s, count, _) in node.p.UNITS.items()})
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
    except Exception: parser.exit(1, 'Live capacity boundary rejected; inspect private receipt.\n')
    print('Live capacity request measured; one-page fixture exhausted, NOT native/Windows/Android.')


if __name__ == '__main__': main()
