#!/usr/bin/env python3
"""Follow caller-owned fresh-table hash/lookup to the next allocation boundary.

Authored checking only. Original x86 states/code stay private; not native proof.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_table_allocation as a
c, b, table = a.c, a.b, a.p.table
STOP = (c.BASE+0x1986, c.BASE+0x83a371)
UNITS = {**a.p.UNITS, **{r: (*table.UNITS[r], table.PINS[r]) for r in (0x1800, 0x17d0)}}


def resume(boundary):
    c.require(boundary['boundary'] == dict(site=a.STOP[0], target=a.STOP[1]))
    c.require(len(boundary['regs']) == 8)
    raw = bytes.fromhex(boundary['pages'])
    order = (*c.DATA_PAGES, *b.IMAGES)
    c.require(len(raw) == 4096*len(order))
    return dict(zip(c.REGS, boundary['regs'])), {
        page: bytearray(raw[i*4096:(i+1)*4096]) for i, page in enumerate(order)}


def contract(before, after):
    """Independent empty-table preservation and pending node request subset."""
    regs, pages = resume(before)
    arena = pages[b.heap.ARENA]
    slots, capacity, count = struct.unpack_from('<3I', arena, 0x160)
    start = sum(b.t.REQUESTS)
    c.require((slots, capacity, count) == (b.heap.ARENA+start, 64, 0))
    c.require(arena[start:start+256] == bytes(256))
    c.require(after['boundary'] == dict(site=STOP[0], target=STOP[1]))
    c.require(len(after['regs']) == 8)
    out = dict(zip(c.REGS, after['regs']))
    raw = bytes.fromhex(after['pages'])
    order = (*c.DATA_PAGES, *b.IMAGES)
    c.require(len(raw) == 4096*len(order))
    c.require(raw[4096:] == bytes.fromhex(before['pages'])[4096:])
    c.require(out['edi'] == regs['edi'] and out['esp'] == regs['esp']-8)
    sp = out['esp']-c.DATA_PAGES[0]
    c.require(0 <= sp <= 4096-8)
    c.require(struct.unpack_from('<II', raw, sp) == (1, 8))
    initial = regs['esp']-c.DATA_PAGES[0]
    c.require(raw[initial:] == bytes.fromhex(before['pages'])[initial:])


def reject_controls(before, after):
    for kind in ('target', 'count', 'width', 'table', 'edi'):
        bad = copy.deepcopy(after)
        if kind == 'target': bad['boundary']['target'] ^= 4
        elif kind == 'edi': bad['regs'][c.REGS.index('edi')] ^= 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            off = (bad['regs'][7]-c.DATA_PAGES[0]+(4 if kind == 'width' else 0)
                   if kind != 'table' else c.DATA_PAGES.index(b.heap.ARENA)*4096+0x160)
            raw[off] ^= 1
            bad['pages'] = raw.hex()
        try: contract(before, bad)
        except ValueError: continue
        raise ValueError('Insertion prefix mutation accepted')


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(a.__file__), Path(table.__file__),
               Path(b.__file__), Path(c.reference.__code__.co_filename),
               Path(b.load_units.__code__.co_filename)}
    row = dict(schema='ts2-table-insertion-prefix/1', success=False, stub=False,
        invocation=[sys.executable, *sys.argv], image_sha256=c.IMAGE_SHA,
        source_sha256={str(p):c.digest(p) for p in sources},
        index_sha256={hex(r):c.digest(p) for r,p in indexes.items()},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False,
        dependencies_newly_resolved=0,
        limits=['Original x86 segmented prefix only, no fresh lift/native execution',
                'Prior portable occupancy/zeroing MODEL, NOT Windows',
                'Exact live GPR/pages across segments; EFLAGS resets 0x202',
                'Fresh empty table only; comparator not necessarily reached',
                'No node allocation response, whole1820/3700/3C50/1AB665, flags/FP/PC/transient stores or gameplay'])
    results, visited = [], set()
    entries = {r: 0 for r in (0x1800, 0x17d0)}
    try:
        # Reproduce upstream ownership, never accept unchecked saved states.
        prefix = a.run(indexes, output/'prefix')
        c.require(prefix['success'])
        row['prefix_result_sha256'] = c.digest(output/'prefix/result.json')
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        pe = pefile.PE(data=image.read_bytes())
        nodes, cp, row['functions'] = b.load_units(pe, indexes, UNITS)
        start = time.monotonic()
        boundaries = json.loads((output/'prefix/boundaries.json').read_text())
        c.require(len(boundaries) == 64)
        for n, boundary in enumerate(boundaries):
            before = boundary['allocation']
            regs, pages = resume(before)
            after, seen = c.reference(nodes, cp, a.STOP[0], regs, pages, budget=512,
                image_pages=b.IMAGES, checked_integer_multiply=True, stop_before_call=STOP)
            results.append(dict(case=n, before=before, after=after))
            visited |= seen
            for r in entries: entries[r] += int(c.BASE+r in seen)
            contract(before, after); reject_controls(before, after)
        c.require(entries == {0x1800: 64, 0x17d0: 0})
        c.require(c.BASE+0x18d8 not in visited)
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(p)) == sha for p,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row.update(success=True, subset_matches=64, negative_controls_rejected=5*64,
            allocation_count=1, allocation_element_bytes=8,
            entry_cases={hex(r):n for r,n in entries.items()},
            growth_allocation_reached=False,
            reference_seconds=time.monotonic()-start,
            original_behaviour_newly_executable=['Caller-owned fresh-table hash/lookup to 1986 node request (x86 only)'],
            coverage={hex(r):dict(visited=sum(c.BASE+r <= pc < c.BASE+r+s for pc in visited), total=count)
                      for r,(s,count,_) in UNITS.items()})
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
    try: run({int(r,16):Path(f) for r,f in json.loads(args.indexes.read_text()).items()}, args.output)
    except Exception: parser.exit(1, 'Insertion prefix rejected; inspect private receipt.\n')
    print('Caller-owned insertion prefix matched; NOT native/Android/whole-function verification.')


if __name__ == '__main__': main()
