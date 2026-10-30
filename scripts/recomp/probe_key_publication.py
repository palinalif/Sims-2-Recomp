#!/usr/bin/env python3
"""Check live key ownership before 3700 calls 1330; original-x86 subset only.

The mode grammar is input, not an authored callee response. All original-derived
states remain private. No allocator or 1330 response is supplied in this segment.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe_live_growth as g
c, b = g.c, g.b
STOP = (c.BASE+0x3861, c.BASE+0x1330)


def resume(before):
    c.require(before['stop_pc'] == g.STOP_PC and len(before['regs']) == 8)
    raw = bytes.fromhex(before['pages'])
    c.require(len(raw) == len(g.ORDER)*4096)
    return dict(zip(c.REGS, before['regs'])), {
        page: bytearray(raw[i*4096:(i+1)*4096]) for i, page in enumerate(g.ORDER)}


def advance(before, nodes, code):
    regs, pages = resume(before)
    return c.reference(nodes, code, g.STOP_PC, regs, pages, budget=1024,
        image_pages=b.IMAGES, extra_data_pages=(g.EXTRA,),
        checked_repeat_copy=True, stop_before_call=STOP)


def contract(before, after):
    """Predict owned key publication and temporary value replacement from inputs.

    The descriptor's temporary key is overwritten by the mode's value. The node
    must first acquire the separate capacity allocation's key. Exact nonstack
    pages and pending arguments are checked, not scratch registers or stack.
    """
    regs, pages = resume(before)
    c.require(after['boundary'] == dict(site=STOP[0], target=STOP[1]))
    c.require(len(after['regs']) == 8)
    raw = bytes.fromhex(after['pages'])
    c.require(len(raw) == len(g.ORDER)*4096)
    observed = {page: raw[i*4096:(i+1)*4096] for i,page in enumerate(g.ORDER)}
    for page in set(g.ORDER)-{c.DATA_PAGES[0], g.heap.ARENA, g.EXTRA}:
        c.require(observed[page] == pages[page])
    old = pages[g.heap.ARENA]+pages[g.EXTRA]
    word = lambda offset: struct.unpack_from('<I', old, offset)[0]
    key = word(0x1e0)-g.heap.ARENA
    owned = word(g.DESCRIPTOR)+8
    owned_offset = owned-g.heap.ARENA
    node = g.p.node.START
    c.require(0 <= key <= g.p.OCCUPIED-4 and
              word(0x1dc) == g.heap.ARENA+key+4)
    c.require(word(node) == g.heap.ARENA+key and word(node+4) == 0)
    c.require(owned_offset == g.p.OCCUPIED+8 and
              old[owned_offset:owned_offset+4] == old[key:key+4])
    # This is deliberately a bounded single key=value fixture grammar, not a
    # general parser oracle. Reject malformed modes instead of guessing behavior.
    literal = pages[b.MODE_PAGE][b.MODE_TEXT-b.MODE_PAGE:]
    end = literal.index(0)
    c.require(end >= 4 and literal[3] == ord('=') and 0 not in literal[:3])
    c.require(old[key:key+4] == literal[:3]+b'\0')
    value = literal[4:end+1]
    c.require(key+len(value) <= word(0x1d8)-g.heap.ARENA and
              key+len(value) <= g.p.node.START)
    expected = bytearray(old)
    struct.pack_into('<I', expected, node, owned)
    expected[key:key+len(value)] = value
    struct.pack_into('<I', expected, 0x1dc, g.heap.ARENA+key+len(value))
    c.require(observed[g.heap.ARENA]+observed[g.EXTRA] == expected)
    out = dict(zip(c.REGS, after['regs']))
    c.require(out['esp'] == regs['esp']-20 and out['esi'] == g.heap.ARENA)
    sp, initial = out['esp']-c.DATA_PAGES[0], regs['esp']-c.DATA_PAGES[0]
    c.require(0 <= sp <= 4080 and 0 <= initial <= 4092)
    c.require(struct.unpack_from('<4I', observed[c.DATA_PAGES[0]], sp) ==
              (g.heap.ARENA, g.heap.ARENA+node, 0, g.heap.ARENA+key))
    c.require(observed[c.DATA_PAGES[0]][initial:] == pages[c.DATA_PAGES[0]][initial:])


def reject_controls(before, after):
    kinds = ('site', 'target', 'cleanup', 'receiver', 'key-owner', 'node-link',
             'cursor', 'value', 'owned-copy', 'slack', 'image', 'argument', 'frame')
    for kind in kinds:
        bad = copy.deepcopy(after)
        if kind in ('site', 'target'): bad['boundary'][kind] ^= 4
        elif kind == 'cleanup': bad['regs'][7] += 4
        elif kind == 'receiver': bad['regs'][c.REGS.index('esi')] ^= 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            arena = g.ORDER.index(g.heap.ARENA)*4096
            old = bytes.fromhex(before['pages'])
            key = struct.unpack_from('<I',old,arena+0x1e0)[0]-g.heap.ARENA
            offsets = {'key-owner':arena+g.p.node.START, 'node-link':arena+g.p.node.START+4,
                'cursor':arena+0x1dc, 'value':arena+key,
                'owned-copy':arena+g.p.OCCUPIED+8,
                'slack':g.ORDER.index(g.EXTRA)*4096+128, 'image':len(raw)-1,
                'argument':after['regs'][7]-c.DATA_PAGES[0]+12,
                'frame':before['regs'][7]-c.DATA_PAGES[0]}
            raw[offsets[kind]] ^= 1
            bad['pages'] = raw.hex()
        try: contract(before, bad)
        except ValueError: continue
        raise ValueError('Key publication mutation accepted')
    return len(kinds)


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__), Path(g.__file__), Path(b.__file__),
               Path(c.reference.__code__.co_filename)}
    row = dict(schema='ts2-key-publication-subset/1', success=False, stub=False,
        invocation=[sys.executable,*sys.argv], image_sha256=c.IMAGE_SHA,
        source_sha256={str(f):c.digest(f) for f in sources},
        index_sha256={hex(r):c.digest(f) for r,f in indexes.items()},
        lifted=False, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['Segmented original x86 only; upstream portable heap MODEL NOT Windows',
                'Exact GPR/pages handed off; EFLAGS reset 0x202',
                'Single fixed key=value grammar; nonstack pages/ESP/ESI/arguments/frame independently checked',
                'No 1330 execution or callee response; no new allocation in this segment',
                'No fresh lift/native/full3700/3C50/1AB665/E3/E4; scratch/flags/FP/PC/transient stores/lifetime/errors/gameplay open'])
    results, visited, negatives = [], set(), 0
    try:
        prefix = g.run(indexes, output/'prefix')
        c.require(prefix['success'])
        row['prefix_result_sha256'] = c.digest(output/'prefix/result.json')
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        nodes, code, row['functions'] = b.load_units(
            pefile.PE(data=image.read_bytes()), indexes, g.p.node.p.UNITS)
        boundaries = json.loads((output/'prefix/boundaries.json').read_text())
        c.require(len(boundaries) == 64)
        start = time.monotonic()
        for n, boundary in enumerate(boundaries):
            before = boundary['after']
            after, seen = advance(before, nodes, code)
            results.append(dict(case=n, before=before, after=after))
            visited |= seen
            contract(before, after)
            negatives += reject_controls(before, after)
            c.require(all(c.BASE+0x3700 <= pc < c.BASE+0x3700+582 for pc in seen))
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(Path(f)) == sha for f,sha in row['source_sha256'].items()))
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row.update(success=True, subset_matches=64, negative_controls_rejected=negatives,
            reference_seconds=time.monotonic()-start, visited_sites=len(visited),
            original_behaviour_newly_executable=['37B2 to pending3861: owned key publication then temporary value replacement (x86 subset)'],
            allocation_calls_in_segment=0, pending_target_rva='0x1330')
    except Exception as exc:
        row.update(error_type=type(exc).__name__, failed_case=locals().get('n'))
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
    try: run({int(r,16):Path(f) for r,f in json.loads(args.indexes.read_text()).items()}, args.output)
    except Exception: parser.exit(1,'Key publication rejected; inspect private receipt.\n')
    print('Live key ownership subset matched; NOT native/Android/whole-function.')


if __name__ == '__main__': main()
