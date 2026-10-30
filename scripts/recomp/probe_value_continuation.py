#!/usr/bin/env python3
"""Resume the live 3700 CALL through 1330, caller RET and opener epilogue.

Original x86 segmented execution only; portable occupied-cell heap MODEL, not
Windows. No generated body, native caller, Android or whole-function claim.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_value_assignment as value
c, g = value.c, value.g
ENTRY = value.key.STOP[0]
CALLER_RVA = 0x3700
# The retained return frame belongs to the real 3C50 opener. After 3700's
# RET, five original opener epilogue instructions run before the sentinel RET.
UNITS = {r:g.p.node.p.UNITS[r] for r in (CALLER_RVA,0x3c50)} | value.UNITS


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    c.require(c.digest(value.BOUNDARIES) == value.BOUNDARY_SHA)
    rows = json.loads(value.BOUNDARIES.read_text())
    c.require(len(rows) == 64 and rows[n]['case'] == n)
    before = rows[n]['after']
    c.require(before['boundary'] == dict(site=ENTRY,target=c.BASE+value.ROOT_RVA))
    c.require(len(before['regs']) == 8)
    raw = bytes.fromhex(before['pages'])
    c.require(len(raw) == len(value.PAGES)*4096)
    # No synthetic CALL/sentinel word: execute the actual original CALL next.
    return dict(zip(c.REGS,before['regs'])), {
        p:bytearray(raw[i*4096:(i+1)*4096]) for i,p in enumerate(value.PAGES)}


def advance(regs, pages, nodes, code):
    service = value.model()
    result, seen = c.reference(nodes, code, ENTRY, regs, pages, budget=4096,
        image_pages=value.IMAGES, extra_data_pages=value.EXTRA_PAGES,
        heap_service=service, checked_repeat_copy=True)
    return result, seen, service


def contract(regs, pages, result, service):
    """Independent publication, cursor reset and retained caller/opener frame.

    Predict every nonstack byte from the pending inputs, including dirty slack.
    Scratch stack/volatile registers are not independently predicted. The caller
    restores nonvolatiles from its retained frame, not from the pending GPRs.
    """
    c.require(set(result) == {'regs', 'pages'} and len(result['regs']) == 8)
    sp = regs['esp']-c.DATA_PAGES[0]
    c.require(0 <= sp <= 4096-48 and sp % 4 == 0)
    stack = pages[c.DATA_PAGES[0]]
    obj, node, context, source, head = struct.unpack_from('<5I', stack, sp)
    c.require(obj == value.heap.ARENA and context == 0)
    old = pages[obj]+pages[g.EXTRA]
    word = lambda address: struct.unpack_from('<I', old, address-obj)[0]
    c.require(word(obj+0x1b4) == 0 and word(obj+0x60) == 0)
    start = source-obj
    c.require(0 <= start < value.OCCUPIED)
    end = old.index(0, start)
    c.require(start < end)
    marker = old[0x204]
    text = old[start:end]+(bytes([marker]) if marker else b'')
    c.require(service.calls == 2 and service.requests == [28,24+len(text)])
    units = 4+(24+len(text)+7)//8
    c.require(service.cells == [True]*(value.OCCUPIED//8+units)+
              [False]*((g.SIZE-value.OCCUPIED)//8-units))
    record, payload = obj+value.OCCUPIED, obj+value.OCCUPIED+32
    expected = bytearray(old)
    struct.pack_into('<7I', expected, value.OCCUPIED,
        node,word(head),word(node+4),context,payload,len(text),24+len(text))
    expected[payload-obj:payload-obj+len(text)] = text
    struct.pack_into('<I', expected, node-obj+4, record)
    struct.pack_into('<I', expected, head-obj, record)
    # The caller discards its temporary value, not the separately owned key or
    # newly published value payload. No freeing/reclaiming is modeled here.
    struct.pack_into('<I', expected, 0x1dc, source)
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == len(value.PAGES)*4096)
    observed = {p:raw[i*4096:(i+1)*4096] for i,p in enumerate(value.PAGES)}
    c.require(observed[obj]+observed[g.EXTRA] == expected)
    for page in set(value.PAGES)-{c.DATA_PAGES[0],obj,g.EXTRA}:
        c.require(observed[page] == pages[page])
    out = dict(zip(c.REGS,result['regs']))
    c.require(out['eax'] == obj and out['esp'] == regs['esp']+48)
    for name, offset in (('edi',20),('ebp',24),('ebx',28),('esi',40)):
        c.require(out[name] == struct.unpack_from('<I',stack,sp+offset)[0])
    c.require(struct.unpack_from('<I',stack,sp+44)[0] == c.RETURN)
    c.require(observed[c.DATA_PAGES[0]][sp+48:] == stack[sp+48:])


def reject_controls(regs, pages, result, service):
    kinds = ('return','cleanup','ebx','esi','edi','ebp','cursor','record','payload',
             'node-link','head','owned-key','slack','image','frame')
    sp = regs['esp']-c.DATA_PAGES[0]
    obj,node,_,source,head = struct.unpack_from('<5I',pages[c.DATA_PAGES[0]],sp)
    owned = struct.unpack_from('<I',pages[obj],node-obj)[0]
    for kind in kinds:
        bad = copy.deepcopy(result)
        if kind in ('return','cleanup','ebx','esi','edi','ebp'):
            name = {'return':'eax','cleanup':'esp'}.get(kind,kind)
            bad['regs'][c.REGS.index(name)] ^= 4
        else:
            raw = bytearray.fromhex(bad['pages'])
            # All live object offsets are bounded by the original fixture pages.
            absolute = {'cursor':obj+0x1dc,'record':obj+value.OCCUPIED,
                'payload':obj+value.OCCUPIED+32,'node-link':node+4,
                'head':head,'owned-key':owned,'slack':obj+g.SIZE-1}
            if kind == 'image': offset = len(raw)-1
            elif kind == 'frame': offset = sp+48
            else:
                address = absolute[kind]
                offset = value.PAGES.index(address & ~4095)*4096+(address & 4095)
            raw[offset] ^= 1
            bad['pages'] = raw.hex()
        try: contract(regs,pages,bad,service)
        except ValueError: continue
        raise ValueError('Caller continuation mutation accepted')
    return len(kinds)


def verify_sources(pins):
    """JSON receipt keys are strings; digest deliberately accepts Path only."""
    c.require(all(c.digest(Path(p)) == sha for p,sha in pins.items()))


def run(indexes, output):
    output = c.private_output(output)
    sources = {Path(__file__),Path(value.__file__),Path(g.__file__),
               Path(g.b.__file__),Path(c.reference.__code__.co_filename)}
    row = dict(schema='ts2-live-value-continuation/1',success=False,stub=False,
        invocation=[sys.executable,*sys.argv],image_sha256=c.IMAGE_SHA,
        input_sha256=value.BOUNDARY_SHA,
        source_sha256={str(p):c.digest(p) for p in sources},
        index_sha256={hex(r):c.digest(indexes[r]) for r in UNITS},
        lifted=False,host_native_executed=False,arm64_executed=False,
        android_executed=False,whole_function_verified=False,
        dependencies_newly_resolved=0,
        limits=['Original-x86 segmented continuation BEFORE3861 through3700 RET and3C50 epilogue RET',
                'Original1330 plus occupied-cell portable heap MODEL; NOT Windows',
                'All eight live pages/five arguments retained, real CALL return PC',
                'Independent nonstack bytes/return/ESP/restored frame registers/retention',
                'EFLAGS reset0x202; scratch/volatile/fullflags/FP/PC/transient writes unverified',
                'No native whole3700/3C50/1AB665/E3/E4/Android/gameplay'])
    results,visited,negatives = [],set(),0
    try:
        import pefile
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        nodes,code,row['functions'] = g.b.load_units(
            pefile.PE(data=image.read_bytes()),indexes,UNITS)
        code[value.heap.SERVICE] = bytes(4096)
        start = time.monotonic()
        for n in range(64):
            regs,pages = state(n)
            result,seen,service = advance(regs,pages,nodes,code)
            contract(regs,pages,result,service)
            negatives += reject_controls(regs,pages,result,service)
            results.append(dict(case=n,after=result,service_requests=service.requests))
            visited |= seen
        c.require(sum(c.BASE+CALLER_RVA<=p<c.BASE+CALLER_RVA+UNITS[CALLER_RVA][0]
                      for p in visited) == 19)
        c.require(sum(c.BASE+0x3c50<=p<c.BASE+0x3c50+UNITS[0x3c50][0]
                      for p in visited) == 5)
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(c.digest(value.BOUNDARIES) == value.BOUNDARY_SHA)
        verify_sources(row['source_sha256'])
        c.require(all(c.digest(indexes[int(r,16)]) == sha for r,sha in row['index_sha256'].items()))
        row.update(success=True,subset_matches=64,negative_controls_rejected=negatives,
            reference_seconds=time.monotonic()-start,
            coverage={hex(r):dict(visited=sum(c.BASE+r<=pc<c.BASE+r+s for pc in visited),total=count)
                      for r,(s,count,_) in UNITS.items()},
            original_behaviour_newly_executable=['3700 pending3861 through original1330,3700 RET and3C50 epilogue RET'])
    except Exception as exc:
        row.update(error_type=type(exc).__name__,failed_case=locals().get('n'))
        raise
    finally:
        (output/'states.json').write_text(json.dumps(results)+'\n')
        row['states_sha256'] = c.digest(output/'states.json')
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--indexes',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    try: run({int(r,16):Path(p) for r,p in json.loads(args.indexes.read_text()).items()},args.output)
    except Exception: parser.exit(1,'Caller continuation rejected; inspect private receipt.\n')
    print('Live caller continuation returned64/64; original x86 only, NOT native/Android.')


if __name__ == '__main__': main()
