#!/usr/bin/env python3
"""Private original tail prefix/helper reference, stopping BEFORE continuation.

No translation, exception dispatch, runtime binding or recovered-PE launch.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_startup_dependency import (require, exercise, GPRS, STACK, MASK,
    ENTRY, DEPENDENCY, inspect_body, crosscheck_index, ROOT, IMAGE_SHA, digest, BASE)
from inspect_startup_dependency import first_direct_call, CALLER_BOUND
from measure_startup import TAIL_RVA


def run(output, index):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    if output.exists():
        raise FileExistsError('Exclusive private output required')
    start = time.monotonic()
    image = ROOT/'work/interop-legacy-002/analysis-image.bin'
    require(digest(image) == IMAGE_SHA)
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
    caller = pe.get_data(TAIL_RVA, CALLER_BOUND)
    require(len(caller) == CALLER_BOUND)
    site, target = first_direct_call(caller, BASE+TAIL_RVA)
    require(target == ENTRY)
    # A single five-byte rel32 call is the final admitted prefix instruction.
    prefix = caller[:site-(BASE+TAIL_RVA)+5]
    helper = pe.get_data(DEPENDENCY, 128)
    body = inspect_body(helper, ENTRY)
    indexed = crosscheck_index(json.loads(index.read_text()), body)
    code = helper[:body['size_bytes']]
    rng = random.Random(11818721)
    deltas, publications = set(), 0
    for n in range(64):
        regs = {r: rng.getrandbits(32) for r in GPRS}
        regs['esp'] = STACK+(0x800, 0xC00)[(n//2) % 2]
        stack = bytearray([0xA5]*4096)
        # Inert caller return canary; the tail is NOT treated as returning.
        struct.pack_into('<I', stack, regs['esp']-STACK, 0x71000000)
        fs = (0x74000000, 0x75000000)[n % 2]
        chain = (MASK, 0x76000100)[(n//4) % 2]
        result = exercise(code, regs, stack, fs, chain,
            (0, MASK, 0xBB40E64E, 0x12345678)[(n//8) % 4],
            prefix=prefix, prefix_entry=BASE+TAIL_RVA)
        require(result.pc == BASE+TAIL_RVA+len(prefix))
        # The independent model compares the full page; explicitly retain the
        # caller's original return word rather than mistaking it for this RET.
        require(result.read(regs['esp']) == 0x71000000)
        deltas.add(result.regs['esp']-regs['esp'])
        head = result.read(fs)
        publications += int(head != chain and STACK <= head <= STACK+4092)
    require(digest(image) == IMAGE_SHA)
    row = dict(schema='ts2-startup-prefix-reference/1', image_sha256=IMAGE_SHA,
        tail_rva=hex(TAIL_RVA), call_site_rva=hex(site-BASE),
        dependency_rva=hex(DEPENDENCY), continuation_rva=hex(TAIL_RVA+len(prefix)),
        prefix_bytes=len(prefix), helper_bytes=len(code), cases=64,
        per_instruction_comparison=True, caller_oracle='independent raw-byte immediate-PUSH/rel32-CALL decoder',
        compared=['eight GPRs', 'PC', 'full stack/FS/cookie pages',
                  'immutable code/GDT/return pages', 'original caller return word'],
        distinct_stack_deltas=len(deltas), stack_delta_min_bytes=min(deltas),
        stack_delta_max_bytes=max(deltas), fs_stack_publication_cases=publications,
        index=indexed, elapsed_seconds=time.monotonic()-start,
        invocation=[sys.executable, *sys.argv], selected_for_translation=False,
        lifted=False, native_executed=False, continuation_executed=False,
        limits=['synthetic tail entry, NOT full startup reachability or complete tail ABI',
                'helper model still shares Capstone decoding with its access guard',
                'no flags/FP/SIMD, SEH dispatch/unwind or continuation execution',
                'synthetic page slack, not a full original PE memory map',
                'reference cost, NOT translation throughput; no AArch64 execution'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(row, stream, indent=2)
        stream.write('\n')
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    try:
        run(args.output, args.index)
    except Exception:
        print('Prefix reference rejected; no native verification claimed', file=sys.stderr)
        return 1
    print('Bounded original prefix/helper reference matched; continuation NOT executed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
