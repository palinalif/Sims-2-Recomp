#!/usr/bin/env python3
"""Measure existing startup-pair memory requirements, NOT runtime integration.

Original x86 executes only in the bounded development reference. No new lift,
selection, protection operation, PE execution or Android/native binding.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reference_startup import (BASE, COOKIE, COMPLEMENT, DATA, INIT, HELPER, SLOTS,
    DEFAULT, cases, oracle, exercise, verify_state, require, run as reference_run)
from measure_leaf import ROOT, IMAGE_SHA


def check_accesses(case, accesses):
    """Independent writable scope, including same-value/implicit stores.

    Reject unknown access classes, IAT/code writes, page slack and wraparound.
    This is a necessary footprint contract, not a complete instruction oracle.
    """
    sp, stack = case['sp'], case['stack']
    used = case['cookie'] == DEFAULT or case['cookie'] < 0x10000
    writes = set()
    for kind, address, size in accesses:
        require(kind in ('read', 'write', 'endpoint-write') and
                type(address) is int and type(size) is int and
                0 <= address < 2**32 and size in (4, 8) and address+size <= 2**32)
        if kind == 'read':
            require((stack <= address and address+size <= stack+4096) or
                    (address in (COOKIE, COMPLEMENT, *(BASE+s for s in SLOTS)) and size == 4))
        else:
            require((sp-(44 if used else 8) <= address and address+size <= sp) or
                    (kind == 'write' and size == 4 and
                     address in ((COOKIE, COMPLEMENT) if used else (COMPLEMENT,))))
            if kind == 'endpoint-write':
                require(used and size == 8 and address in (sp-28, sp-36))
            writes.update(range(address, address+size))
    # Both paths publish complement; initialization also publishes the cookie.
    expected_globals = set(range(COMPLEMENT, COMPLEMENT+4))
    if used:
        expected_globals.update(range(COOKIE, COOKIE+4))
    require({a for a in writes if a >= BASE} == expected_globals)
    require(set(range(sp-8, sp)) <= writes)
    return dict(helper_invoked=used, write_bytes=len(writes),
                stack_write_bytes=sum(stack <= a < stack+4096 for a in writes),
                global_write_bytes=len(expected_globals),
                accesses=len(accesses))


def run(output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    row = dict(schema='ts2-startup-memory-assessment/1', success=False,
               native_integrated=False, android_executed=False, new_functions=0,
               cases=0, timings={}, limits=[
                   'decoded explicit operands and selected implicit stack operations only',
                   'authored endpoints, not Windows; no general instruction access tracer',
                   'reference state components unchanged: no final flags/ECX/EDX/FP/SIMD',
                   'no persistent native startup execution, writable bridge or IAT binding'])
    try:
        start = time.monotonic()
        # Reuse all existing image/index/import checks, x86/oracle and negative controls.
        ref = reference_run(output/'reference')
        row['reference_success'] = ref['success']
        row['timings']['existing_reference'] = time.monotonic()-start
        import pefile
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        raw = image.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == IMAGE_SHA)
        pe = pefile.PE(data=raw)
        extent = BASE+pe.OPTIONAL_HEADER.SizeOfImage
        require(all(not (c['stack'] < extent and c['stack']+4096 > BASE) for c in cases()))
        codes = {INIT: pe.get_data(INIT-BASE,75), HELPER: pe.get_data(HELPER-BASE,77)}
        results, traces = [], []
        start = time.monotonic()
        for case in cases():
            journal = []
            actual = exercise(codes, case, accesses=journal)
            verify_state(actual, oracle(case))
            results.append(check_accesses(case, journal))
            traces.append(journal)
            row['cases'] += 1
        row['timings']['journal_x86_and_oracle'] = time.monotonic()-start
        # Raw addresses/access order remain private, never committed.
        (output/'accesses.json').write_text(json.dumps(traces)+'\n')
        (output/'cases.json').write_text(json.dumps(results)+'\n')
        row.update(helper_invoked=sum(r['helper_invoked'] for r in results),
                   helper_bypassed=sum(not r['helper_invoked'] for r in results),
                   max_stack_write_bytes=max(r['stack_write_bytes'] for r in results),
                   global_write_bytes=sorted({r['global_write_bytes'] for r in results}),
                   non_image_stacks=True, image_sha256=IMAGE_SHA,
                   required_global_rvas=[hex(COOKIE-BASE),hex(COMPLEMENT-BASE)],
                   iat_slot_rvas=[hex(s) for s in SLOTS],
                   requirements=['checked stack reads and writes outside image',
                       'two exact writable mapped globals, without fixture page overwrite',
                       'four exact read-only IAT slots with explicit authored endpoint binding',
                       'nested compiled call and decoded return-address ABI',
                       'explicit entry/exit transport and single-owner lifetime'],
                   success=True)
        require(hashlib.sha256(image.read_bytes()).hexdigest() == IMAGE_SHA)
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    try:
        result = run(args.output)
    except Exception:
        parser.exit(1,'Startup memory assessment failed; inspect private report.\n')
    print('Startup memory requirements: %d x86/oracle cases; native integration NOT established' % result['cases'])
