#!/usr/bin/env python3
"""Campaign F1: inspect one allocator window; never traverse targets or execute.

Only metadata/counts/addresses leave the decoder. The fixed 0x400-byte window
is an authorization bound, not a claim that the allocator closure fits inside it.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, dependencies
from inspect_startup_dependency import inspect_body

RVA = 0x8461F2
BOUND = 0x400


def inventory(code, pe):
    if not 0 < len(code) <= BOUND:
        raise ValueError('Allocator window exceeds scope')
    # Complete normal-flow decoding or hard failure; no branch/call target reads.
    body = inspect_body(code, BASE + RVA)
    from measure_startup import decode_flow
    _, nodes, _, _ = decode_flow(code, BASE + RVA, lambda i: i)
    return dict(body=body, dependencies=dependencies(nodes, pe),
                targets_followed=False, abi_established=False)


def check_index(envelope, body):
    """Compare the capped indexed linear prefix, never call it full ownership."""
    p, r = envelope['provenance'], envelope['result']
    if (envelope['schema'] != 'sims2-ghidra-query-envelope/1' or
            p['sourceImageSha256'] != IMAGE_SHA or p['mode'] != 'readOnly' or
            p['analysisPerformed'] is not False or p['headlessExitCode'] != 0 or
            p['outputParseError'] is not None or
            int(r['query']['rva'], 16) != RVA or
            int(r['program']['imageBaseVa'], 16) != BASE or
            r['function']['resolution'] != 'function-at' or
            int(r['function']['entryRva'], 16) != RVA):
        raise ValueError('Index provenance mismatch')
    dis = r['function']['disassembly']
    addresses = [hex(int(i['rva'], 16)) for i in dis['items']]
    if not addresses or addresses != body['instruction_rvas'][:len(addresses)]:
        raise ValueError('Indexed prefix boundary mismatch')
    return dict(prefix_boundaries_agree=True, compared_instructions=len(addresses),
                complete_boundary_agreement=(len(addresses) == body['instructions']
                    and not r['truncation']['instructions']),
                operand_semantics_compared=False, truncation=r['truncation'],
                log_signals=envelope['queryLogSignals'], ghidra_version=p['ghidraVersion'])


def inspect(index, output):
    output = output.resolve()
    if not output.is_relative_to((ROOT / 'work/recomp-bench').resolve()):
        raise ValueError('Private output required')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    image = ROOT / 'work/interop-legacy-002/analysis-image.bin'
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image pin mismatch')
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    if pe.OPTIONAL_HEADER.ImageBase != BASE or pe.FILE_HEADER.Machine != 0x14c:
        raise ValueError('Wrong image mapping')
    code = pe.get_data(RVA, BOUND)
    if len(code) != BOUND:
        raise ValueError('Short allocator window')
    report = inventory(code, pe)
    report.update(schema='ts2-allocator-boundary/1', rva=hex(RVA),
        image_sha256=IMAGE_SHA, window_bytes=BOUND, harness_sha256=digest(Path(__file__)),
        index_sha256=digest(index), index=check_index(json.loads(index.read_text()), report['body']),
        invocation=[sys.executable, *sys.argv], lifted=False, host_executed=False,
        arm64_executed=False, android_executed=False,
        limits=['HYPOTHESIS: normal-return flow; call effects and feasibility unmodeled',
                'No targets followed, heap semantics, reference execution or runtime binding',
                'Absolute memory operands are addresses, not established global contracts',
                'RET immediate is not a proven net stack/ABI contract'])
    if digest(image) != IMAGE_SHA:
        raise ValueError('Image changed')
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        inspect(a.index, a.output)
    except Exception:
        p.exit(1, 'Bounded allocator inspection failed; no execution claim.\n')
    print('One allocator window inspected; targets not followed; ABI unverified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
