#!/usr/bin/env python3
"""Whole pinned lift of 0x1AB665, ONLY the zero-+0x1C no-open return E3 fragment.

This gives the AL=0 early-return arm (populated-handle +0x34 clear AND +0x1C
clear) its first host and Linux/AArch64 native differential against bounded
original-x86 reference execution. The settled guard fragment
(execute_initialization_guard.py) proves only the +0x34-populated AL=1 arm; it
branches at 0x1ab66e before the +0x1C gate, so the arm exercised here is
genuinely distinct. Reuses that fragment's lift/bridge/transport verbatim so the
whole-body lifted source, callee address set and GuestMemory/exact-VA bridge are
the same point of truth. No opener, service, callback or other callee executes.
Private artifacts only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspect_classifier_paths as probe
# Reuse the settled guard fragment's transport assembly verbatim (same whole-body
# lift of 0x1AB665, same single-target bridge). Only state() and oracle() differ.
import execute_initialization_guard as guard
from inspect_initialization_graph import seed_receipt
from measure_startup import decode_flow, dependencies
c = probe.c
RVA, SIZE = guard.RVA, guard.SIZE
FUNCTION_SHA = guard.FUNCTION_SHA
# Original-x86 reference path for the no-open arm: entry pushes, both gates clear,
# return AL=0, callee-saved pops and ret. Distinct from the guard's GUARD_PATH
# (which diverts at 0x1ab66e to 0x1ab766 for the AL=1 arm).
NO_OPEN_PATH = (0x1ab665, 0x1ab666, 0x1ab668, 0x1ab669, 0x1ab66b, 0x1ab66e,
                0x1ab674, 0x1ab677, 0x1ab76c, 0x1ab76e, 0x1ab769, 0x1ab76a,
                0x1ab76b)
MODES = ('valid', 'wrong-result', 'wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random((RVA << 8) + n + 0x0e)
    regs = {r: rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0] + (0x800 if n % 2 else 0xc00)
    regs['ecx'] = c.DATA_PAGES[1] + (0x80 if n % 2 else 0xe00)
    pages = {p: bytearray(rng.randbytes(4096)) for p in probe.PAGES}
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], regs['esp'] - c.DATA_PAGES[0],
                     c.RETURN)
    off = regs['ecx'] - c.DATA_PAGES[1]
    # The no-open arm needs BOTH the populated-handle slot clear AND the +0x1C
    # gate clear; any other receiver bytes are opaque data the arm never reads.
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off + 0x34, 0)
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off + 0x1c, 0)
    # Retain nontrivial upper EAX and guarantee a visible AL write (AL starts 0xff
    # on half the cases so the zeroing is observable in the differential).
    regs['eax'] = (rng.getrandbits(24) << 8) | (0xff if n % 2 else 0x00)
    return regs, pages


def oracle(regs, pages):
    obj, sp = regs['ecx'], regs['esp']
    c.require(set(regs) == set(c.REGS) and set(pages) == set(probe.PAGES))
    c.require(c.DATA_PAGES[1] <= obj <= c.DATA_PAGES[1] + 4096 - 0x38 and obj % 4 == 0)
    c.require(sp in (c.DATA_PAGES[0] + 0x800, c.DATA_PAGES[0] + 0xc00))
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[0]],
                                 sp - c.DATA_PAGES[0])[0] == c.RETURN)
    # Both gates clear: this is the no-open arm, not the +0x34-populated arm.
    off = obj - c.DATA_PAGES[1]
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[1]], off + 0x34)[0] == 0)
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[1]], off + 0x1c)[0] == 0)
    after = {p: bytearray(b) for p, b in pages.items()}
    # Entry pushes callee-saved edi/esi below the frame; the epilogue pops restore
    # the register values but leave the two written words in memory.
    struct.pack_into('<II', after[c.DATA_PAGES[0]], sp - c.DATA_PAGES[0] - 8,
                     regs['edi'], regs['esi'])
    out = dict(regs, eax=(regs['eax'] & 0xffffff00), esp=sp + 4)
    return dict(regs=[out[r] for r in c.REGS],
                pages=b''.join(after[p] for p in probe.PAGES).hex())


def run(output):
    output = c.private_output(output)
    row = dict(schema='ts2-initialization-no-open-native/1', success=False,
        rva=hex(RVA), size=SIZE, image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)), probe_sha256=c.digest(Path(probe.__file__)),
        helper_sha256=c.digest(Path(c.__file__)), guard_sha256=c.digest(Path(guard.__file__)),
        template_sha256=c.digest(c.TEMPLATE), bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable, *sys.argv], commands=[], runs={}, timings={},
        lifted=False, host_executed=False, arm64_executed=False, android_executed=False,
        stub=False, whole_function_verified=False, e3_fragment=True, e3_complete=False,
        e4_complete=False,
        arm='zero-+0x1C no-open return AL=0 (distinct from the settled +0x34 AL=1 guard)',
        compared=['eight final GPRs including ESP',
                  'six complete 4096-byte pages including retained saved-register words'],
        limits=['ONLY receiver+0x34 clear AND receiver+0x1C clear no-open return path; '
                'no opener or other callee execution',
                'Authored bounded receiver with both gates clear, not producer/input/'
                'lifetime/callback ownership proof',
                'No flags/FP/PC/native transient-write comparison',
                'Diagnostic GuestMemory/exact-VA bridge, not production integration or Android'])

    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err,
                                   cwd=c.ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    stage = 'preflight'
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        row['seed'] = seed_receipt(c.ROOT/'work/recomp-bench/frontier-d3-sibling-final/result.json')
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        c.require(all(c.digest(upstream/n) == c.digest(pristine/n) for n in used))
        row['upstream_files'] = {n: c.digest(upstream/n) for n in used}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0, str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() ==
                  (upstream/'tools/lift/lift32.py').resolve())
        stage = 'fresh-lift'; start = time.monotonic()
        code = pe.get_data(RVA, SIZE)
        c.require(hashlib.sha256(code).hexdigest() == FUNCTION_SHA)
        function, nodes, _, _ = decode_flow(code, c.BASE+RVA, LinearInstruction)
        c.require(len(nodes) == 83)
        deps = dependencies(nodes, pe)
        guard.check_dependencies(deps, row['seed'])
        function.name = 'initialization_guard_1AB665'
        body = Lifter(precise_carry=True).lift_function(function)
        c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
        (output/'lifted.c').write_text(body)
        row.update(lifted=True, function_sha256=FUNCTION_SHA, dependencies=deps,
            lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',
                                 address=hex(c.BASE+RVA), name=function.name))
        row['timings']['translation'] = time.monotonic()-start
        stage = 'original-reference'; start = time.monotonic()
        code_pages = {c.BASE+0x1ab000: bytearray(4096)}
        code_pages[c.BASE+0x1ab000][0x665:0x665+SIZE] = code
        expected, inputs = [], bytearray()
        for n in range(64):
            regs, pages = state(n)
            result = probe.trace(nodes, code_pages, c.BASE+RVA, regs, pages)
            c.require(result['outcome'] == 'returned' and
                      result['visited'] == [c.BASE+a for a in NO_OPEN_PATH])
            observed = {k: result[k] for k in ('regs', 'pages')}
            c.require(observed == oracle(regs, pages))
            expected.append(dict(case=n, **observed))
            inputs.extend(struct.pack('<8I', *(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in probe.PAGES))
        row.update(x86_oracle_matches=64, coverage=dict(visited=len(NO_OPEN_PATH),
                   total=83, callee_calls=0, arm='no-open-AL0'))
        row['timings']['reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'
        transport.write_text(guard.assemble(body, deps['direct_calls']))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(guard.bridge_source(mode))
            for isa in ('host', 'arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile', ['zig-cxx',
                    *([] if isa == 'host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0',
                    '-I'+str(upstream/'runtime/recomp32'), '-I'+str(c.ROOT/'native/include'),
                    transport, bridge, c.ROOT/'native/src/guest_memory.cpp',
                    c.ROOT/'native/src/guest_dispatch.cpp','-lm','-o', binary])
                header = binary.read_bytes()[:20]
                c.require(header[:6] == b'\x7fELF\x02\x01' and
                          int.from_bytes(header[18:20], 'little') == (62 if isa == 'host' else 183))
                command(stage+'-execute', [binary] if isa == 'host' else [c.ROOT/'scripts/campaign/arm64-run.sh', binary], bytes(inputs))
                row['runs'][stage] = dict(compiled=True,
                    **c.assess((output/(stage+'-execute.stdout')).read_text(), expected, mode))
                if isa == 'arm64':
                    row['arm64_executed'] = True
                else:
                    row['host_executed'] = True
        row['artifact_sha256'] = {n: c.digest(output/n)
            for n in ('lifted.c','transport.cpp','reference.json','input.bin')}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n, sha in row['upstream_files'].items()))
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        run(a.output)
    except Exception:
        p.exit(1, 'No-open fragment failed; inspect private receipt.\n')
    print('Zero-+0x1C no-open return: 64/64 host + Linux/AArch64; two controls '
          'reject. Fragment ONLY; NOT Android.')


if __name__ == '__main__':
    main()
