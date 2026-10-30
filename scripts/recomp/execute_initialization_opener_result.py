#!/usr/bin/env python3
"""Fresh pinned lift of the 0x1AB665 opener-result segment (RVA 0x1AB6A6), first
host and Linux/AArch64 native differential of the opener RETURN edge with the
zero-result (opener failed) completion.

This is the next dependency-directed E3 fragment after the settled whole-body
early-return arms (guard +0x34 AL=1; no-open +0x1C AL=0): the original bytes at
the exact 0x3C50 call-return boundary (0x1AB6A6 pop / 0x1AB6A7 store) through
the shared 0x1AB763 comparison tail and epilogue. Opener result 0 (the failure
edge of the opener-success composition) completes to return with no callee; the
store [ESI+0x34]=EAX, TEST/JE and CMP/SETNE AL from ([+0x34] != EDI) execute for
the first time natively. Non-zero results divert to `push ESI; push EAX;
call 0x1030` at 0x1AB6B3 — that association-call argument shape is bound here
by the x86 boundary observation only, never executed or responded to. The
segment is original image code at a recorded instruction boundary lifted by the
unchanged pcrecomp lifter; no hand-written body. Private artifacts only.
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
# Enclosing-function context only: this segment lives inside the settled 1AB665.
import execute_initialization_guard as guard
from inspect_initialization_graph import seed_receipt
from measure_startup import decode_flow, dependencies
c = probe.c
RVA, SIZE = 0x1ab6a6, 0xca
SEGMENT_SHA = '02fd4cdbf888632efdfa896694081014c0eba8578f198bbbd75f63c1f39b826a'
SEGMENT_NODES = 60
SEGMENT_CALLEES = ('0x1030', '0x1070', '0x1090', '0x10a0', '0x10b0',
                                    '0x10c0', '0x10e0', '0x1100', '0x1110', '0x1120',
                                    '0x1130', '0x1140')
# Zero-result completion path: two pops, store, test, je to the shared tail.
RESULT_PATH = (0x1ab6a6, 0x1ab6a7, 0x1ab6aa, 0x1ab6ab, 0x1ab6ad,
               0x1ab763, 0x1ab766, 0x1ab769, 0x1ab76a, 0x1ab76b)
# Sites no settled arm has ever executed (guard shares only the 0x1ab766+ tail,
# no-open reaches the epilogue only through the 0x1ab76c AL=0 stub).
NEW_SITES = (0x1ab6a6, 0x1ab6a7, 0x1ab6aa, 0x1ab6ab, 0x1ab6ad, 0x1ab763)
MODES = ('valid', 'wrong-result', 'wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random((RVA << 8) + n + 0x5b)
    regs = {r: rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0] + (0x800 if n % 2 else 0xc00)
    regs['esi'] = c.DATA_PAGES[1] + (0x80, 0x800, 0xd00, 0xe00)[(n >> 3) % 4]
    pages = {p: bytearray(rng.randbytes(4096)) for p in probe.PAGES}
    sp = regs['esp']
    off = sp - c.DATA_PAGES[0]
    # Layout at the exact 0x3C50 return boundary: [sp] string-arg word, [sp+4]
    # 0x40-arg word (both popped into ECX and discarded), [sp+8] the word the
    # epilogue pops into EDI, [sp+0xC] the word popped back into ESI (the
    # receiver, pushed by the enclosing entry), [sp+0x10] the return sentinel.
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], off, rng.getrandbits(32) | 1)
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], off + 4, rng.getrandbits(32))
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], off + 8, rng.getrandbits(32))
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], off + 0xc, regs['esi'])
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], off + 0x10, c.RETURN)
    # Opener result: this fragment completes only on the zero (failure) edge.
    regs['eax'] = 0
    # 32 cases keep the real path's callee-saved EDI == 0; the other 32 probe
    # the CMP/SETNE operand semantics (AL = ([+0x34] != EDI)) beyond it.
    regs['edi'] = 0 if n < 32 else (rng.getrandbits(32) | 1)
    return regs, pages


def oracle(regs, pages):
    esi, sp = regs['esi'], regs['esp']
    c.require(set(regs) == set(c.REGS) and set(pages) == set(probe.PAGES))
    c.require(c.DATA_PAGES[1] <= esi <= c.DATA_PAGES[1] + 4096 - 0x38 and esi % 4 == 0)
    c.require(sp in (c.DATA_PAGES[0] + 0x800, c.DATA_PAGES[0] + 0xc00))
    # Boundary contract: EAX is the opener result and must be zero here; the
    # return sentinel sits above the saved-word pair the epilogue pops.
    c.require(regs['eax'] == 0)
    stack = pages[c.DATA_PAGES[0]]
    off = sp - c.DATA_PAGES[0]
    arg_string, arg_40, saved_edi, saved_esi, sentinel = struct.unpack_from('<5I', stack, off)
    c.require(sentinel == c.RETURN)
    c.require(saved_esi == esi)  # the entry push ESI modelled by the enclosing frame
    after = {p: bytearray(b) for p, b in pages.items()}
    # Store of the zero opener result into [receiver+0x34]; pops and the ret
    # only read stack words. The shared tail then sets AL from ([+0x34] != EDI).
    struct.pack_into('<I', after[c.DATA_PAGES[1]], esi - c.DATA_PAGES[1] + 0x34, 0)
    out = dict(regs, eax=1 if regs['edi'] != 0 else 0, ecx=arg_40,
               edi=saved_edi, esi=saved_esi, esp=sp + 0x14)
    return dict(regs=[out[r] for r in c.REGS],
                pages=b''.join(after[p] for p in probe.PAGES).hex())


def check_dependencies(deps, seed):
    c.require(not deps['indirect_calls'] and not deps['absolute_memory_va'] and
              not deps['segmented_memory_operands'])
    c.require(sorted(set(deps['direct_calls'])) == list(SEGMENT_CALLEES))
    # Every segment callee is an enclosing-1AB665 direct callee from the seed.
    c.require(set(deps['direct_calls']).issubset(set(seed['direct'])))


def assemble(body, callees):
    c.require(type(body) is str and body.strip())
    expected = set(SEGMENT_CALLEES)
    c.require(set(callees) == expected and len(callees) == len(expected))
    name = 'initialization_opener_result_1AB6A6'
    declarations = '\n'.join(f'static constexpr unsigned address_sub_{c.BASE+int(r,16):08X}=0x{c.BASE+int(r,16):08X}u;' for r in callees)
    replacements = {
        '@PROTOTYPES@': f'static void {name}(void);\n' + declarations,
        '@SELECT@': 'case 0xA01AB6A6u: initialization_opener_result_1AB6A6();break;',
        '@ADAPTERS@': 'static void adapter_1AB6A6(uint32_t* s) {select_body(0xA01AB6A6u,s);}',
        '@CALLBACKS@': 'case 0xA01AB6A6u:callback=adapter_1AB6A6;break;',
        '@DIRECT_RETURNS@': '', '@INDIRECT_RETURNS@': '', '@BODY@': body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA01AB6A6u,in,adapter_1AB6A6)',
    }
    text = c.TEMPLATE.read_text()
    for old, new in replacements.items():
        c.require(text.count(old) == 1)
        text = text.replace(old, new)
    c.require(text.count(body) == 1)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = c.BRIDGE.read_text()
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    c.require(text.count(old) == 1)
    text = text.replace(old, 'constexpr std::array<uint32_t,1> targets{0xA01AB6A6u};')
    c.require(text.count('0xA0009000u') == 1)
    text = text.replace('0xA0009000u', '0xA1050000u')
    if mode != 'valid':
        old = '    current(s.data());'
        c.require(text.count(old) == 1)
        # wrong-result flips AL, i.e. inverts the CMP/SETNE polarity this segment
        # newly executes; forcing a constant would hide the EDI!=0 half the space.
        text = text.replace(old, old + ('\n    s[0]^=1;' if mode == 'wrong-result' else '\n    s[7]+=8;'))
    return text


def run(output):
    output = c.private_output(output)
    row = dict(schema='ts2-initialization-opener-result-native/1', success=False,
        rva=hex(RVA), size=SIZE, segment_of=hex(guard.RVA),
        enclosing_function_sha256=guard.FUNCTION_SHA,
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)), probe_sha256=c.digest(Path(probe.__file__)),
        helper_sha256=c.digest(Path(c.__file__)), guard_sha256=c.digest(Path(guard.__file__)),
        template_sha256=c.digest(c.TEMPLATE), bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable, *sys.argv], commands=[], runs={}, timings={},
        lifted=False, host_executed=False, arm64_executed=False, android_executed=False,
        stub=False, whole_function_verified=False, e3_fragment=True, e3_complete=False,
        e4_complete=False,
        arm='opener-result edge: store [ESI+0x34]=EAX, TEST/JE, zero-result completion '
            'through the shared 0x1AB763 CMP/SETNE tail (distinct from both early-return arms)',
        compared=['eight final GPRs including ESP',
                  'six complete 4096-byte pages including the stored +0x34 slot'],
        limits=['ONLY the zero-opener-result completion from the exact 0x3C50 return '
                'boundary; non-zero results divert to call 0x1030 (x86 boundary only, '
                'never executed or responded to here)',
                'Authored bounded return-edge stack (saved-word pair, sentinel), not '
                'producer/input/lifetime/callback ownership proof',
                'EDI==0 on 32 cases mirrors callee-save; EDI!=0 cases probe CMP/SETNE '
                'operand semantics beyond the real path; the wrong-result control flips '
                'AL (SETE-for-SETNE polarity) so it must differ on all 64 cases',
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
        # The segment lies inside the settled 1AB665 whole-body pin.
        c.require(guard.RVA == 0x1ab665 and guard.RVA <= RVA and
                  RVA+SIZE <= guard.RVA+guard.SIZE)
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
        c.require(hashlib.sha256(code).hexdigest() == SEGMENT_SHA)
        function, nodes, _, _ = decode_flow(code, c.BASE+RVA, LinearInstruction)
        c.require(len(nodes) == SEGMENT_NODES)
        deps = dependencies(nodes, pe)
        check_dependencies(deps, row['seed'])
        function.name = 'initialization_opener_result_1AB6A6'
        body = Lifter(precise_carry=True).lift_function(function)
        c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
        (output/'lifted.c').write_text(body)
        row.update(lifted=True, function_sha256=SEGMENT_SHA, dependencies=deps,
            lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',
                                 address=hex(c.BASE+RVA), name=function.name))
        row['timings']['translation'] = time.monotonic()-start
        stage = 'original-reference'; start = time.monotonic()
        code_pages = {c.BASE+0x1ab000: bytearray(4096)}
        code_pages[c.BASE+0x1ab000][0x6a6:0x6a6+SIZE] = code
        expected, inputs = [], bytearray()
        for n in range(64):
            regs, pages = state(n)
            result = probe.trace(nodes, code_pages, c.BASE+RVA, regs, pages)
            c.require(result['outcome'] == 'returned' and
                      result['visited'] == [c.BASE+a for a in RESULT_PATH])
            observed = {k: result[k] for k in ('regs', 'pages')}
            c.require(observed == oracle(regs, pages))
            expected.append(dict(case=n, **observed))
            inputs.extend(struct.pack('<8I', *(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in probe.PAGES))
        row.update(x86_oracle_matches=64, coverage=dict(visited=len(RESULT_PATH),
                   segment_instructions=SEGMENT_NODES, whole_function_instructions=83,
                   callee_calls=0, new_sites=list(map(hex, NEW_SITES)),
                   arm='opener-result-zero-completion'))
        row['timings']['reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'
        transport.write_text(assemble(body, deps['direct_calls']))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(mode))
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
        p.exit(1, 'Opener-result fragment failed; inspect private receipt.\n')
    print('Opener-result zero completion: 64/64 host + Linux/AArch64; two controls '
          'reject. Fragment ONLY; NOT Android.')


if __name__ == '__main__':
    main()
