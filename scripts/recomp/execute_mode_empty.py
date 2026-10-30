#!/usr/bin/env python3
"""Verify only 3700's empty-input success branch; retain the complete lift.

Authored contracts/transport only. Original bodies and states stay private.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_initialization_setter as c
from inspect_startup_dependency import crosscheck_index
from measure_startup import decode_flow, dependencies

RVA, SIZE, COUNT = 0x3700, 582, 163
PIN = '656b1487f4f7b6019a75d44a87c493fc5b997b21bb30542366e3bc09c5b0b996'
CALLEES = (0x1330, 0x1820, 0x1af0, 0x26b0)
PATH = (0x3700, 0x3701, 0x3702, 0x3703, 0x3704, 0x3706, 0x3709,
        0x370b, 0x370f, 0x3935, 0x3936, 0x3937, 0x393c, 0x393d, 0x393e)
MODES = ('valid', 'wrong-result', 'wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    regs, pages = c.state(n)
    # Poisoned receiver remains valid but untouched; EAX points to the empty
    # byte string, including the last readable byte of its page. No callee
    # response or preinitialized parser state is supplied.
    regs['esi'] = c.DATA_PAGES[1]+(0, 128, 1024, 4096-528)[n % 4]
    offset = (0, 1, 128, 4095)[n % 4]
    regs['eax'] = c.DATA_PAGES[2]+offset
    pages[c.DATA_PAGES[2]][offset] = 0
    return regs, pages


def oracle(regs, pages):
    """Independent full final GPR/page contract; not an instruction replay."""
    c.require(set(regs) == set(c.REGS) and set(pages) == set(c.PAGES))
    c.require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
    c.require(all(len(pages[p]) == 4096 for p in c.PAGES))
    sp = regs['esp']-c.DATA_PAGES[0]
    source = regs['eax']-c.DATA_PAGES[2]
    receiver = regs['esi']-c.DATA_PAGES[1]
    c.require(16 <= sp <= 4092 and sp % 4 == 0)
    c.require(0 <= source < 4096 and pages[c.DATA_PAGES[2]][source] == 0)
    c.require(0 <= receiver <= 4096-528)
    c.require(struct.unpack_from('<I', pages[c.DATA_PAGES[0]], sp)[0] == c.RETURN)
    after = {p: bytearray(b) for p, b in pages.items()}
    struct.pack_into('<4I', after[c.DATA_PAGES[0]], sp-16,
                     regs['edi'], regs['ebp'], regs['ebx'], regs['eax'])
    out = dict(regs, eax=1, ecx=regs['eax'], esp=regs['esp']+4)
    return dict(regs=[out[r] for r in c.REGS],
                pages=b''.join(after[p] for p in c.PAGES).hex())


def assemble(body):
    c.require(type(body) is str and body.strip())
    replacements = {
        '@PROTOTYPES@': 'static void mode_empty_3700(void);\n'+''.join(
            f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;\n' for r in CALLEES),
        '@SELECT@': 'case 0xA0003700u:mode_empty_3700();break;',
        '@ADAPTERS@': 'static void adapter_3700(uint32_t* s) {select_body(0xA0003700u,s);}',
        '@CALLBACKS@': 'case 0xA0003700u:callback=adapter_3700;break;',
        '@DIRECT_RETURNS@': '', '@INDIRECT_RETURNS@': '', '@BODY@': body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA0003700u,in,adapter_3700)',
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
    text = text.replace(old, 'constexpr std::array<uint32_t,1> targets{0xA0003700u};')
    if mode != 'valid':
        old = '    current(s.data());'
        c.require(text.count(old) == 1)
        text = text.replace(old, old+('\n    s[0]^=4;' if mode == 'wrong-result' else '\n    s[7]+=8;'))
    return text


def run(index, output):
    output = c.private_output(output)
    sources = [Path(__file__), Path(c.__file__), Path(decode_flow.__code__.co_filename),
               Path(c.reference.__code__.co_filename), Path(c.assess.__code__.co_filename),
               c.TEMPLATE, c.BRIDGE, *[c.ROOT/'native/src'/n for n in ('guest_memory.cpp', 'guest_dispatch.cpp')]]
    row = dict(schema='ts2-mode-empty-native/1', success=False, stub=False,
        invocation=[sys.executable, *sys.argv], image_sha256=c.IMAGE_SHA,
        pcrecomp_revision=c.REVISION, rva=hex(RVA), size_bytes=SIZE, instructions=COUNT,
        function_sha256=PIN, category='alternate-opener dependency, empty-input branch',
        source_sha256={str(p): c.digest(p) for p in sources},
        commands=[], runs={}, host_native_executed=False, arm64_executed=False,
        android_executed=False, whole_function_verified=False, dependencies_newly_resolved=0,
        limits=['Empty EAX input only; poisoned valid ESI handle; no callees executed',
                'Full lift retained; nonempty calls unregistered and fail closed',
                'Independent eight-GPR/six-page oracle; no flags/FP/PC/transient-store comparison',
                'No composed 3C50/1AB665, production registration, Android or gameplay'])
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err, cwd=c.ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    stage = 'preflight'
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py', 'tools/disasm/disasm32.py']
        row['upstream_files'] = {n: c.digest(upstream/n) for n in used}
        c.require(all(sha == c.digest(pristine/n) for n, sha in row['upstream_files'].items()))
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(RVA, SIZE)
        c.require(hashlib.sha256(code).hexdigest() == PIN)
        sys.path.insert(0, str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        stage = 'fresh-lift'
        fn, nodes, _, flow = decode_flow(code, c.BASE+RVA, LinearInstruction)
        c.require(len(nodes) == COUNT and flow['size_bytes'] == SIZE)
        row['index'] = crosscheck_index(json.loads(index.read_text()),
            dict(flow, instruction_rvas=[hex(a-c.BASE) for a in sorted(nodes)]), RVA)
        row['index_sha256'] = c.digest(index)
        row['dependencies'] = dependencies(nodes, pe)
        c.require(set(row['dependencies']['direct_calls']) == {hex(r) for r in CALLEES})
        c.require(row['dependencies']['indirect_calls'] == 0)
        fn.name = 'mode_empty_3700'
        row['lift_invocation'] = dict(api='Lifter(precise_carry=True).lift_function', address=hex(c.BASE+RVA), name=fn.name)
        start = time.monotonic(); body = Lifter(precise_carry=True).lift_function(fn)
        row['lift_seconds'] = time.monotonic()-start
        c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
        (output/'lifted.c').write_text(body); row['lifted'] = True
        stage = 'original-reference'
        cp = bytearray(4096); cp[RVA % 4096:RVA % 4096+SIZE] = code
        expected, inputs, visited = [], bytearray(), set()
        for n in range(64):
            regs, pages = state(n)
            result, seen = c.reference(nodes, {c.BASE+(RVA//4096)*4096: cp}, c.BASE+RVA, regs, pages, budget=64)
            c.require(result == oracle(regs, pages) and seen == {c.BASE+r for r in PATH})
            expected.append(dict(case=n, **result)); visited |= seen
            inputs.extend(struct.pack('<8I', *(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in c.PAGES))
        row.update(x86_oracle_matches=64, coverage=dict(visited=len(visited), total=len(nodes)))
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(body))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(mode))
            for isa in ('host', 'arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile', ['zig-cxx', *([] if isa == 'host' else ['-target', 'aarch64-linux-musl', '-static']),
                    '-std=c++20', '-D_POSIX_C_SOURCE=200809L', '-O0', '-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'), transport, bridge,
                    *[c.ROOT/'native/src'/n for n in ('guest_memory.cpp', 'guest_dispatch.cpp')], '-lm', '-o', binary])
                header = binary.read_bytes()[:20]
                c.require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == (62 if isa == 'host' else 183))
                command(stage+'-execute', [binary] if isa == 'host' else [c.ROOT/'scripts/campaign/arm64-run.sh', binary], bytes(inputs))
                row['runs'][stage] = dict(compiled=True, **c.assess((output/(stage+'-execute.stdout')).read_text(), expected, mode))
                row['host_native_executed' if isa == 'host' else 'arm64_executed'] = True
        row['artifact_sha256'] = {p.name: c.digest(p) for p in output.iterdir() if p.is_file()}
        c.require(c.digest(image) == c.IMAGE_SHA and c.digest(index) == row['index_sha256'])
        c.require(all(c.digest(Path(p)) == sha for p, sha in row['source_sha256'].items()))
        c.require(all(c.digest(upstream/n) == sha for n, sha in row['upstream_files'].items()))
        row.update(success=True, original_behaviour_newly_executable=['3700 empty-input branch'])
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        run(a.index, a.output)
    except Exception:
        p.exit(1, '3700 empty-input check rejected; inspect private receipt.\n')
    print('3700 empty-input branch matched host/Linux-AArch64; NOT whole function or Android.')


if __name__ == '__main__':
    main()
