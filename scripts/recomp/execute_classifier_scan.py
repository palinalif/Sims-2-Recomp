#!/usr/bin/env python3
"""10700/FCB0 scan differential, optionally under real 109D0 producer.

Only authored infrastructure is public; bodies, tables and states remain private.
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
import execute_initialization_producer as producer
from measure_startup import decode_flow, dependencies

RVA = c.CLASSIFIER
IMAGES = (c.BASE+0x1050000, c.BASE+0xe19000)
PAGES = (*c.DATA_PAGES, *IMAGES)
MODES = ('valid', 'wrong-result', 'wrong-cleanup')
ALTERNATE = 0x10b60
ALTERNATE_SHA = '820273871703ba7086e823c5f6dd7edb5ce80486b47ca694e48c579302ed5426'


def producer_profile(rva):
    c.require(type(rva) is int and rva in (producer.RVA, ALTERNATE))
    return (producer.FUNCTION_SHA, 0x10970, 0x109a0) if rva == producer.RVA else (ALTERNATE_SHA, 0x10b00, 0x10b30)


TABLE = c.BASE+0x1050044


def names_from_pages(images):
    c.require(set(images) == set(IMAGES) and all(len(v) == 4096 for v in images.values()))
    pointers = struct.unpack_from('<6I', images[IMAGES[0]], TABLE-IMAGES[0])
    names = []
    for pointer in pointers:
        c.require(IMAGES[1] <= pointer < IMAGES[1]+4096)
        tail = bytes(images[IMAGES[1]][pointer-IMAGES[1]:])
        c.require(b'\0' in tail)
        name = tail.split(b'\0', 1)[0]
        c.require(0 < len(name) < 128)
        names.append(name)
    c.require(len(set(names)) == 6)
    return names


def state(n, images):
    c.require(type(n) is int and 0 <= n < 64)
    names = names_from_pages(images)
    regs, old = c.state(n, RVA)
    pages = {p:old[p] for p in c.DATA_PAGES}
    pages.update({p:bytearray(images[p]) for p in IMAGES})
    # Each table entry: exact, case-folded, and suffix/prefix mismatches.
    source = names[n % 6]
    group = n // 6
    sample = source if group % 4 == 0 else source.swapcase() if group % 4 == 1 else source+b'!' if group % 4 == 2 else b'!'+source
    if n == 62: sample = b''
    if n == 63: sample = b'\xff\x80'
    regs['edi'] = c.DATA_PAGES[1]+128
    pages[c.DATA_PAGES[1]][128:129+len(sample)] = sample+b'\0'
    # Also retain the proven null-input path as a distinct branch.
    if n == 61: regs['edi'] = 0
    return regs, pages, sample


def contract(regs, pages, sample, result):
    """Independent result/nonvolatile/ESP contract, not a volatile-register oracle."""
    names = names_from_pages({p:pages[p] for p in IMAGES})
    matches = [i for i, name in enumerate(names) if c.comparison_equal(name, sample)]
    value = 6 if regs['edi'] == 0 else matches[0] if matches else 0xffffffff
    c.require(result['regs'][0] == value)
    for r in ('ebx', 'ebp', 'esi', 'edi'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    c.require(result['regs'][7] == regs['esp']+4)
    final = bytes.fromhex(result['pages'])
    c.require(len(final) == 6*4096)
    # Only the scratch stack may change; every other page is immutable here.
    c.require(final[4096:] == b''.join(bytes(pages[p]) for p in PAGES[1:]))
    return value


def producer_state(n, images):
    """Inline producer storage plus independent bounded string input."""
    scan_regs, scan_pages, sample = state(n, images)
    regs, old = producer.state(n, 'inline')
    pages = {p:old[p] for p in c.DATA_PAGES}
    pages.update({p:bytearray(images[p]) for p in IMAGES})
    pointer = c.DATA_PAGES[3]+128 if scan_regs['edi'] else 0
    pages[c.DATA_PAGES[3]][128:129+len(sample)] = sample+b'\0'
    struct.pack_into('<I', pages[PAGES[0]], regs['esp']-PAGES[0]+12, pointer)
    return regs, pages, sample


def producer_contract(regs, pages, sample, result, producer_rva=producer.RVA):
    """Independent publication/failure contract; scratch/volatile state from x86."""
    _, first, second = producer_profile(producer_rva)
    _, obj, link, pointer = struct.unpack_from('<4I', pages[PAGES[0]], regs['esp']-PAGES[0])
    names = names_from_pages({p:pages[p] for p in IMAGES})
    matches = [i for i, name in enumerate(names) if c.comparison_equal(name, sample)]
    value = 6 if pointer == 0 else matches[0] if matches else 0xffffffff
    success = value != 0xffffffff
    c.require(result['regs'][0] == int(success))
    for r in ('ebx', 'ebp', 'esi', 'edi'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    c.require(result['regs'][7] == regs['esp']+4)
    after = {p:bytearray(b) for p,b in pages.items()}
    if success:
        for offset, word in ((0, c.BASE+first), (4, c.BASE+second),
                             (0x34, c.BASE+0xfcf0), (0x4c, link)):
            struct.pack_into('<I', after[PAGES[1]], obj-PAGES[1]+offset, word)
        after[PAGES[1]][obj-PAGES[1]+0x49] = value
        struct.pack_into('<I', after[PAGES[1]], link-PAGES[1], obj)
    final = bytes.fromhex(result['pages'])
    c.require(len(final) == len(PAGES)*4096)
    c.require(final[4096:] == b''.join(after[p] for p in PAGES[1:]))
    return value


def assemble(bodies, with_producer=False, producer_rva=producer.RVA):
    producer_profile(producer_rva)
    targets = (RVA, c.MODULE_COMPARE, producer_rva) if with_producer else (RVA, c.MODULE_COMPARE)
    name = lambda r: f'initialization_producer_{producer_rva:X}' if r == producer_rva else c.body_name(r)
    c.require(set(bodies) == set(targets) and all(type(b) is str and b.strip() for b in bodies.values()))
    replacements = {
        '@PROTOTYPES@': '\n'.join('static void '+name(r)+'(void);' for r in targets)+'\nstatic constexpr unsigned address_sub_A000FCB0=0xA000FCB0u;'+ ('\nstatic constexpr unsigned address_sub_A0010700=0xA0010700u;' if with_producer else ''),
        '@SELECT@': '\n'.join(f'case 0x{c.BASE+r:08X}u: {name(r)}();break;' for r in targets),
        '@ADAPTERS@': '\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}' for r in targets),
        '@CALLBACKS@': '\n'.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in targets),
        '@DIRECT_RETURNS@': 'if(caller==0xA0010700u && target==0xA000FCB0u) return 0xA001071Eu;'+ ('\nif(caller==0xA00109D0u && target==0xA0010700u) return 0xA00109DAu;' if with_producer else ''),
        '@INDIRECT_RETURNS@': '', '@BODY@': '\n'.join(bodies.values()),
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)': 'cache_invoke(0xA00109D0u,in,adapter_109D0)' if with_producer else 'cache_invoke(0xA0010700u,in,adapter_10700)',
    }
    # Rewrite authored dispatch metadata only, NEVER proprietary lifted bodies.
    if with_producer:
        for key in ('@DIRECT_RETURNS@', 'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)'):
            replacements[key] = replacements[key].replace('A00109D0', f'{c.BASE+producer_rva:08X}').replace('A00109DA', f'{c.BASE+producer_rva+10:08X}').replace('adapter_109D0', f'adapter_{producer_rva:X}')
    text = c.TEMPLATE.read_text()
    for old, new in replacements.items():
        c.require(text.count(old) == 1); text = text.replace(old, new)
    for body in bodies.values(): c.require(text.count(body) == 1)
    return text


def bridge_source(text, mode, with_producer=False, producer_rva=producer.RVA):
    producer_profile(producer_rva)
    c.require(mode in MODES)
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    c.require(text.count(old) == 1)
    text = text.replace(old, 'constexpr std::array<uint32_t,3> targets{0xA0010700u,0xA000FCB0u,0xA00109D0u};' if with_producer else 'constexpr std::array<uint32_t,2> targets{0xA0010700u,0xA000FCB0u};')
    if with_producer:
        text = text.replace('0xA00109D0u', f'0x{c.BASE+producer_rva:08X}u')
    for old, new in (('0xA0009000u,0xA0E17000u', '0xA1050000u,0xA0E19000u'),):
        c.require(text.count(old) == 1); text = text.replace(old, new)
    if mode != 'valid':
        old = '    current(s.data());'
        new = old+'\n    if(depth==1) '+('s[0]^=4;' if mode == 'wrong-result' else 's[7]+=8;')
        c.require(text.count(old) == 1); text = text.replace(old, new)
    return text


def run(output, index, compare_index, producer_index=None, producer_rva=producer.RVA):
    profile_sha, _, _ = producer_profile(producer_rva)
    c.require(producer_index is not None or producer_rva == producer.RVA)
    output = c.private_output(output)
    row = dict(schema='ts2-classifier-scan-native/1', success=False, rva=hex(producer_rva if producer_index else RVA),
        image_sha256=c.IMAGE_SHA, pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)), helper_sha256=c.digest(Path(c.__file__)),
        reference_helper_sha256=c.digest(c.ROOT/'scripts/recomp/execute_cache_dispatch.py'),
        template_sha256=c.digest(c.TEMPLATE), bridge_sha256=c.digest(c.BRIDGE),
        invocation=[sys.executable,*sys.argv], commands=[], functions={}, runs={}, timings={},
        attempted=False, lifted=False, arm64_executed=False, android_executed=False, stub=False,
        compared=['eight final GPRs', 'six complete 4096-byte pages including scratch stack'],
        limits=['synthetic valid NUL-terminated inputs; not a proven incoming caller/ownership contract',
                'no flags/FP/PC/native transient writes or invalid-pointer semantics',
                'diagnostic GuestMemory/exact-VA dispatch, not E3/E4 or Android'])
    stage = 'preflight'
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err, cwd=c.ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    try:
        start = time.monotonic()
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        indexes = {RVA:index, c.MODULE_COMPARE:compare_index}
        if producer_index: indexes[producer_rva] = producer_index
        row['indexes'] = {}
        for r, p in indexes.items():
            envelope = json.loads(p.read_text())
            if r == producer_rva:
                context = c.index_context(envelope, r)
                f = envelope['result']['function']; d = f['disassembly']
                c.require(f['resolution'] == 'function-at' and int(f['entryRva'],16) == r)
                c.require(d['extentBytes'] == producer.SIZE and d['instructionCount'] == producer.COUNT and
                          int(d['extentEndVa'],16) == c.BASE+r+producer.SIZE-1)
                c.require(not any(v for k,v in envelope['result']['truncation'].items() if k != 'counts'))
                row['indexes'][hex(r)] = context
            else:
                row['indexes'][hex(r)] = c.check_index(envelope, r)
        if producer_index:
            row['schema'] = 'ts2-producer-scan-native/1'
            row['producer_helper_sha256'] = c.digest(Path(producer.__file__))
            row['path_contract'] = dict(storage_layout='inline', real_callees=['0x10700','0xfcb0'],
                incoming_caller_verified=False, callback_invoked=False)
        row['index_sha256'] = {hex(r):c.digest(p) for r,p in indexes.items()}
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        c.require(all(c.digest(upstream/n) == c.digest(pristine/n) for n in used))
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'fresh-lift'; start = time.monotonic(); row['attempted'] = True
        bodies, nodes, code_pages = {}, {}, {}
        for rva in indexes:
            _, sha, size, count, _ = (None, profile_sha, producer.SIZE, producer.COUNT, None) if rva == producer_rva else c.unit(rva)
            code = pe.get_data(rva,size)
            c.require(hashlib.sha256(code).hexdigest() == sha)
            function, decoded, _, _ = decode_flow(code,c.BASE+rva,LinearInstruction)
            deps = dependencies(decoded,pe)
            c.require(deps['direct_calls'] == (['0x10700'] if rva == producer_rva else ['0xfcb0'] if rva == RVA else []) and deps['indirect_calls'] == 0 and not deps['segmented_memory_operands'])
            function.name = f'initialization_producer_{producer_rva:X}' if rva == producer_rva else c.body_name(rva)
            body = Lifter(precise_carry=True).lift_function(function)
            c.require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
            bodies[rva] = body; (output/f'{rva:x}-lifted.c').write_text(body)
            row['functions'][hex(rva)] = dict(function_sha256=sha, size=size, dependencies=deps,
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+rva),name=function.name,
                    blocks=[(a-c.BASE-rva,b.instructions[-1].address+b.instructions[-1].size-c.BASE-rva) for a,b in sorted(function.blocks.items())]))
            c.require(not set(nodes) & set(decoded)); nodes.update(decoded)
            indexed = json.loads(indexes[rva].read_text())['result']['function']['disassembly']['items']
            c.require(len(decoded) == count and [int(i['va'],16) for i in indexed] == sorted(decoded))
            page = c.BASE+(rva//4096)*4096
            code_pages.setdefault(page,bytearray(4096))[rva%4096:rva%4096+size] = code
        row['lifted'] = True; row['timings']['translation'] = time.monotonic()-start
        stage = 'original-reference'; start = time.monotonic()
        images = {p:pe.get_data(p-c.BASE,4096) for p in IMAGES}
        row['image_pages_sha256'] = {hex(p):hashlib.sha256(b).hexdigest() for p,b in images.items()}
        expected, inputs, visited, outcomes = [], bytearray(), set(), {}
        for n in range(64):
            regs,pages,sample = producer_state(n,images) if producer_index else state(n,images)
            result,seen = c.reference(nodes,code_pages,c.BASE+(producer_rva if producer_index else RVA),regs,pages,budget=4096,image_pages=IMAGES)
            value = producer_contract(regs,pages,sample,result,producer_rva) if producer_index else contract(regs,pages,sample,result)
            outcomes[str(value)] = outcomes.get(str(value),0)+1
            expected.append(dict(case=n,**result)); visited.update(seen)
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in PAGES))
        c.require(set(outcomes) == {str(i) for i in (*range(7),0xffffffff)})
        classifier_nodes = {a for a in nodes if c.BASE+RVA <= a < c.BASE+RVA+49}
        c.require(classifier_nodes <= visited and c.BASE+c.MODULE_COMPARE in visited)
        if producer_index:
            producer_nodes = {a for a in nodes if c.BASE+producer_rva <= a < c.BASE+producer_rva+producer.SIZE}
            c.require(len(producer_nodes) == producer.COUNT and producer_nodes <= visited)
        row['coverage'] = dict(visited=len(visited),total=len(nodes),
            classifier_visited=len(visited & classifier_nodes),classifier_total=len(classifier_nodes),
            comparison_visited=sum(c.BASE+c.MODULE_COMPARE <= a < c.BASE+c.MODULE_COMPARE+51 for a in visited),comparison_total=26,
            producer_visited=sum(c.BASE+producer_rva <= a < c.BASE+producer_rva+producer.SIZE for a in visited),producer_total=producer.COUNT if producer_index else 0,
            result_counts=outcomes)
        row['x86_oracle_matches'] = 64
        row['timings']['x86_reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(bodies, bool(producer_index),producer_rva))
        for mode in MODES:
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(c.BRIDGE.read_text(),mode,bool(producer_index),producer_rva))
            for isa in ('host','arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,c.ROOT/'native/src/guest_memory.cpp',
                    c.ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
                h = binary.read_bytes()[:20]
                c.require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage] = dict(compiled=True,**c.assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                if isa == 'arm64': row['arm64_executed'] = True
        row['artifact_sha256'] = {n:c.digest(output/n) for n in ('10700-lifted.c','fcb0-lifted.c','transport.cpp','reference.json','input.bin',*([f'{producer_rva:x}-lifted.c'] if producer_index else []))}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__)
        raise
    finally: (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--index',type=Path,required=True)
    p.add_argument('--compare-index',type=Path,required=True)
    p.add_argument('--producer-index',type=Path,help='Compose 109D0 with inline storage and real classifier')
    p.add_argument('--producer-rva', type=lambda s:int(s,16), default=producer.RVA,
                   choices=(producer.RVA, ALTERNATE), help='Producer entry RVA (hex); requires --producer-index')
    a = p.parse_args(); r = run(a.output,a.index,a.compare_index,a.producer_index,a.producer_rva)
    print(json.dumps({k:r[k] for k in ('success','coverage','runs','android_executed')}))

if __name__ == '__main__': main()
