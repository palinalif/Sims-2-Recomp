#!/usr/bin/env python3
"""Fresh 2790/26B0/1AF0 default-allocation path with explicit portable heap.

Original Windows heap is NOT executed; private lifted bodies and states stay in work/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import execute_heap_success as heap
import probe_capacity_service as prefix
from inspect_startup_dependency import crosscheck_index
from measure_startup import decode_flow, dependencies, supported
c = heap.c
UNITS = {**prefix.UNITS, heap.WRAPPER:(heap.WRAPPER_SIZE,heap.WRAPPER_COUNT,heap.WRAPPER_PIN),
         heap.RVA:(heap.SIZE,heap.COUNT,heap.PIN)}
ROOT = prefix.h.ROOT_RVA
MODES = ('valid','wrong-result','wrong-cleanup')


def state(n):
    regs,pages = prefix.state(n)
    # Empty old descriptor only. Full buffers require a separate release contract.
    sp = regs['esp']-c.DATA_PAGES[0]
    obj = struct.unpack_from('<I',pages[c.DATA_PAGES[0]],sp+4)[0]
    struct.pack_into('<5I',pages[c.DATA_PAGES[1]],obj-c.DATA_PAGES[1]+0x1d0,0,0,0,0,0)
    # The reused prefix stores source text in DATA_PAGES[2]. That page is
    # exclusively owned by GuestHeap here: relocate input before allocating.
    old_source = struct.unpack_from('<I',pages[c.DATA_PAGES[0]],sp+8)[0]
    offset = old_source-c.DATA_PAGES[2]
    end = pages[c.DATA_PAGES[2]].index(0,offset)
    sample = pages[c.DATA_PAGES[2]][offset:end+1]
    source = c.DATA_PAGES[3]+128
    pages[c.DATA_PAGES[3]][128:128+len(sample)] = sample
    struct.pack_into('<I',pages[c.DATA_PAGES[0]],sp+8,source)
    struct.pack_into('<I',pages[c.DATA_PAGES[1]],obj-c.DATA_PAGES[1]+0xd0,source)
    pages = {p:pages[p] for p in c.DATA_PAGES}
    pages.update({p:bytearray(4096) for p in heap.IMAGES})
    struct.pack_into('<I',pages[heap.IMAGES[0]],heap.IAT-heap.IMAGES[0],heap.SERVICE)
    struct.pack_into('<I',pages[heap.IMAGES[1]],heap.GLOBAL-heap.IMAGES[1],heap.HANDLE)
    return regs,pages


def contract(regs,pages,result,model):
    """Independent publication/copy contract, excluding scratch regs/stack bytes."""
    c.require(model.calls == 1 and model.expected_size == 1032)
    sp = regs['esp']-c.DATA_PAGES[0]
    ret,obj,source = struct.unpack_from('<III',pages[c.DATA_PAGES[0]],sp)
    c.require(ret == c.RETURN)
    offset = obj-c.DATA_PAGES[1]
    c.require(struct.unpack_from('<5I',pages[c.DATA_PAGES[1]],offset+0x1d0) == (0,0,0,0,0))
    source_offset = source-c.DATA_PAGES[3]
    c.require(0 <= source_offset < 4096)
    end = bytes(pages[c.DATA_PAGES[3]]).find(b'\0',source_offset)
    c.require(end >= source_offset)
    sample = bytes(pages[c.DATA_PAGES[3]][source_offset:end+1])
    after = {p:bytearray(b) for p,b in pages.items()}
    # Capacity owns the raw allocation separately; usable text skips 8 bytes.
    struct.pack_into('<I',after[c.DATA_PAGES[1]],offset+0xd0,heap.ARENA+8)
    struct.pack_into('<I',after[c.DATA_PAGES[1]],offset+0x1d0,heap.ARENA)
    struct.pack_into('<III',after[c.DATA_PAGES[1]],offset+0x1d8,
                     heap.ARENA+1032,heap.ARENA+8+len(sample),heap.ARENA+8+len(sample))
    struct.pack_into('<II',after[heap.ARENA],0,0,1024)
    after[heap.ARENA][8:8+len(sample)] = sample
    c.require(result['regs'][0] == 1 and result['regs'][7] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    data = bytes.fromhex(result['pages']);c.require(len(data) == 6*4096)
    for i,p in enumerate(heap.PAGES):
        if p != c.DATA_PAGES[0]:c.require(data[i*4096:(i+1)*4096] == after[p])


def assemble(bodies, direct_returns, indirect_return, *, units=None,
             tail_wrapper=heap.WRAPPER, tail_body=heap.RVA,
             entry_rva=ROOT, direct_targets=()):
    units = UNITS if units is None else units
    c.require(tail_wrapper in units and tail_body in units)
    c.require(set(bodies) == set(units) and all(b.strip() and supported(b) for b in bodies.values()))
    prototypes = '\n'.join(f'static void capacity_{r:X}(void);' for r in units)
    # Out-of-domain calls retain their generated target constants but never get responses.
    targets = {0x26b0,0x1af0,0x8413b0,heap.WRAPPER,0x8437c6,0x842a91,0x831b17,
               0x8461f2,0x8461b8} | set(direct_targets)
    prototypes += '\n'+'\n'.join(f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;' for r in targets)
    replacements = {
        '@PROTOTYPES@':prototypes+'\nextern "C" void heap_endpoint(uint32_t*);',
        '@SELECT@':''.join(f'case 0x{c.BASE+r:08X}u:capacity_{r:X}();break;' for r in units),
        '@ADAPTERS@':'\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}' for r in units),
        '@CALLBACKS@':''.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in units)+f'case 0x{heap.SERVICE:08X}u:callback=heap_endpoint;break;',
        '@DIRECT_RETURNS@':'\n'.join(f'if(caller==0x{caller:08X}u && target==0x{target:08X}u) return 0x{ret:08X}u;' for caller,target,ret in direct_returns),
        '@INDIRECT_RETURNS@':f'if(caller==0x{c.BASE+tail_body:08X}u && target==0x{heap.SERVICE:08X}u) return 0x{indirect_return:08X}u;',
        '@BODY@':'\n'.join(bodies.values()),
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40);':f'cache_invoke(0x{c.BASE+entry_rva:08X}u,in,adapter_{entry_rva:X});',
        'if(g_cur_func!=0xA000FCF0u || target!=0xA0009550u) reject();':f'if(g_cur_func!=0x{c.BASE+tail_wrapper:08X}u || target!=0x{c.BASE+tail_body:08X}u) reject();',
    }
    text = c.TEMPLATE.read_text()
    for old,new in replacements.items():
        c.require(text.count(old) == 1);text = text.replace(old,new)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = heap.bridge_source('valid' if mode == 'wrong-cleanup' else mode)
    if mode == 'wrong-cleanup':
        # Corrupt the outer return ABI, not an inner service frame (which aborts
        # before producing post-state). The comparator must detect ESP divergence.
        old = '    current(s.data());'
        c.require(text.count(old) == 1)
        text = text.replace(old,old+'\n    if(depth==1) s[7]+=4;')
    old = f'constexpr std::array<uint32_t,2> targets{{0x{c.BASE+heap.RVA:08X}u,0x{heap.SERVICE:08X}u}};'
    c.require(text.count(old) == 1)
    targets = [c.BASE+r for r in UNITS]+[heap.SERVICE]
    return text.replace(old,f'constexpr std::array<uint32_t,{len(targets)}> targets{{'+','.join(f'0x{a:08X}u' for a in targets)+'};')


def run(indexes,output, *, scenario=None):
    # Explicit scenario seam: no mutation of module globals or default fixtures.
    units = UNITS if scenario is None else scenario.UNITS
    entry_rva = ROOT if scenario is None else getattr(scenario, 'ROOT_RVA', ROOT)
    pages_order = heap.PAGES if scenario is None else getattr(scenario, 'PAGES', heap.PAGES)
    image_pages = heap.IMAGES if scenario is None else getattr(scenario, 'IMAGES', heap.IMAGES)
    extra_pages = () if scenario is None else getattr(scenario, 'EXTRA_PAGES', ())
    make_state = state if scenario is None else scenario.state
    make_model = (lambda:heap.HeapModel(1032)) if scenario is None else scenario.model
    check_contract = contract if scenario is None else scenario.contract
    make_transport = assemble if scenario is None else getattr(scenario, 'assemble', None)
    c.require(callable(make_transport) or callable(getattr(scenario, 'assemble_traced', None)))
    make_bridge = bridge_source if scenario is None else scenario.bridge_source
    assess_output = c.assess if scenario is None else getattr(scenario, 'assess', c.assess)
    tail_wrapper = heap.WRAPPER if scenario is None else scenario.WRAPPER
    tail_body = heap.RVA if scenario is None else scenario.RVA
    output = c.private_output(output)
    row = dict(schema='ts2-capacity-success-native/1',success=False,stub=False,
        invocation=[sys.executable,*sys.argv],image_sha256=c.IMAGE_SHA,pcrecomp_revision=c.REVISION,
        harness_sha256=c.digest(Path(__file__)),functions={},commands=[],runs={},
        helper_sha256={Path(m.__file__).name:c.digest(Path(m.__file__)) for m in (c,heap,prefix)},
        reference_harness_sha256=c.digest(Path(c.reference.__code__.co_filename)),
        template_sha256=c.digest(c.TEMPLATE),bridge_sha256=c.digest(c.BRIDGE),
        android_executed=False,windows_heap_verified=False,whole_function_verified=False,
        dependencies_newly_resolved=0,host_native_executed=False,arm64_executed=False,
        closure=[hex(r) for r in UNITS],
        service_boundary=dict(target=hex(heap.SERVICE),x86='independent occupancy model',
            native='production GuestHeap',original_windows_import_executed=False),
        limits=['Empty old descriptors, null default selector, one successful 1032-byte allocation per case only',
                'Independent x86 occupancy model vs production GuestHeap; NOT Windows HeapAlloc execution',
                'Synthetic immutable IAT/global/token; no startup/global/lifetime proof',
                'Eight final GPRs and six pages; no flags/FP/PC/native transient-store comparison',
                'No full 1AF0/26B0/opener/1AB665/E3/E4/Android/game startup'])
    if scenario is not None:
        row.update(schema=scenario.SCHEMA,closure=[hex(r) for r in units],limits=scenario.LIMITS,
            scenario_sha256=c.digest(Path(scenario.__file__)))
        if hasattr(scenario, 'SERVICE_BOUNDARY'):
            row['service_boundary'] = scenario.SERVICE_BOUNDARY
        row['scenario_helper_sha256'] = {
            str(p):c.digest(p) for p in getattr(scenario, 'HELPERS', ())}
        row['input_pins'] = {str(p):sha for p,sha in getattr(scenario, 'INPUT_PINS', {}).items()}
    row['compared'] = ['eight final GPRs', f'{len(pages_order)} complete 4096-byte pages including stack']
    def command(name,argv,data=None):
        rec = dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=c.ROOT,timeout=180)
        rec.update(exit_code=child.returncode,seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    stage = 'preflight'
    try:
        c.require(all(c.digest(Path(p)) == sha for p,sha in row.get('input_pins', {}).items()))
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e';c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        c.require(all(sha == c.digest(pristine/n) for n,sha in row['upstream_files'].items()))
        row['native_service_sha256'] = {n:c.digest(c.ROOT/n) for n in
            ('native/src/guest_heap.cpp','native/include/ts2/guest_heap.hpp','native/src/guest_memory.cpp','native/src/guest_dispatch.cpp')}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        from capstone import CS_GRP_CALL
        from capstone.x86 import X86_OP_IMM
        nodes,bodies,code_pages,returns = {},{},{heap.SERVICE:bytes(4096)},[]
        indirect_return = None
        stage = 'fresh-lifts'
        for r,(size,count,pin) in units.items():
            code = pe.get_data(r,size);c.require(hashlib.sha256(code).hexdigest() == pin)
            tail_targets = {tail_wrapper:tail_body} if scenario is None else getattr(
                scenario, 'TAIL_WRAPPERS', {tail_wrapper:tail_body})
            if r in tail_targets:
                fn,ns,meta = heap.decode_wrapper(code,LinearInstruction,rva=r,size=size,
                    count=count,pin=pin,target=tail_targets[r])
            else:
                fn,ns,_,flow = decode_flow(code,c.BASE+r,LinearInstruction)
                meta = dict(flow,instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)])
            c.require(len(ns) == count and meta['size_bytes'] == size)
            index = indexes[r];checked = crosscheck_index(json.loads(index.read_text()),meta,r)
            fn.name = f'capacity_{r:X}';start = time.monotonic()
            body = Lifter(precise_carry=True).lift_function(fn)
            c.require(body.strip() and supported(body));bodies[r] = body
            row['functions'][hex(r)] = dict(size=size,instructions=count,function_sha256=pin,
                index=checked,index_sha256=c.digest(index),lift_seconds=time.monotonic()-start,
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+r),name=fn.name),
                dependencies=dependencies(ns,pe))
            (output/f'{r:x}.c').write_text(body)
            for i in ns.values():
                if i.group(CS_GRP_CALL):
                    if i.operands[0].type == X86_OP_IMM:
                        if i.operands[0].imm-c.BASE in units:returns.append((c.BASE+r,i.operands[0].imm,i.address+i.size))
                    elif r == tail_body:indirect_return = i.address+i.size
            nodes.update(ns);page = c.BASE+(r//4096)*4096
            code_pages.setdefault(page,bytearray(4096))[r%4096:r%4096+size] = code
        row['lifted'] = True;c.require(indirect_return is not None)
        stage = 'original-reference';start = time.monotonic()
        expected,inputs,visited = [],bytearray(),set()
        traces = []
        row['service_calls_per_case'] = []
        for n in range(64):
            regs,pages = make_state(n);model = make_model()
            options = {} if scenario is None else dict(getattr(scenario, 'REFERENCE_OPTIONS', {}))
            if scenario is not None and hasattr(scenario, 'assemble_traced'):
                trace = []
                options['call_trace'] = trace
                traces.append(trace)
            result,seen = c.reference(nodes,code_pages,c.BASE+entry_rva,regs,pages,
                image_pages=image_pages,heap_service=model,checked_repeat_copy=True,
                extra_data_pages=extra_pages, **options)
            check_contract(regs,pages,result,model);visited |= seen
            row['service_calls_per_case'].append(model.calls)
            expected.append(dict(case=n,**result))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in pages_order))
        row.update(x86_contract_matches=64,reference_seconds=time.monotonic()-start,
            coverage=dict(visited=len(visited),total=len(nodes)),
            per_unit_coverage={hex(r):sum(c.BASE+r <= a < c.BASE+r+s for a in visited) for r,(s,_,_) in units.items()})
        # Pin the exercised path, not just successful final-state coincidence.
        c.require(row['per_unit_coverage'] == ({'0x2790':13,'0x26b0':26,
            '0x1af0':44,'0x831a6f':5,'0x8461f2':19} if scenario is None else scenario.COVERAGE))
        (output/'reference.json').write_text(json.dumps(expected));(output/'input.bin').write_bytes(inputs)
        if traces:
            (output/'call-traces.json').write_text(json.dumps(traces)+'\n')
            row['call_traces_sha256'] = c.digest(output/'call-traces.json')
            source = scenario.assemble_traced(bodies,returns,indirect_return,traces)
        else:
            source = make_transport(bodies,returns,indirect_return)
        transport = output/'transport.cpp';transport.write_text(source)
        for mode in MODES:
            bridge = output/(mode+'.cpp');bridge.write_text(make_bridge(mode))
            for isa in ('host','arm64'):
                stage = mode+'-'+isa;binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa == 'host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,*[c.ROOT/'native/src'/name for name in
                    ('guest_memory.cpp','guest_dispatch.cpp','guest_heap.cpp')],'-lm','-o',binary])
                header = binary.read_bytes()[:20]
                c.require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little') == (62 if isa == 'host' else 183))
                command(stage+'-execute',[binary] if isa == 'host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage] = dict(compiled=True,**assess_output((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                row['host_native_executed' if isa == 'host' else 'arm64_executed'] = True
        row['artifact_sha256'] = {p.name:c.digest(p) for p in [transport,output/'input.bin',output/'reference.json',
            *[output/f'{r:x}.c' for r in units],*[output/(mode+'.cpp') for mode in MODES],
            *[output/(mode+'-'+isa) for mode in MODES for isa in ('host','arm64')]]}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        c.require(all(c.digest(c.ROOT/n) == sha for n,sha in row['native_service_sha256'].items()))
        c.require(c.digest(Path(__file__)) == row['harness_sha256'])
        c.require(c.digest(Path(c.reference.__code__.co_filename)) == row['reference_harness_sha256'])
        c.require(all(c.digest(Path(m.__file__)) == row['helper_sha256'][Path(m.__file__).name] for m in (c,heap,prefix)))
        c.require(c.digest(c.TEMPLATE) == row['template_sha256'] and c.digest(c.BRIDGE) == row['bridge_sha256'])
        if scenario is not None:
            c.require(c.digest(Path(scenario.__file__)) == row['scenario_sha256'])
            c.require(all(c.digest(Path(p)) == sha for p,sha in row['scenario_helper_sha256'].items()))
            c.require(all(c.digest(Path(p)) == sha for p,sha in row['input_pins'].items()))
        row.update(success=True,original_behaviour_newly_executable=[
            '2790/26B0/1AF0 empty-descriptor default allocation path' if scenario is None else scenario.BEHAVIOUR])
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__);raise
    finally:(output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--indexes',type=Path,required=True,help='JSON object: RVA -> existing private index envelope path')
    p.add_argument('--output',type=Path,required=True)
    a = p.parse_args()
    try:run({int(k,16):Path(v) for k,v in json.loads(a.indexes.read_text()).items()},a.output)
    except Exception:p.exit(1,'Capacity comparison rejected; inspect private receipt.\n')
    print('Empty-descriptor capacity allocation compared on host/AArch64; NOT full function/Windows/Android.')


if __name__ == '__main__':main()
