#!/usr/bin/env python3
"""Fresh original realloc thunk/body vs explicit portable service, NOT Windows.

Only nonnull, nonzero successful requests; unknown callees fail closed. All
original-derived artifacts are exclusively written under ignored work/.
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
import execute_heap_success as heap
from inspect_startup_dependency import crosscheck_index
from measure_startup import decode_flow, dependencies, supported
c = heap.c
RVA, SIZE, COUNT = 0x85217f, 105, 44
WRAPPER = 0x8413b0
PIN = '9f8cac1bc55158aa8a1779a3ccf60c83a34c69a8e7313fc5a3aaa17b5ccbb57d'
WRAPPER_PIN = 'bf06b9a1f6fd0deebe481f21d1dd0844791bc1e7e5e6ac9a886b3ba57e9a16e3'
IAT = c.BASE+0xd9a380
REQUESTS = (1,7,8,9,63,64,65,127,128,129,528,1032,3968)
MODES = ('valid','wrong-copy','wrong-cleanup')


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    regs,pages,_ = heap.state(n)
    size = REQUESTS[n % len(REQUESTS)]
    struct.pack_into('<III',pages[c.DATA_PAGES[0]],regs['esp']-c.DATA_PAGES[0],c.RETURN,heap.ARENA,size)
    # Model ownership independently on each side: two live 64-byte allocations;
    # the second obstructs adjacent growth, forcing a move for requests >64.
    struct.pack_into('<I',pages[heap.IMAGES[0]],IAT-heap.IMAGES[0],heap.SERVICE)
    return regs,pages,size


class ReallocateModel:
    """Cell occupancy + byte copy, independent of native extent-map machinery."""
    target = heap.SERVICE

    def __init__(self, size):
        # 120 is the independently observed owned-empty capacity growth request.
        # Keep the standalone corpus unchanged while permitting that composition.
        c.require(type(size) is int and size in (*REQUESTS, 120))
        self.expected_size = size
        self.calls = 0
        self.occupied = [i < 16 for i in range(512)]

    def invoke(self, cpu, ids, return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4096-20 and sp % 4 == 0)
        ret,handle,flags,old,size = struct.unpack('<5I',bytes(cpu.mem_read(sp,20)))
        c.require(ret == return_pc and handle == heap.HANDLE and flags == 0)
        c.require(old == heap.ARENA and size == self.expected_size and self.calls == 0)
        cells = (size+7)//8
        if size <= 64:
            start = 0
            self.occupied[cells:8] = [False]*(8-cells)
        else:
            start = next((i for i in range(513-cells) if not any(self.occupied[i:i+cells])),None)
            c.require(start is not None)
            self.occupied[start:start+cells] = [True]*cells
            cpu.mem_write(heap.ARENA+8*start,bytes(cpu.mem_read(old,64)))
            self.occupied[:8] = [False]*8
        cpu.reg_write(ids['eax'],heap.ARENA+8*start)
        cpu.reg_write(ids['esp'],sp+20)
        cpu.reg_write(x.UC_X86_REG_EIP,ret)
        self.calls += 1


def contract(regs,pages,result,model):
    c.require(model.calls == 1)
    expected = heap.ARENA+(128 if model.expected_size > 64 else 0)
    c.require(result['regs'][0] == expected and result['regs'][7] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    after = {p:bytearray(b) for p,b in pages.items()}
    if expected != heap.ARENA:
        after[heap.ARENA][128:192] = pages[heap.ARENA][:64]
    data = bytes.fromhex(result['pages'])
    c.require(len(data) == len(heap.PAGES)*4096)
    c.require(data[4096:] == b''.join(after[p] for p in heap.PAGES[1:]))


def assemble(bodies, direct, return_pc):
    c.require(set(bodies) == {WRAPPER,RVA} and all(b.strip() and supported(b) for b in bodies.values()))
    targets = {0x8461f2,0x8461b8,0x831b17,0x8437c6,0x842a91}
    c.require(set(direct) == targets and c.BASE+RVA < return_pc < c.BASE+RVA+SIZE)
    changes = {
        '@PROTOTYPES@':'\n'.join(f'static void reallocate_{r:X}(void);' for r in bodies)+'\n'+
            '\n'.join(f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;' for r in targets)+'\nextern "C" void heap_endpoint(uint32_t*);',
        '@SELECT@':''.join(f'case 0x{c.BASE+r:08X}u:reallocate_{r:X}();break;' for r in bodies),
        '@ADAPTERS@':'\n'.join(f'static void adapter_{r:X}(uint32_t* s) {{select_body(0x{c.BASE+r:08X}u,s);}}' for r in bodies),
        '@CALLBACKS@':''.join(f'case 0x{c.BASE+r:08X}u:callback=adapter_{r:X};break;' for r in bodies)+f'case 0x{heap.SERVICE:08X}u:callback=heap_endpoint;break;',
        '@DIRECT_RETURNS@':'',
        '@INDIRECT_RETURNS@':f'if(caller==0x{c.BASE+RVA:08X}u && target==0x{heap.SERVICE:08X}u) return 0x{return_pc:08X}u;',
        '@BODY@':'\n'.join(bodies.values()),
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40);':f'cache_invoke(0x{c.BASE+WRAPPER:08X}u,in,adapter_{WRAPPER:X});',
        'if(g_cur_func!=0xA000FCF0u || target!=0xA0009550u) reject();':f'if(g_cur_func!=0x{c.BASE+WRAPPER:08X}u || target!=0x{c.BASE+RVA:08X}u) reject();',
    }
    text = c.TEMPLATE.read_text()
    for old,new in changes.items():
        c.require(text.count(old) == 1);text = text.replace(old,new)
    return text


def bridge_source(mode):
    c.require(mode in MODES)
    text = heap.bridge_source('valid')
    changes = {
        f'constexpr std::array<uint32_t,2> targets{{0x{c.BASE+heap.RVA:08X}u,0x{heap.SERVICE:08X}u}};':
            f'constexpr std::array<uint32_t,3> targets{{0x{c.BASE+WRAPPER:08X}u,0x{c.BASE+RVA:08X}u,0x{heap.SERVICE:08X}u}};',
        f'    if(!heap) heap=std::make_unique<ts2::GuestHeap>(*memory,0x{heap.HANDLE:08X}u,0x{heap.ARENA:08X}u,4096);':f'''    if(!heap) {{
        heap=std::make_unique<ts2::GuestHeap>(*memory,0x{heap.HANDLE:08X}u,0x{heap.ARENA:08X}u,4096);
        if(heap->allocate(0x{heap.HANDLE:08X}u,0,64)!=0x{heap.ARENA:08X}u ||
           heap->allocate(0x{heap.HANDLE:08X}u,0,64)!=0x{heap.ARENA+64:08X}u)
            throw std::runtime_error("ownership setup");
    }}''',
        'heap->invoke_allocate(r);':'heap->invoke_reallocate(r);',
    }
    # No image-page remapping is needed: both IAT slots are in the same page.
    for old,new in changes.items():
        c.require(text.count(old) == 1);text = text.replace(old,new)
    if mode == 'wrong-copy':
        old = '    s[0]=r.eax;s[7]=r.esp;'
        c.require(text.count(old) == 1)
        text = text.replace(old,old+'\n    memory->write32(r.eax,memory->read32(r.eax)^1u);')
    if mode == 'wrong-cleanup':
        old = '    current(s.data());'
        c.require(text.count(old) == 1)
        text = text.replace(old,old+'\n    if(depth==1) s[7]+=4;')
    return text


def run(index,wrapper_index,output):
    output = c.private_output(output)
    row = dict(schema='ts2-reallocate-success-native/1',success=False,stub=False,
        invocation=[sys.executable,*sys.argv],image_sha256=c.IMAGE_SHA,pcrecomp_revision=c.REVISION,
        functions={},commands=[],runs={},host_native_executed=False,arm64_executed=False,
        android_executed=False,windows_heap_verified=False,whole_function_verified=False,
        limits=['Nonnull nonzero success only; null/zero/retry/error dependencies fail closed',
                'Synthetic two-block ownership/IAT/global/token; no original startup or caller ownership proof',
                'Independent portable x86 service model vs production GuestHeap, NOT Windows HeapReAlloc',
                'Eight final GPRs/six pages, not flags/FP/PC/transient writes; no capacity composition/Android/gameplay'])
    sources = [Path(__file__),Path(heap.__file__),Path(c.__file__),c.TEMPLATE,c.BRIDGE,
        Path(c.reference.__code__.co_filename),Path(__file__).with_name('measure_startup.py'),
        Path(__file__).with_name('inspect_startup_dependency.py')]
    sources += [c.ROOT/n for n in ('native/src/guest_heap.cpp','native/include/ts2/guest_heap.hpp',
        'native/src/guest_memory.cpp','native/src/guest_dispatch.cpp')]
    row['source_sha256'] = {str(p.relative_to(c.ROOT)):c.digest(p) for p in sources}
    stage = 'preflight'
    def command(name,argv,data=None):
        rec = dict(name=name,argv=[str(a) for a in argv]);row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=c.ROOT,timeout=180)
        rec.update(exit_code=child.returncode,seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin';c.require(c.digest(image) == c.IMAGE_SHA)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e';c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        c.require(all(sha == c.digest(pristine/n) for n,sha in row['upstream_files'].items()))
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        nodes,bodies,code_pages = {},{},{heap.SERVICE:bytes(4096)}
        stage = 'fresh-lifts'
        for r,size,count,pin,idx in ((WRAPPER,11,5,WRAPPER_PIN,wrapper_index),(RVA,SIZE,COUNT,PIN,index)):
            code = pe.get_data(r,size);c.require(hashlib.sha256(code).hexdigest() == pin)
            if r == WRAPPER:
                fn,ns,meta = heap.decode_wrapper(code,LinearInstruction,rva=r,size=size,count=count,pin=pin,target=RVA)
            else:
                fn,ns,_,flow = decode_flow(code,c.BASE+r,LinearInstruction)
                meta = dict(flow,instruction_rvas=[hex(a-c.BASE) for a in sorted(ns)])
            c.require(len(ns) == count and meta['size_bytes'] == size)
            checked = crosscheck_index(json.loads(idx.read_text()),meta,r)
            fn.name = f'reallocate_{r:X}';start = time.monotonic()
            body = Lifter(precise_carry=True).lift_function(fn);c.require(body.strip() and supported(body))
            (output/f'{r:x}.c').write_text(body);bodies[r] = body
            row['functions'][hex(r)] = dict(size=size,instructions=count,function_sha256=pin,
                index=checked,index_sha256=c.digest(idx),lift_seconds=time.monotonic()-start,
                lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+r),name=fn.name))
            if r == RVA:
                deps = dependencies(ns,pe);row['dependencies'] = deps
                c.require(deps['indirect_calls'] == 1 and deps['indirect_call_sites'][0]['slot_rva'] == '0xd9a380')
                c.require(deps['indirect_call_sites'][0]['import_metadata']['name'] == 'HeapReAlloc')
                c.require(deps['absolute_memory_va'] == [hex(IAT),hex(heap.GLOBAL)] and not deps['segmented_memory_operands'])
                site = c.BASE+int(deps['indirect_call_sites'][0]['call_rva'],16)
                return_pc = site+ns[site].size
            nodes.update(ns);page = c.BASE+r//4096*4096
            code_pages.setdefault(page,bytearray(4096))[r%4096:r%4096+size] = code
        stage = 'original-reference';start = time.monotonic()
        expected,inputs,visited = [],bytearray(),set()
        for n in range(64):
            regs,pages,size = state(n);model = ReallocateModel(size)
            result,seen = c.reference(nodes,code_pages,c.BASE+WRAPPER,regs,pages,image_pages=heap.IMAGES,heap_service=model)
            contract(regs,pages,result,model);visited |= seen
            expected.append(dict(case=n,**result))
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)));inputs.extend(b''.join(pages[p] for p in heap.PAGES))
        c.require(set(a for a in nodes if c.BASE+WRAPPER <= a < c.BASE+WRAPPER+11) <= visited)
        c.require(site in visited)
        # Pin the observed success domain, not merely final-state coincidence.
        from capstone import CS_GRP_CALL
        c.require({a for a in visited if nodes[a].group(CS_GRP_CALL)} == {site})
        c.require(len(visited) == 30)
        row.update(reference_seconds=time.monotonic()-start,x86_contract_matches=64,
            coverage=dict(visited=len(visited),total=len(nodes)),
            per_unit_coverage={hex(r):sum(c.BASE+r <= a < c.BASE+r+s for a in visited) for r,s in ((WRAPPER,11),(RVA,SIZE))})
        (output/'reference.json').write_text(json.dumps(expected));(output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp';transport.write_text(assemble(bodies,{int(r,16) for r in deps['direct_calls']},return_pc))
        for mode in MODES:
            bridge = output/(mode+'.cpp');bridge.write_text(bridge_source(mode))
            for isa in ('host','arm64'):
                stage = mode+'-'+isa;binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa == 'host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,*[c.ROOT/'native/src'/n for n in
                    ('guest_memory.cpp','guest_dispatch.cpp','guest_heap.cpp')],'-lm','-o',binary])
                header = binary.read_bytes()[:20]
                c.require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little') == (62 if isa == 'host' else 183))
                command(stage+'-execute',[binary] if isa == 'host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                # assess requires all cases to differ for negative controls.
                row['runs'][stage] = dict(compiled=True,**c.assess((output/(stage+'-execute.stdout')).read_text(),expected,'wrong-result' if mode == 'wrong-copy' else mode))
                row['host_native_executed' if isa == 'host' else 'arm64_executed'] = True
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        c.require(all(c.digest(c.ROOT/n) == sha for n,sha in row['source_sha256'].items()))
        row['artifact_sha256'] = {p.name:c.digest(p) for p in output.iterdir() if p.is_file()}
        row.update(success=True,dependencies_newly_resolved=0,new_native_bodies=2,
            original_behaviour_newly_executable=['8413B0/85217F nonnull nonzero successful reallocation path'])
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__);raise
    finally:(output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index',type=Path,required=True);p.add_argument('--wrapper-index',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a = p.parse_args()
    try:run(a.index,a.wrapper_index,a.output)
    except Exception:p.exit(1,'Reallocation comparison rejected; inspect private receipt.\n')
    print('Original realloc success path compared host/AArch64; NOT Windows/Android/full closure.')


if __name__ == '__main__':main()
