#!/usr/bin/env python3
"""Fresh 849A00 success-path differential; explicit portable zeroing, not Windows.

Reuses the checked heap transport, never a previous lifted body. Private outputs
include original-derived code/state and must remain in ignored work/.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import execute_heap_success as h
c = h.c
RVA, SIZE, COUNT = 0x849a00, 93, 39
PIN = '2667a9d13c74c15946f60d627cd7b8769536c2d0201e688165f1338d626a9869'
WRAPPER, WRAPPER_SIZE, WRAPPER_COUNT = 0x83a371, 11, 5
WRAPPER_PIN = 'e2e8a2e4341d73d16399f25e011ce4964ba59552b64a61a007adb48efa90e053'
PAIRS = ((64,4),(1,256),(256,1),(0,4),(4,0),(0,0),(1,1),(1,7),
         (1,8),(3,3),(1,4096),(512,8),(1,4095),(17,17),(7,73),(2,1032))


def state(n):
    regs,pages,_ = h.state(n)
    count,width = PAIRS[n % len(PAIRS)]
    struct.pack_into('<3I',pages[c.DATA_PAGES[0]],regs['esp']-c.DATA_PAGES[0],
                     c.RETURN,count,width)
    return regs,pages,count*width


class ZeroModel(h.HeapModel):
    """Independent occupancy/byte-array policy; no native heap code reused."""
    def invoke(self,cpu,ids,return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4080 and sp % 4 == 0)
        ret,handle,flags,size = struct.unpack('<4I',bytes(cpu.mem_read(sp,16)))
        c.require(ret == return_pc and handle == h.HANDLE and flags == 8)
        c.require(size == max(1,self.expected_size) and self.calls == 0)
        units = (size+7)//8
        start = next((i for i in range(513-units) if not any(self.occupied[i:i+units])),None)
        result = 0
        if start is not None:
            self.occupied[start:start+units] = [True]*units
            result = h.ARENA+8*start
            cpu.mem_write(result,bytes(8*units))
        cpu.reg_write(ids['eax'],result); cpu.reg_write(ids['esp'],sp+16)
        cpu.reg_write(x.UC_X86_REG_EIP,ret)
        self.calls += 1


def contract(regs,pages,result,model):
    c.require(model.calls == 1)
    c.require(result['regs'][0] == h.ARENA and result['regs'][-1] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    expected = {p:bytearray(data) for p,data in pages.items()}
    rounded = (max(1,model.expected_size)+7)//8*8
    expected[h.ARENA][:rounded] = bytes(rounded)
    raw = bytes.fromhex(result['pages'])
    c.require(len(raw) == len(h.PAGES)*4096)
    c.require(raw[4096:] == b''.join(expected[p] for p in h.PAGES[1:]))


def run(index,output,wrapper_index=None):
    output = c.private_output(output)
    sources = [Path(__file__),Path(h.__file__),Path(c.__file__),c.TEMPLATE,c.BRIDGE,
               Path(c.reference.__code__.co_filename),Path(h.decode_flow.__code__.co_filename),
               Path(h.crosscheck_index.__code__.co_filename)]
    row = dict(schema='ts2-calloc-success-native/1',success=False,rva=hex(RVA),
        image_sha256=c.IMAGE_SHA,pcrecomp_revision=c.REVISION,stub=False,
        invocation=[sys.executable,*sys.argv],commands=[],runs={},lifted=False,
        host_native_executed=False,arm64_executed=False,android_executed=False,
        whole_function_verified=False,windows_heap_verified=False,
        source_sha256={str(p):c.digest(p) for p in sources},index_sha256=c.digest(index),
        limits=['849A00 successful first allocation only; overflow/retry/error paths reject',
                'Synthetic heap token/global/IAT and independent portable zeroing MODEL, NOT Windows',
                'Eight final GPRs and six complete pages; no flags/FP/PC/transient native stores',
                'No 83A371 thunk, actual caller/1820 creation, startup, E3/E4 or Android'])
    composed = wrapper_index is not None
    if composed:
        row.update(schema='ts2-calloc-tail-success-native/1',rva=hex(WRAPPER),
            closure=[hex(WRAPPER),hex(RVA)],tail_stack_frame_preserved=True)
        row['limits'][-1] = '83A371 success tail only; no actual caller/1820 creation, startup, E3/E4 or Android'
    def command(name,argv,data=None):
        rec = dict(name=name,argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            proc = subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=c.ROOT,timeout=180)
        rec.update(exit_code=proc.returncode,seconds=time.monotonic()-start)
        c.require(proc.returncode == 0)
    stage = 'preflight'
    try:
        image = c.ROOT/'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        upstream = c.ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = c.ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        c.verify(pristine)
        locked = json.loads((c.ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        c.require(all(c.digest(upstream/n) == c.digest(pristine/n) for n in used))
        row['upstream_files'] = {n:c.digest(upstream/n) for n in used}
        native = [c.ROOT/'native/src'/n for n in ('guest_heap.cpp','guest_memory.cpp','guest_dispatch.cpp')]
        native += [c.ROOT/'native/include/ts2/guest_heap.hpp']
        row['native_sha256'] = {str(p):c.digest(p) for p in native}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(RVA,SIZE); c.require(h.hashlib.sha256(code).hexdigest() == PIN)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        function,nodes,_,flow = h.decode_flow(code,c.BASE+RVA,LinearInstruction)
        c.require(len(nodes) == COUNT and flow['size_bytes'] == SIZE)
        metadata = dict(size_bytes=SIZE,instructions=COUNT,instruction_rvas=[hex(a-c.BASE) for a in sorted(nodes)])
        row['index'] = h.crosscheck_index(json.loads(index.read_text()),metadata,RVA)
        deps = h.dependencies(nodes,pe); row['dependencies'] = deps
        c.require(deps['direct_calls'] == ['0x8437c6','0x842a91','0x831b17'])
        c.require(deps['indirect_calls'] == 1 and deps['indirect_call_sites'][0]['slot_rva'] == '0xd9a1d8')
        c.require(deps['indirect_call_sites'][0]['import_metadata']['name'] == 'HeapAlloc')
        c.require(deps['absolute_memory_va'] == [hex(h.IAT),hex(h.GLOBAL)] and not deps['segmented_memory_operands'])
        stage = 'fresh-lift'; function.name = 'heap_success'; started = time.monotonic()
        body = Lifter(precise_carry=True).lift_function(function)
        c.require(body.strip() and h.supported(body)); (output/'lifted.c').write_text(body)
        row.update(lifted=True,lift_seconds=time.monotonic()-started,function_sha256=PIN,
            lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+RVA),name=function.name))
        wrapper_nodes, wrapper_body = {}, None
        if composed:
            wrapper_code = pe.get_data(WRAPPER,WRAPPER_SIZE)
            wf,wrapper_nodes,metadata = h.decode_wrapper(wrapper_code,LinearInstruction,
                rva=WRAPPER,size=WRAPPER_SIZE,count=WRAPPER_COUNT,pin=WRAPPER_PIN,target=RVA)
            row['wrapper_index'] = h.crosscheck_index(json.loads(wrapper_index.read_text()),metadata,WRAPPER)
            row['wrapper_index_sha256'] = c.digest(wrapper_index)
            wf.name = 'default_allocator'; started = time.monotonic()
            wrapper_body = Lifter(precise_carry=True).lift_function(wf)
            c.require(wrapper_body.strip() and h.supported(wrapper_body))
            row.update(wrapper_lift_seconds=time.monotonic()-started,wrapper_function_sha256=WRAPPER_PIN,
                wrapper_lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+WRAPPER),name=wf.name))
            (output/'wrapper-lifted.c').write_text(wrapper_body)
        indirect = c.BASE+int(deps['indirect_call_sites'][0]['call_rva'],16)
        return_pc = indirect+nodes[indirect].size
        block = bytearray(4096); block[RVA%4096:RVA%4096+SIZE] = code
        cp = {c.BASE+RVA//4096*4096:block,h.SERVICE:bytes(4096)}
        from capstone import CS_GRP_CALL
        calls = {a for a,i in nodes.items() if i.group(CS_GRP_CALL)}
        if composed:
            wp = bytearray(4096)
            wp[WRAPPER%4096:WRAPPER%4096+WRAPPER_SIZE] = wrapper_code
            cp[c.BASE+WRAPPER//4096*4096] = wp
            nodes.update(wrapper_nodes)
        stage = 'original-reference'; started = time.monotonic()
        expected,inputs,visited = [],bytearray(),set()
        for n in range(64):
            regs,pages,size = state(n); model = ZeroModel(size)
            result,seen = c.reference(nodes,cp,c.BASE+(WRAPPER if composed else RVA),regs,pages,image_pages=h.IMAGES,heap_service=model,
                checked_calloc_arithmetic=True)
            contract(regs,pages,result,model); c.require(seen & calls == {indirect})
            expected.append(dict(case=n,**result)); visited |= seen
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in h.PAGES))
        if composed:
            c.require(set(wrapper_nodes) <= visited)
            row['wrapper_coverage'] = dict(visited=len(set(wrapper_nodes)&visited),total=WRAPPER_COUNT)
        row.update(x86_contract_matches=64,reference_seconds=time.monotonic()-started,
            coverage=dict(visited=len(visited),total=len(nodes)))
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'
        text = h.assemble(body,{int(r,16) for r in deps['direct_calls']},return_pc,rva=RVA,size=SIZE)
        if composed:
            text = h.compose_transport(text,wrapper_body,rva=RVA,wrapper=WRAPPER)
        transport.write_text(text)
        for mode in h.MODES:
            bridge = output/(mode+'.cpp'); text = h.bridge_source(mode,rva=RVA)
            bridge.write_text(h.compose_bridge(text,rva=RVA,wrapper=WRAPPER) if composed else text)
            for isa in ('host','arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa == 'host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,*native[:3],'-lm','-o',binary])
                header = binary.read_bytes()[:20]
                c.require(header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20],'little') == (62 if isa == 'host' else 183))
                command(stage+'-execute',[binary] if isa == 'host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage] = dict(compiled=True,**c.assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                row['host_native_executed' if isa == 'host' else 'arm64_executed'] = True
        row['artifact_sha256'] = {n:c.digest(output/n) for n in ('lifted.c','transport.cpp','reference.json','input.bin')}
        if composed:
            row['artifact_sha256']['wrapper-lifted.c'] = c.digest(output/'wrapper-lifted.c')
            c.require(c.digest(wrapper_index) == row['wrapper_index_sha256'])
        c.require(c.digest(image) == c.IMAGE_SHA and c.digest(index) == row['index_sha256'])
        for group in ('source_sha256','native_sha256'):
            c.require(all(c.digest(Path(p)) == sha for p,sha in row[group].items()))
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        row.update(success=True,dependencies_newly_resolved=0,
            original_behaviour_newly_executable=[
                '83A371 success tail with real 849A00 and explicit portable zeroing' if composed else
                '849A00 success branch with explicit portable zeroing'])
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__); raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p.add_argument('--wrapper-index',type=Path,help='Freshly lift and execute 83A371 tail caller too')
    a = p.parse_args()
    try: run(a.index,a.output,a.wrapper_index)
    except Exception: p.exit(1,'Calloc success differential rejected; inspect private receipt.\n')
    print(('83A371 + actual 849A00' if a.wrapper_index else '849A00')+
          ' success + portable zeroing matched on host/AArch64; NOT Windows/Android/startup.')


if __name__ == '__main__': main()
