#!/usr/bin/env python3
"""8461F2 success-path lift against original x86 plus explicit portable heap model.

NOT Windows HeapAlloc verification: its import is an independently implemented
allocation service on each ISA. No retry/error responses or startup writes supplied.
All original-derived bodies, states and logs remain private under work/.
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
import execute_initialization_setter as c
from inspect_allocator_boundary import check_index
from inspect_startup_dependency import inspect_body, crosscheck_index
from measure_startup import decode_flow, dependencies, supported

RVA, SIZE, COUNT = 0x8461f2, 78, 32
PIN = 'cfc058933e429483a316f13222fb92c4d0c9bcab03e6f73037fd3f70c82a98a1'
IAT, GLOBAL = c.BASE+0xd9a1d8, c.BASE+0x10e0380
SERVICE, HANDLE, ARENA = 0x60000000, 0x13579bdf, c.DATA_PAGES[2]
IMAGES = (IAT & ~4095, GLOBAL & ~4095)
PAGES = (*c.DATA_PAGES, *IMAGES)
MODES = ('valid', 'wrong-result', 'wrong-cleanup')
REQUESTS = (0, 1, 7, 8, 9, 15, 16, 17, 528, 1032, 4088, 4096)
WRAPPER, WRAPPER_SIZE, WRAPPER_COUNT = 0x831a6f, 11, 5
WRAPPER_PIN = '2e5d070c4fb39b16ebad5ff9b74eacd97bdfee08e6a461ecd464af2396f716d6'


def decode_wrapper(code, instruction_wrapper, *, rva=None, size=None,
                   count=None, pin=None, target=None):
    """Pinned straight-line tail thunk; never treat an escaping JMP as a CALL.

    decode_flow deliberately rejects external normal-flow edges. Keep that gate:
    this bounded decoder admits exactly one final direct tail edge to the
    explicitly pinned target (8461F2 by default).
    """
    # Resolve defaults at call time, preserving the existing authored-fixture
    # seam that temporarily pins module constants to a different byte range.
    rva = WRAPPER if rva is None else rva
    size = WRAPPER_SIZE if size is None else size
    count = WRAPPER_COUNT if count is None else count
    pin = WRAPPER_PIN if pin is None else pin
    target = RVA if target is None else target
    from types import SimpleNamespace
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
    from capstone.x86 import X86_OP_IMM
    c.require(len(code) == size and hashlib.sha256(code).hexdigest() == pin)
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    nodes = {i.address:i for i in md.disasm(code,c.BASE+rva)}
    c.require(len(nodes) == count and sum(i.size for i in nodes.values()) == size)
    seq = list(nodes.values())
    c.require(all(not any(i.group(g) for g in (CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET)) for i in seq[:-1]))
    tail = seq[-1]
    c.require(tail.mnemonic == 'jmp' and len(tail.operands) == 1 and
        tail.operands[0].type == X86_OP_IMM and tail.operands[0].imm == c.BASE+target)
    function = SimpleNamespace(name='default_allocator',address=c.BASE+rva,
        blocks={c.BASE+rva:SimpleNamespace(start=c.BASE+rva,
            instructions=[instruction_wrapper(i) for i in seq])})
    metadata = dict(size_bytes=size,instructions=count,
        instruction_rvas=[hex(a-c.BASE) for a in nodes])
    return function,nodes,metadata


def compose_transport(text, wrapper_body, *, rva=RVA, wrapper=WRAPPER):
    """Keep both generated bodies verbatim and preserve the tail's stack frame."""
    RVA, WRAPPER = rva, wrapper
    c.require(type(wrapper_body) is str and wrapper_body.strip() and supported(wrapper_body))
    changes = {
        'static void heap_success(void);':'static void default_allocator(void);\nstatic void heap_success(void);',
        f'case 0x{c.BASE+RVA:08X}u:heap_success();break;':
            f'case 0x{c.BASE+WRAPPER:08X}u:default_allocator();break;case 0x{c.BASE+RVA:08X}u:heap_success();break;',
        'static void heap_adapter(uint32_t* s)':
            f'static void default_adapter(uint32_t* s) {{select_body(0x{c.BASE+WRAPPER:08X}u,s);}}\nstatic void heap_adapter(uint32_t* s)',
        f'case 0x{c.BASE+RVA:08X}u:callback=heap_adapter;break;':
            f'case 0x{c.BASE+WRAPPER:08X}u:callback=default_adapter;break;case 0x{c.BASE+RVA:08X}u:callback=heap_adapter;break;',
        'if(g_cur_func!=0xA000FCF0u || target!=0xA0009550u) reject();':
            f'if(g_cur_func!=0x{c.BASE+WRAPPER:08X}u || target!=0x{c.BASE+RVA:08X}u) reject();',
        f'cache_invoke(0x{c.BASE+RVA:08X}u,in,heap_adapter);':
            f'cache_invoke(0x{c.BASE+WRAPPER:08X}u,in,default_adapter);',
        'int main() {':wrapper_body+'\nint main() {',
    }
    for old,new in changes.items():
        c.require(text.count(old) == 1);text = text.replace(old,new)
    c.require(text.count(wrapper_body) == 1)
    return text


def compose_bridge(text, *, rva=RVA, wrapper=WRAPPER):
    RVA, WRAPPER = rva, wrapper
    old = f'constexpr std::array<uint32_t,2> targets{{0x{c.BASE+RVA:08X}u,0x{SERVICE:08X}u}};'
    c.require(text.count(old) == 1)
    return text.replace(old,f'constexpr std::array<uint32_t,3> targets{{0x{c.BASE+WRAPPER:08X}u,0x{c.BASE+RVA:08X}u,0x{SERVICE:08X}u}};')


class HeapModel:
    """Independent unit-occupancy model, not the native block-map algorithm."""
    target = SERVICE

    def __init__(self, expected_size):
        c.require(type(expected_size) is int and 0 <= expected_size <= 4096)
        self.expected_size = expected_size
        self.occupied = [False]*512
        self.calls = 0

    def invoke(self, cpu, ids, return_pc):
        import unicorn.x86_const as x
        sp = cpu.reg_read(ids['esp'])
        c.require(c.DATA_PAGES[0] <= sp <= c.DATA_PAGES[0]+4096-16 and sp % 4 == 0)
        ret, handle, flags, size = struct.unpack('<4I', bytes(cpu.mem_read(sp,16)))
        c.require(ret == return_pc and handle == HANDLE and flags == 0)
        # 8461F2 promotes malloc(0) to a one-byte HeapAlloc request.
        c.require(size == max(1,self.expected_size) and self.calls == 0)
        count = max(1,(size+7)//8)
        start = next((i for i in range(513-count) if not any(self.occupied[i:i+count])), None)
        result = 0
        if start is not None:
            self.occupied[start:start+count] = [True]*count
            result = ARENA+8*start
        cpu.reg_write(ids['eax'],result)
        cpu.reg_write(ids['esp'],sp+16)
        cpu.reg_write(x.UC_X86_REG_EIP,ret)
        self.calls += 1


def state(n):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random(0x8461f200+n)
    regs = {r:rng.getrandbits(32) for r in c.REGS}
    regs['esp'] = c.DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    pages = {p:bytearray(rng.randbytes(4096)) for p in PAGES}
    size = REQUESTS[n % len(REQUESTS)] if n < 32 else rng.randrange(4097)
    struct.pack_into('<II',pages[c.DATA_PAGES[0]],regs['esp']-c.DATA_PAGES[0],c.RETURN,size)
    struct.pack_into('<I',pages[IMAGES[0]],IAT-IMAGES[0],SERVICE)
    struct.pack_into('<I',pages[IMAGES[1]],GLOBAL-IMAGES[1],HANDLE)
    return regs,pages,size


def contract(regs,pages,result,model):
    c.require(model.calls == 1)
    c.require(result['regs'][0] == ARENA and result['regs'][-1] == regs['esp']+4)
    for r in ('ebx','esi','edi','ebp'):
        c.require(result['regs'][c.REGS.index(r)] == regs[r])
    data = bytes.fromhex(result['pages'])
    c.require(len(data) == len(PAGES)*4096)
    # The allocation is dirty/uninitialized by contract. All non-stack pages,
    # including heap and explicit read-only IAT/global inputs, must stay intact.
    c.require(data[4096:] == b''.join(pages[p] for p in PAGES[1:]))


def assemble(body, direct, indirect, *, rva=RVA, size=SIZE):
    RVA, SIZE = rva, size
    c.require(type(body) is str and body.strip() and supported(body))
    c.require(set(direct) == {0x8437c6,0x842a91,0x831b17})
    c.require(type(indirect) is int and c.BASE+RVA < indirect < c.BASE+RVA+SIZE)
    replacements = {
        '@PROTOTYPES@':'static void heap_success(void);\n'+
            '\n'.join(f'static constexpr unsigned address_sub_{c.BASE+r:08X}=0x{c.BASE+r:08X}u;' for r in direct)+
            '\nextern "C" void heap_endpoint(uint32_t*);',
        '@SELECT@':f'case 0x{c.BASE+RVA:08X}u:heap_success();break;',
        '@ADAPTERS@':f'static void heap_adapter(uint32_t* s) {{select_body(0x{c.BASE+RVA:08X}u,s);}}',
        '@CALLBACKS@':f'case 0x{c.BASE+RVA:08X}u:callback=heap_adapter;break; case 0x{SERVICE:08X}u:callback=heap_endpoint;break;',
        # Error/retry paths retain their original body but cannot get responses.
        '@DIRECT_RETURNS@':'',
        '@INDIRECT_RETURNS@':f'if(caller==0x{c.BASE+RVA:08X}u && target==0x{SERVICE:08X}u) return 0x{indirect:08X}u;',
        '@BODY@':body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40);':f'cache_invoke(0x{c.BASE+RVA:08X}u,in,heap_adapter);',
    }
    text = c.TEMPLATE.read_text()
    for old,new in replacements.items():
        c.require(text.count(old) == 1); text = text.replace(old,new)
    c.require(text.count(body) == 1)
    return text


def bridge_source(mode, *, rva=RVA):
    RVA = rva
    c.require(mode in MODES)
    text = c.BRIDGE.read_text()
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    changes = {
        '#include "ts2/guest_memory.hpp"':'#include "ts2/guest_memory.hpp"\n#include "ts2/guest_heap.hpp"',
        '0xA0009000u,0xA0E17000u':f'0x{IMAGES[0]:08X}u,0x{IMAGES[1]:08X}u',
        old:f'constexpr std::array<uint32_t,2> targets{{0x{c.BASE+RVA:08X}u,0x{SERVICE:08X}u}};',
        'std::unique_ptr<ts2::GuestMemory> memory;':'std::unique_ptr<ts2::GuestMemory> memory;\nstd::unique_ptr<ts2::GuestHeap> heap;',
        '    memory=std::make_unique<ts2::GuestMemory>();':'    heap.reset();\n    memory=std::make_unique<ts2::GuestMemory>();',
        'extern "C" uint32_t cache_read':f'''extern "C" void heap_endpoint(uint32_t* s) {{
    if(!heap) heap=std::make_unique<ts2::GuestHeap>(*memory,0x{HANDLE:08X}u,0x{ARENA:08X}u,4096);
    ts2::GuestRegisters r{{s[0],s[2],s[3],s[1],s[7],s[6],s[4],s[5],0}};
    heap->invoke_allocate(r);
    s[0]=r.eax;s[7]=r.esp;
}}
extern "C" uint32_t cache_read''',
    }
    for old,new in changes.items():
        c.require(text.count(old) == 1); text = text.replace(old,new)
    if mode != 'valid':
        old = '    s[0]=r.eax;s[7]=r.esp;'
        c.require(text.count(old) == 1)
        text = text.replace(old,old+ ('s[0]+=8;' if mode == 'wrong-result' else 's[7]+=4;'))
    return text


def run(index,output,wrapper_index=None):
    output = c.private_output(output)
    row = dict(schema='ts2-heap-success-native/1',success=False,rva=hex(RVA),
        image_sha256=c.IMAGE_SHA,pcrecomp_revision=c.REVISION,
        invocation=[sys.executable,*sys.argv],harness_sha256=c.digest(Path(__file__)),
        reference_harness_sha256=c.digest(Path(c.reference.__code__.co_filename)),
        template_sha256=c.digest(c.TEMPLATE),bridge_sha256=c.digest(c.BRIDGE),
        commands=[],runs={},lifted=False,host_native_executed=False,arm64_executed=False,
        android_executed=False,stub=False,windows_heap_verified=False,whole_function_verified=False,
        service_boundary=dict(target=hex(SERVICE),kind='explicit portable guest heap',
            x86='independent occupancy model',native='production GuestHeap',
            original_windows_import_executed=False),
        limits=['Successful first allocation only; retry/error paths reject and remain unverified',
            'Synthetic heap token/IAT/global inputs, NOT original startup initialization/ownership',
            'Eight final GPRs/six pages; no flags/FP/PC/transient-store comparison',
            'Diagnostic GuestMemory/GuestDispatch composition, not whole malloc/opener/1AB665/E4 or Android'])
    composed = wrapper_index is not None
    if composed:
        row.update(schema='ts2-default-allocator-success-native/1',rva=hex(WRAPPER),
            closure=[hex(WRAPPER),hex(RVA)],tail_stack_frame_preserved=True)
        row['limits'].append('831A6F successful default path only; no capacity caller or upstream ownership proof')
    stage = 'preflight'
    def command(name,argv,data=None):
        rec = dict(name=name,argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'],input=data,stdout=out,stderr=err,cwd=c.ROOT,timeout=180)
        rec.update(exit_code=child.returncode,seconds=time.monotonic()-start)
        c.require(child.returncode == 0)
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
        native_files = ['native/src/guest_heap.cpp','native/include/ts2/guest_heap.hpp',
                        'native/src/guest_memory.cpp','native/src/guest_dispatch.cpp']
        row['native_service_sha256'] = {n:c.digest(c.ROOT/n) for n in native_files}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == c.BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(RVA,SIZE)
        c.require(hashlib.sha256(code).hexdigest() == PIN)
        row['index'] = check_index(json.loads(index.read_text()),inspect_body(code,c.BASE+RVA))
        row['index_sha256'] = c.digest(index)
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        c.require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        function,nodes,_,flow = decode_flow(code,c.BASE+RVA,LinearInstruction)
        c.require(len(nodes) == COUNT and flow['size_bytes'] == SIZE)
        deps = dependencies(nodes,pe); row['dependencies'] = deps
        c.require(deps['direct_calls'] == ['0x8437c6','0x842a91','0x831b17'])
        c.require(deps['indirect_calls'] == 1 and deps['indirect_call_sites'][0]['slot_rva'] == '0xd9a1d8')
        c.require(deps['indirect_call_sites'][0]['import_metadata']['name'] == 'HeapAlloc')
        c.require(deps['absolute_memory_va'] == [hex(IAT),hex(GLOBAL)] and not deps['segmented_memory_operands'])
        stage = 'fresh-lift'; function.name = 'heap_success'; start = time.monotonic()
        body = Lifter(precise_carry=True).lift_function(function)
        c.require(supported(body) and body.strip())
        row['lift_seconds'] = time.monotonic()-start
        (output/'lifted.c').write_text(body)
        row.update(lifted=True,function_sha256=PIN,lift_invocation=dict(api='Lifter(precise_carry=True).lift_function',address=hex(c.BASE+RVA),name=function.name))
        wrapper_nodes, wrapper_body = {}, None
        if composed:
            wrapper_code = pe.get_data(WRAPPER,WRAPPER_SIZE)
            wrapper_function,wrapper_nodes,metadata = decode_wrapper(wrapper_code,LinearInstruction)
            row['wrapper_index'] = crosscheck_index(json.loads(wrapper_index.read_text()),metadata,WRAPPER)
            row['wrapper_index_sha256'] = c.digest(wrapper_index)
            row['wrapper_function_sha256'] = WRAPPER_PIN
            start = time.monotonic()
            wrapper_body = Lifter(precise_carry=True).lift_function(wrapper_function)
            c.require(supported(wrapper_body) and wrapper_body.strip())
            row['wrapper_lift_seconds'] = time.monotonic()-start
            row['wrapper_lift_invocation'] = dict(api='Lifter(precise_carry=True).lift_function',
                address=hex(c.BASE+WRAPPER),name=wrapper_function.name)
            (output/'wrapper-lifted.c').write_text(wrapper_body)
        from capstone import CS_GRP_CALL
        calls = [i for i in nodes.values() if i.group(CS_GRP_CALL)]
        indirect = c.BASE+int(deps['indirect_call_sites'][0]['call_rva'],16)
        return_pc = nodes[indirect].address+nodes[indirect].size
        code_page = bytearray(4096); code_page[RVA%4096:RVA%4096+SIZE] = code
        code_pages = {c.BASE+(RVA//4096)*4096:code_page,SERVICE:bytes(4096)}
        if composed:
            page = bytearray(4096)
            page[WRAPPER%4096:WRAPPER%4096+WRAPPER_SIZE] = wrapper_code
            code_pages[c.BASE+WRAPPER//4096*4096] = page
            nodes.update(wrapper_nodes)
        stage = 'original-reference'; start = time.monotonic()
        expected,inputs,visited = [],bytearray(),set()
        for n in range(64):
            regs,pages,size = state(n); model = HeapModel(size)
            result,seen = c.reference(nodes,code_pages,c.BASE+(WRAPPER if composed else RVA),regs,pages,image_pages=IMAGES,heap_service=model)
            contract(regs,pages,result,model)
            c.require(seen & {i.address for i in calls} == {indirect})
            expected.append(dict(case=n,**result)); visited |= seen
            inputs.extend(struct.pack('<8I',*(regs[r] for r in c.REGS)))
            inputs.extend(b''.join(pages[p] for p in PAGES))
        c.require(len(visited) == (26 if composed else 21))
        if composed:
            c.require(set(wrapper_nodes) <= visited)
            row['wrapper_coverage'] = dict(visited=len(set(wrapper_nodes)&visited),total=WRAPPER_COUNT)
        row.update(x86_contract_matches=64,reference_seconds=time.monotonic()-start,
                   coverage=dict(visited=len(visited),total=len(nodes)))
        (output/'reference.json').write_text(json.dumps(expected)); (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'
        transport_text = assemble(body,{int(r,16) for r in deps['direct_calls']},return_pc)
        if composed:
            transport_text = compose_transport(transport_text,wrapper_body)
        transport.write_text(transport_text)
        for mode in MODES:
            bridge = output/(mode+'.cpp')
            bridge_text = bridge_source(mode)
            bridge.write_text(compose_bridge(bridge_text) if composed else bridge_text)
            for isa in ('host','arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(c.ROOT/'native/include'),transport,bridge,*[c.ROOT/'native/src'/name for name in
                    ('guest_memory.cpp','guest_dispatch.cpp','guest_heap.cpp')],'-lm','-o',binary])
                h = binary.read_bytes()[:20]
                c.require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [c.ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage] = dict(compiled=True,**c.assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                row['host_native_executed' if isa=='host' else 'arm64_executed'] = True
        row['artifact_sha256'] = {n:c.digest(output/n) for n in ('lifted.c','transport.cpp','reference.json','input.bin')}
        c.require(c.digest(image) == c.IMAGE_SHA)
        c.require(all(c.digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        c.require(all(c.digest(c.ROOT/n) == sha for n,sha in row['native_service_sha256'].items()))
        row.update(success=True,dependencies_newly_resolved=0,
            original_behaviour_newly_executable=[
                '0x831a6f success tail path with real 8461F2 and portable service' if composed else
                '0x8461f2 success path with portable service'])
        if composed:
            row['artifact_sha256']['wrapper-lifted.c'] = c.digest(output/'wrapper-lifted.c')
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__); raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p.add_argument('--wrapper-index',type=Path,help='Also freshly lift/execute actual 831A6F tail caller')
    a = p.parse_args()
    try: run(a.index,a.output,a.wrapper_index)
    except Exception: p.exit(1,'Heap success differential failed; inspect private receipt.\n')
    print(('831A6F + actual 8461F2' if a.wrapper_index else '8461F2')+
        ' success + portable heap: 64 cases per ISA; NOT Windows/Android/startup.')


if __name__ == '__main__': main()
