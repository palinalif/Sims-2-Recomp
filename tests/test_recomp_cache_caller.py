"""Public authored bridge/transport controls; no original bodies or private fixtures."""
import importlib.util
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cache_caller',ROOT/'scripts/recomp/execute_cache_caller.py')
b=importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class CacheCallerTests(unittest.TestCase):
    def test_receiver_handle_binding_and_disjoint_pages(self):
        for n in range(64):
            regs,pages=b.caller_state(n,random.Random(17),{p:bytes(4096) for p in b.IMAGE_PAGES})
            self.assertEqual(regs['ecx'],b.DATA_PAGES[3]+128)
            self.assertEqual(struct.unpack_from('<I',pages[b.DATA_PAGES[3]],128+0x34)[0],b.DATA_PAGES[1]+128)
            self.assertEqual(set(pages),set(b.PAGES))
            self.assertEqual(struct.unpack_from('<I',pages[b.DATA_PAGES[0]],regs['esp']-b.DATA_PAGES[0])[0],b.RETURN)

    def test_reference_supports_caller_byte_result(self):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        # Authored full-width immediate followed by TEST/SETNE AL/RET.
        code=bytes.fromhex('b87856341285c00f95c0c3')
        md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
        entry=b.BASE+0x1100
        nodes={i.address:i for i in md.disasm(code,entry)}
        cp=bytearray(4096);cp[0x100:0x100+len(code)]=code
        regs,pages=b.caller_state(8,random.Random(17),{p:bytes(4096) for p in b.IMAGE_PAGES})
        result,_=b.reference(nodes,{b.BASE+0x1000:cp},entry,regs,pages)
        self.assertEqual(result['regs'][0],0x12345601)

    def test_independent_poststate_rejects_slot_cleanup_count_index_update(self):
        regs,pages=b.caller_state(8,random.Random(17),{p:bytes(4096) for p in b.IMAGE_PAGES})
        def initial(off):return struct.unpack_from('<I',pages[b.DATA_PAGES[1]],128+off)[0]
        final=bytearray(b''.join(bytes(pages[p]) for p in b.PAGES))
        def put(p,off,value):struct.pack_into('<I',final,b.PAGES.index(p)*4096+128+off,value)
        end=initial(0x100)
        put(b.DATA_PAGES[1],0x1c8,17);put(b.DATA_PAGES[1],0x1cc,23);put(b.DATA_PAGES[1],0x108,end)
        values=[initial(0xfc),18,23,(initial(0x18)-initial(0x1c)+end)&0xffffffff,
                (initial(0x104)-end)&0xffffffff]
        for off,value in zip(range(0x80,0x94,4),values):put(b.DATA_PAGES[3],off,value)
        out=[regs[r] for r in b.REGS];out[-1]+=4
        out[0]=(values[-1]&0xffffff00)|int(values[0]!=0)
        state=dict(regs=out,pages=final.hex())
        b.assert_poststate(regs,pages,state)
        for p,off in ((b.DATA_PAGES[3],0x80),(b.DATA_PAGES[3],0x84),(b.DATA_PAGES[3],0x88),
                      (b.DATA_PAGES[3],0x8c),(b.DATA_PAGES[3],0x90),(b.DATA_PAGES[1],0x1c8),
                      (b.DATA_PAGES[1],0x1cc),(b.DATA_PAGES[1],0x108)):
            wrong=bytearray(final);wrong[b.PAGES.index(p)*4096+128+off]^=1
            with self.subTest(page=p,offset=off),self.assertRaises(ValueError):
                b.assert_poststate(regs,pages,dict(state,pages=wrong.hex()))
        wrong=list(out);wrong[-1]-=4
        with self.assertRaises(ValueError):b.assert_poststate(regs,pages,dict(state,regs=wrong))

    def test_assembly_requires_exact_closure_and_call_edges(self):
        with self.assertRaises(ValueError):b.assemble({}, {}, {})
        bodies={r:f'static void startup_{r:06X}(void) {{}}' for r in b.CLOSURE}
        with self.assertRaises(ValueError):b.assemble(bodies,{}, {})
        direct={r:b.BASE+0x100+i*5 for i,r in enumerate(b.CLOSURE[1:6])}
        indirect={r:b.BASE+0x200+i*5 for i,r in enumerate((0x1290,0x12d0))}
        text=b.assemble(bodies,direct,indirect)
        self.assertTrue(all(text.count(body)==1 for body in bodies.values()))
        self.assertNotIn('@BODY@',text)
        self.assertIn('cache_invoke(0xA01ABD40u,in,adapter_1ABD40)',text)

    def test_failure_is_private_exclusive_and_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(b,'ROOT',Path(tmp)),patch('execute_cache_skip.ROOT',Path(tmp)):
            out=Path(tmp)/'work/recomp-bench/missing'
            with self.assertRaises(FileNotFoundError):b.run(out,Path('missing'))
            row=json.loads((out/'result.json').read_text())
            self.assertFalse(row['success']);self.assertFalse(row['arm64_executed']);self.assertFalse(row['android_executed'])
            with self.assertRaises(FileExistsError):b.run(out,Path('missing'))

    def test_live_guest_memory_dispatch_and_mutation_controls(self):
        cc=shutil.which('zig-cxx') or shutil.which('c++')
        self.assertIsNotNone(cc,'A real C++ compiler is required')
        # Independently authored C++ entry, using the SAME real memory/dispatch
        # bridge as private lifted bodies. Not evidence of original x86 behavior.
        source=r'''
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
extern "C" {
void cache_reset(const unsigned char*);
unsigned cache_read(unsigned,unsigned);
void cache_write(unsigned,unsigned,unsigned);
void cache_copy(unsigned char*);
void cache_invoke(unsigned,unsigned*,void (*)(unsigned*));
}
static unsigned calls;
static void leaf(unsigned* s) {
    ++calls;
    auto h=cache_read(s[7]+4,4);
    s[0]=cache_read(h+0xfc,4)+calls;
    s[7]+=4;
}
static void caller(unsigned* s) {
    auto receiver=s[2],h=cache_read(receiver+0x34,4),sp=s[7];
    for(unsigned k=0;k<5;++k) {
        s[7]-=4;cache_write(s[7],4,h);
        s[7]-=4;cache_write(s[7],4,0x71000000);
        cache_invoke(0xA0001240,s,leaf);
        cache_write(receiver+0x80+k*4,4,s[0]);
    }
    s[7]+=20; // caller-owned cleanup
    if(s[7]!=sp) throw std::runtime_error("cleanup");
    cache_write(h+0x1c8,4,17);cache_write(h+0x1cc,4,23);
    cache_write(h+0x108,4,cache_read(h+0x100,4));
    s[7]+=4;
}
int main() {
    unsigned char pages[6*4096]={};cache_reset(pages);
    unsigned s[8]={0,0,0xA10DF080,0,0,0,0,0x70000800};
    unsigned h=0x72000080;
    cache_write(s[2]+0x34,4,h);cache_write(h+0xfc,4,40);
    cache_write(h+0x100,4,0xA104F088);
    cache_invoke(0xA01ABD40,s,caller);
    if(s[7]!=0x70000804 || calls!=5) return 1;
    for(unsigned k=0;k<5;++k) if(cache_read(0xA10DF100+k*4,4)!=41+k) return 2;
    if(cache_read(h+0x1c8,4)!=17 || cache_read(h+0x1cc,4)!=23 || cache_read(h+0x108,4)!=0xA104F088) return 3;
    for(auto a:{0xA0009000u,0xA0E17000u,0x50000000u}) {
        try {cache_write(a,4,1);return 4;} catch (...) {}
    }
    try {cache_invoke(0xA0001241,s,leaf);return 5;} catch (...) {}
    cache_reset(pages); // exceptions must not poison the next context
    return cache_read(h+0xfc,4)==0?0:6;
}
'''
        mutations={
            'valid':source,
            'slot-order':source.replace('receiver+0x80+k*4','receiver+0x80+(4-k)*4'),
            'cleanup':source.replace('s[7]+=20','s[7]+=16'),
            'count':source.replace('h+0x1c8,4,17','h+0x1c8,4,18'),
            'index':source.replace('h+0x1cc,4,23','h+0x1cc,4,24'),
            'update':source.replace('h+0x108,4,cache_read(h+0x100,4)','h+0x108,4,0'),
        }
        with tempfile.TemporaryDirectory() as tmp:
            for name,text in mutations.items():
                with self.subTest(name=name):
                    path=Path(tmp)/(name+'.cpp');path.write_text(text)
                    binary=Path(tmp)/name
                    p=subprocess.run([cc,'-std=c++20','-I'+str(ROOT/'native/include'),str(path),str(b.BRIDGE),
                        str(ROOT/'native/src/guest_memory.cpp'),str(ROOT/'native/src/guest_dispatch.cpp'),'-o',str(binary)],capture_output=True,timeout=120)
                    self.assertEqual(p.returncode,0,p.stderr.decode())
                    p=subprocess.run([str(binary)],capture_output=True,timeout=10)
                    if name=='valid':self.assertEqual(p.returncode,0,p.stderr.decode())
                    else:self.assertNotEqual(p.returncode,0)


if __name__=='__main__':unittest.main()
