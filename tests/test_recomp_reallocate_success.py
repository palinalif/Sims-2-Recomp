"""Public authored tests; no original image or derived code fixtures required."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_reallocate_success.py'
spec = importlib.util.spec_from_file_location('reallocate_success',PATH)
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class CPU:
    def __init__(self, regs, pages):
        self.regs = dict(regs)
        self.pages = copy.deepcopy(pages)

    def reg_read(self, r):return self.regs[r]
    def reg_write(self, r, v):self.regs[r] = v
    def mem_read(self, address, size):
        page = address & ~4095;off = address-page
        if not 0 <= off <= 4096-size:raise ValueError('range')
        return self.pages[page][off:off+size]
    def mem_write(self, address, data):
        page = address & ~4095;off = address-page
        if not 0 <= off <= 4096-len(data):raise ValueError('range')
        self.pages[page][off:off+len(data)] = data


class ReallocateSuccessTests(unittest.TestCase):
    def service(self, n):
        regs,pages,size = m.state(n)
        sp = regs['esp']-96;ret = 0x12345678
        struct.pack_into('<5I',pages[m.c.DATA_PAGES[0]],sp-m.c.DATA_PAGES[0],ret,m.heap.HANDLE,0,m.heap.ARENA,size)
        cpu = CPU(dict(regs,esp=sp),pages)
        return regs,pages,size,sp,ret,cpu,m.ReallocateModel(size)

    def test_corpus_is_deterministic_nonnull_nonzero_with_explicit_import(self):
        sizes = set()
        for n in range(64):
            regs,pages,size = m.state(n);sizes.add(size)
            self.assertEqual((regs,pages,size),m.state(n))
            self.assertEqual(set(pages),set(m.heap.PAGES))
            self.assertEqual(struct.unpack_from('<III',pages[m.c.DATA_PAGES[0]],regs['esp']-m.c.DATA_PAGES[0]),(m.c.RETURN,m.heap.ARENA,size))
            self.assertEqual(struct.unpack_from('<I',pages[m.heap.IMAGES[0]],m.IAT-m.heap.IMAGES[0])[0],m.heap.SERVICE)
        self.assertEqual(sizes,set(m.REQUESTS))
        for n in (-1,64,True,0.0):
            with self.assertRaises(ValueError):m.state(n)

    def test_model_shrink_grow_copy_ownership_and_stdcall16(self):
        for n in range(64):
            regs,pages,size,sp,ret,cpu,model = self.service(n)
            model.invoke(cpu,{r:r for r in m.c.REGS},ret)
            dest = m.heap.ARENA+(128 if size > 64 else 0)
            self.assertEqual(cpu.regs['eax'],dest)
            self.assertEqual(cpu.regs['esp'],sp+20)
            for r in m.c.REGS:
                if r not in ('eax','esp'):self.assertEqual(cpu.regs[r],regs[r])
            self.assertEqual(model.calls,1)
            expected = copy.deepcopy(pages)
            if size > 64:expected[m.heap.ARENA][128:192] = pages[m.heap.ARENA][:64]
            self.assertEqual(cpu.pages,expected)
            occupied = [False]*512
            occupied[8:16] = [True]*8
            start = (dest-m.heap.ARENA)//8;count = (size+7)//8
            occupied[start:start+count] = [True]*count
            self.assertEqual(model.occupied,occupied)
            # A second invocation may not silently reuse the corpus' ownership.
            with self.assertRaises(ValueError):model.invoke(cpu,{r:r for r in m.c.REGS},ret)

    def test_model_rejects_bad_frame_before_any_effect(self):
        for word,value in ((0,99),(1,0),(2,1),(3,m.heap.ARENA+8),(4,0),(4,4096)):
            _,_,_,sp,ret,cpu,model = self.service(8)
            cpu.mem_write(sp+word*4,struct.pack('<I',value))
            before = copy.deepcopy((cpu.regs,cpu.pages,model.occupied))
            with self.assertRaises(ValueError):model.invoke(cpu,{r:r for r in m.c.REGS},ret)
            self.assertEqual((cpu.regs,cpu.pages,model.occupied),before)
            self.assertEqual(model.calls,0)
        for sp in (m.c.DATA_PAGES[0]-4,m.c.DATA_PAGES[0]+4096-16,m.c.DATA_PAGES[0]+1):
            _,_,_,_,ret,cpu,model = self.service(0);cpu.regs['esp'] = sp
            with self.assertRaises(ValueError):model.invoke(cpu,{r:r for r in m.c.REGS},ret)

    def publication(self,n):
        regs,pages,size,_,ret,cpu,model = self.service(n)
        model.invoke(cpu,{r:r for r in m.c.REGS},ret)
        out = [regs[r] for r in m.c.REGS]
        out[0] = cpu.regs['eax'];out[7] += 4
        return regs,pages,dict(regs=out,pages=b''.join(cpu.pages[p] for p in m.heap.PAGES).hex()),model

    def test_contract_rejects_result_frame_preservation_copy_and_image_mutations(self):
        for n in (0,6,12):
            regs,pages,result,model = self.publication(n)
            m.contract(regs,pages,result,model)
            for r in (0,1,4,5,6,7):
                bad = copy.deepcopy(result);bad['regs'][r] ^= 4
                with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
            for pos in (4096,8192,8192+128,8192+192,3*4096,4*4096,5*4096):
                bad = copy.deepcopy(result);data = bytearray.fromhex(bad['pages']);data[pos] ^= 1;bad['pages'] = data.hex()
                with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
            model.calls = 0
            with self.assertRaises(ValueError):m.contract(regs,pages,result,model)

    def test_transport_retains_bodies_and_exact_tail_without_external_responses(self):
        bodies = {r:f'/* authored fixture {r:x} */' for r in (m.WRAPPER,m.RVA)}
        direct = {0x8461f2,0x8461b8,0x831b17,0x8437c6,0x842a91}
        text = m.assemble(bodies,direct,m.c.BASE+m.RVA+90)
        self.assertNotIn('@',text)
        for body in bodies.values():self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA08413B0u,in,adapter_8413B0)',text)
        self.assertIn('target!=0xA085217Fu',text)
        for r in direct:self.assertNotIn(f'target==0x{m.c.BASE+r:08X}u) return',text)
        with self.assertRaises(ValueError):m.assemble(bodies,set(),m.c.BASE+m.RVA+90)
        with self.assertRaises(ValueError):m.assemble({},direct,0)

    def test_native_bridge_uses_production_reallocation_and_rejecting_faults(self):
        text = m.bridge_source('valid')
        self.assertIn('heap->invoke_reallocate(r)',text)
        self.assertNotIn('heap->invoke_allocate(r)',text)
        self.assertIn('ownership setup',text)
        self.assertIn('memory->read32(r.eax)^1u',m.bridge_source('wrong-copy'))
        self.assertIn('if(depth==1) s[7]+=4;',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('bad')

    def test_generalized_tail_decoder_remains_pin_and_edge_gated(self):
        # Authored x86 tail fixture, NOT original bytes: push/pop then near JMP.
        rva,target = 0x3000,0x4000
        code = b'\x55\x5d\xe9'+struct.pack('<i',target-rva-7)
        pin = hashlib.sha256(code).hexdigest()
        _,ns,meta = m.heap.decode_wrapper(code,lambda i:i,rva=rva,size=7,count=3,pin=pin,target=target)
        self.assertEqual(len(ns),3);self.assertEqual(meta['size_bytes'],7)
        for change in (dict(pin='0'*64),dict(target=target+1),dict(count=4)):
            kwargs = dict(rva=rva,size=7,count=3,pin=pin,target=target);kwargs.update(change)
            with self.assertRaises(ValueError):m.heap.decode_wrapper(code,lambda i:i,**kwargs)


if __name__ == '__main__':unittest.main()
