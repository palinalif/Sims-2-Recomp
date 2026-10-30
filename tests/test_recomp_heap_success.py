"""Authored fixtures for explicit portable-service composition; no game bytes."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_heap_success.py'
spec = importlib.util.spec_from_file_location('heap_success',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class HeapSuccessTests(unittest.TestCase):
    def test_corpus_is_deterministic_and_includes_allocator_edges(self):
        sizes = set()
        for n in range(64):
            regs,pages,size = m.state(n)
            self.assertEqual((regs,pages,size),m.state(n))
            self.assertEqual(set(pages),set(m.PAGES))
            self.assertEqual(struct.unpack_from('<I',pages[m.IMAGES[0]],m.IAT-m.IMAGES[0])[0],m.SERVICE)
            self.assertEqual(struct.unpack_from('<I',pages[m.IMAGES[1]],m.GLOBAL-m.IMAGES[1])[0],m.HANDLE)
            sizes.add(size)
        self.assertTrue(set(m.REQUESTS) <= sizes)
        self.assertGreater(len(sizes),32)
        for n in (-1,64,True,0.0):
            with self.assertRaises(ValueError):m.state(n)

    def authored_reference(self, *, bind=True, target=None, bad_handle=False):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        target = m.SERVICE if target is None else target
        entry = m.c.BASE+0x2000
        # Hand-authored x86: push size; push flags; push handle; call endpoint; ret.
        handle = m.HANDLE ^ int(bad_handle)
        code = b'\x6a\x09\x6a\x00\x68'+struct.pack('<I',handle)
        code += b'\xe8'+struct.pack('<i',target-(entry+len(code)+5))+b'\xc3'
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(code,entry)}
        regs,pages,_ = m.state(0)
        block = bytearray(4096); block[:len(code)] = code
        model = m.HeapModel(9)
        result,seen = m.c.reference(nodes,{entry:block,m.SERVICE:bytes(4096)},entry,regs,pages,
            image_pages=m.IMAGES,heap_service=model if bind else None)
        return regs,pages,result,seen,model

    def test_explicit_service_executes_with_checked_original_call(self):
        regs,pages,result,seen,model = self.authored_reference()
        m.contract(regs,pages,result,model)
        self.assertEqual(len(seen),5)
        self.assertEqual(model.occupied[:3],[True,True,False])
        # No heap bytes are initialized for flags=0.
        off = m.PAGES.index(m.ARENA)*4096
        self.assertEqual(bytes.fromhex(result['pages'])[off:off+4096],pages[m.ARENA])

    def test_no_implicit_service_or_unknown_target_response(self):
        with self.assertRaises(ValueError):self.authored_reference(bind=False)
        with self.assertRaises(ValueError):self.authored_reference(target=m.SERVICE+4)
        with self.assertRaises(ValueError):self.authored_reference(bad_handle=True)

    def test_model_validates_entire_frame_and_call_count(self):
        import unicorn.x86_const as x
        class Cpu:
            def __init__(self,frame,sp=m.c.DATA_PAGES[0]+256):
                self.sp=sp; self.frame=frame; self.writes=[]
            def reg_read(self,k):return self.sp
            def mem_read(self,a,n):return struct.pack('<4I',*self.frame)
            def reg_write(self,k,v):self.writes.append((k,v))
        good=(0x1234,m.HANDLE,0,1)
        for frame in ((0x1235,m.HANDLE,0,1),(0x1234,0,0,1),
                      (0x1234,m.HANDLE,8,1),(0x1234,m.HANDLE,0,0),
                      (0x1234,m.HANDLE,0,2)):
            cpu=Cpu(frame); model=m.HeapModel(0)
            with self.assertRaises(ValueError):model.invoke(cpu,{'esp':1,'eax':2},0x1234)
            self.assertFalse(cpu.writes)
            self.assertFalse(any(model.occupied))
        for sp in (m.c.DATA_PAGES[0]-4,m.c.DATA_PAGES[0]+4084,m.c.DATA_PAGES[0]+1):
            with self.assertRaises(ValueError):m.HeapModel(0).invoke(Cpu(good,sp),{'esp':1,'eax':2},0x1234)
        cpu=Cpu(good); model=m.HeapModel(0); model.invoke(cpu,{'esp':1,'eax':2},0x1234)
        self.assertEqual(cpu.writes,[(2,m.ARENA),(1,cpu.sp+16),(x.UC_X86_REG_EIP,0x1234)])
        with self.assertRaises(ValueError):model.invoke(cpu,{'esp':1,'eax':2},0x1234)

    def test_contract_rejects_result_cleanup_nonvolatile_and_heap_mutations(self):
        regs,pages,result,_,model=self.authored_reference()
        before=copy.deepcopy((regs,pages,result))
        for index in (0,1,4,5,6,7):
            bad=copy.deepcopy(result); bad['regs'][index]^=8
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        bad=copy.deepcopy(result); data=bytearray.fromhex(bad['pages']);data[8192]^=1;bad['pages']=data.hex()
        with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        self.assertEqual((regs,pages,result),before)

    def test_service_entry_without_original_call_rejects(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        entry=m.c.BASE+0x2000
        code=b'\xe9'+struct.pack('<i',m.SERVICE-(entry+5))
        md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
        nodes={i.address:i for i in md.disasm(code,entry)}
        block=bytearray(4096);block[:len(code)]=code
        regs,pages,_=m.state(0)
        with self.assertRaises(ValueError):m.c.reference(nodes,{entry:block,m.SERVICE:bytes(4096)},entry,
            regs,pages,image_pages=m.IMAGES,heap_service=m.HeapModel(0))

    def test_transport_retains_body_and_rejects_all_error_callees(self):
        body='/* authored transport placeholder, never executed */'
        text=m.assemble(body,{0x8437c6,0x842a91,0x831b17},m.c.BASE+m.RVA+1)
        self.assertEqual(text.count(body),1)
        self.assertIn('heap_endpoint',text)
        self.assertNotIn('@',text)
        self.assertIn('static uint32_t direct_return(uint32_t caller,uint32_t target) {\n    \n    reject();',text)
        with self.assertRaises(ValueError):m.assemble(body,set(),m.c.BASE+m.RVA+1)
        with self.assertRaises(ValueError):m.assemble(body,{0x8437c6,0x842a91,0x831b17},0)

    def test_bridge_uses_production_heap_and_exact_targets(self):
        text=m.bridge_source('valid')
        self.assertIn('ts2::GuestHeap',text)
        self.assertIn('heap->invoke_allocate(r);',text)
        self.assertIn('targets{0xA08461F2u,0x60000000u}',text)
        self.assertIn('heap.reset();',text)
        self.assertNotIn('s[0]+=8;',text)
        self.assertIn('s[0]+=8;',m.bridge_source('wrong-result'))
        self.assertIn('s[7]+=4;',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('unknown')


if __name__ == '__main__':unittest.main()
