"""Authored capacity/REP boundary tests only; no proprietary fixtures."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_capacity_success.py'
spec = importlib.util.spec_from_file_location('capacity_success',PATH)
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class CapacitySuccessTests(unittest.TestCase):
    def test_corpus_has_empty_default_descriptor_and_explicit_service(self):
        for n in range(64):
            regs,pages = m.state(n)
            self.assertEqual((regs,pages),m.state(n))
            self.assertEqual(set(pages),set(m.heap.PAGES))
            obj = struct.unpack_from('<I',pages[m.c.DATA_PAGES[0]],regs['esp']-m.c.DATA_PAGES[0]+4)[0]
            self.assertEqual(struct.unpack_from('<5I',pages[m.c.DATA_PAGES[1]],obj-m.c.DATA_PAGES[1]+0x1d0),(0,0,0,0,0))
            self.assertEqual(struct.unpack_from('<I',pages[m.heap.IMAGES[0]],m.heap.IAT-m.heap.IMAGES[0])[0],m.heap.SERVICE)
        for n in (-1,64,True,0.0):
            with self.assertRaises(ValueError):m.state(n)

    def test_input_source_is_outside_exclusive_heap_arena(self):
        for n in range(64):
            regs,pages = m.state(n)
            source = struct.unpack_from('<I',pages[m.c.DATA_PAGES[0]],
                regs['esp']-m.c.DATA_PAGES[0]+8)[0]
            self.assertFalse(m.heap.ARENA <= source < m.heap.ARENA+4096)
            self.assertTrue(m.c.DATA_PAGES[3] <= source < m.c.DATA_PAGES[3]+4096)

    def publication(self):
        regs,pages = m.state(15)
        out = [regs[r] for r in m.c.REGS];out[0]=1;out[7]+=4
        after = copy.deepcopy(pages)
        sp = regs['esp']-m.c.DATA_PAGES[0]
        _,obj,source = struct.unpack_from('<III',pages[m.c.DATA_PAGES[0]],sp)
        off = obj-m.c.DATA_PAGES[1];src = source-m.c.DATA_PAGES[3]
        end = pages[m.c.DATA_PAGES[3]].index(0,src)
        sample = pages[m.c.DATA_PAGES[3]][src:end+1]
        struct.pack_into('<I',after[m.c.DATA_PAGES[1]],off+0xd0,m.heap.ARENA+8)
        struct.pack_into('<I',after[m.c.DATA_PAGES[1]],off+0x1d0,m.heap.ARENA)
        struct.pack_into('<III',after[m.c.DATA_PAGES[1]],off+0x1d8,m.heap.ARENA+1032,m.heap.ARENA+8+len(sample),m.heap.ARENA+8+len(sample))
        struct.pack_into('<II',after[m.heap.ARENA],0,0,1024)
        after[m.heap.ARENA][8:8+len(sample)] = sample
        model = m.heap.HeapModel(1032);model.calls = 1
        return regs,pages,dict(regs=out,pages=b''.join(after[p] for p in m.heap.PAGES).hex()),model

    def test_publication_contract_and_rejecting_controls(self):
        regs,pages,result,model = self.publication()
        m.contract(regs,pages,result,model)
        for idx in (0,1,4,5,6,7):
            bad = copy.deepcopy(result);bad['regs'][idx]^=4
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        obj = struct.unpack_from('<I',pages[m.c.DATA_PAGES[0]],regs['esp']-m.c.DATA_PAGES[0]+4)[0]
        descriptor = 4096+obj-m.c.DATA_PAGES[1]
        for offset in (4096,8192,8200,descriptor+0xd0,descriptor+0x1d0,
                       descriptor+0x1d8,descriptor+0x1dc,descriptor+0x1e0,4*4096,5*4096):
            bad = copy.deepcopy(result);data = bytearray.fromhex(bad['pages']);data[offset]^=1;bad['pages']=data.hex()
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        model.calls=0
        with self.assertRaises(ValueError):m.contract(regs,pages,result,model)

    def rep_reference(self, *, width=1,count=9,source=None,dest=None,enabled=True,prefix=b''):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        entry = m.c.BASE+0x2000
        code = prefix+b'\xf3'+(b'\xa4' if width==1 else b'\xa5')+b'\xc3'
        md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
        nodes={i.address:i for i in md.disasm(code,entry)}
        regs,pages=m.state(0)
        regs.update(ecx=count,esi=m.c.DATA_PAGES[2]+128 if source is None else source,
                    edi=m.c.DATA_PAGES[1]+128 if dest is None else dest)
        block=bytearray(4096);block[:len(code)]=code
        result,seen=m.c.reference(nodes,{entry:block},entry,regs,pages,image_pages=m.heap.IMAGES,checked_repeat_copy=enabled)
        return regs,pages,result,seen

    def test_repeat_copy_executes_checked_byte_and_dword_spans(self):
        for width in (1,4):
            regs,pages,result,seen=self.rep_reference(width=width)
            data=bytes.fromhex(result['pages'])
            self.assertEqual(data[4096+128:4096+128+9*width],pages[m.c.DATA_PAGES[2]][128:128+9*width])
            self.assertEqual(result['regs'][m.c.REGS.index('ecx')],0)
            self.assertEqual(result['regs'][m.c.REGS.index('esi')],regs['esi']+9*width)
            self.assertEqual(result['regs'][m.c.REGS.index('edi')],regs['edi']+9*width)
            self.assertEqual(len(seen),2)

    def test_zero_repeat_does_not_access_unmapped_pointers(self):
        regs,pages,result,_=self.rep_reference(count=0,source=0xffffffff,dest=0xffffffff)
        self.assertEqual(result['pages'],b''.join(pages[p] for p in m.heap.PAGES).hex())

    def test_repeat_gate_default_and_bad_spans_reject(self):
        for kwargs in (dict(enabled=False),dict(count=4097),dict(width=4,count=1025),
                       dict(source=m.c.DATA_PAGES[2]+4090),dict(dest=m.c.DATA_PAGES[1]+4090),
                       dict(source=0xffffffff),dict(dest=m.heap.IMAGES[0])):
            with self.assertRaises(ValueError):self.rep_reference(**kwargs)

    def test_repeat_copy_rejects_segment_and_address_overrides(self):
        # Even explicit DS (same flat address) must not bypass the supported
        # instruction shape. FS/GS and 16-bit SI/DI need different checks.
        for prefix in (b'\x3e',b'\x64',b'\x65',b'\x67'):
            for count in (0,9):
                with self.subTest(prefix=prefix.hex(),count=count):
                    with self.assertRaises(ValueError):
                        self.rep_reference(prefix=prefix,count=count)

    def test_transport_preserves_all_bodies_and_tail_frame(self):
        bodies={r:f'/* authored {r:x} */' for r in m.UNITS}
        text=m.assemble(bodies,[(m.c.BASE+m.ROOT,m.c.BASE+0x26b0,m.c.BASE+m.ROOT+5)],m.c.BASE+m.heap.RVA+5)
        for body in bodies.values():self.assertEqual(text.count(body),1)
        self.assertNotIn('@',text)
        self.assertIn('target!=0xA08461F2u',text)
        self.assertIn('cache_invoke(0xA0002790u,in,adapter_2790)',text)
        self.assertNotIn('target==0xA08413B0u) return',text)
        with self.assertRaises(ValueError):m.assemble({},[],0)

    def test_bridge_admits_only_composed_targets_and_portable_heap(self):
        text=m.bridge_source('valid')
        self.assertIn('ts2::GuestHeap',text)
        for r in m.UNITS:self.assertIn(f'0x{m.c.BASE+r:08X}u',text)
        self.assertNotIn('0xA08413B0u',text)
        self.assertIn('s[0]+=8;',m.bridge_source('wrong-result'))
        cleanup=m.bridge_source('wrong-cleanup')
        self.assertIn('if(depth==1) s[7]+=4;',cleanup)
        self.assertNotIn('s[7]=r.esp;s[7]+=4;',cleanup)
        with self.assertRaises(ValueError):m.bridge_source('bad')


if __name__ == '__main__':unittest.main()
