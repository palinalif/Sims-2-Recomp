"""Authored ownership/publication fixtures only; no original-game bytes."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_capacity_reallocate.py'
spec = importlib.util.spec_from_file_location('capacity_reallocate', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CapacityReallocateTests(unittest.TestCase):
    def publication(self, n=0):
        regs, pages = m.state(n)
        sp = regs['esp']-m.c.DATA_PAGES[0]
        _, obj, source = struct.unpack_from('<III', pages[m.c.DATA_PAGES[0]], sp)
        off = obj-m.c.DATA_PAGES[1]
        src = source-m.c.DATA_PAGES[3]
        sample = pages[m.c.DATA_PAGES[3]][src:pages[m.c.DATA_PAGES[3]].index(0, src)+1]
        after = copy.deepcopy(pages)
        raw = m.heap.ARENA+128
        after[m.heap.ARENA][8:64] = sample[:56]
        after[m.heap.ARENA][128:192] = after[m.heap.ARENA][:64]
        struct.pack_into('<II', after[m.heap.ARENA], 128, 0, 112)
        after[m.heap.ARENA][136:136+len(sample)] = sample
        struct.pack_into('<I', after[m.c.DATA_PAGES[1]], off+0xd0, raw+8)
        struct.pack_into('<5I', after[m.c.DATA_PAGES[1]], off+0x1d0,
                         raw, 0, raw+120, raw+8+len(sample), raw+8+len(sample))
        out = [regs[r] for r in m.c.REGS]
        out[0] = 1; out[7] += 4
        service = m.model(); service.calls = 1
        return regs, pages, dict(regs=out, pages=b''.join(after[p] for p in m.heap.PAGES).hex()), service, off

    def test_empty_owned_chunk_and_long_disjoint_input_are_deterministic(self):
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            sp = regs['esp']-m.c.DATA_PAGES[0]
            _, obj, source = struct.unpack_from('<III', pages[m.c.DATA_PAGES[0]], sp)
            self.assertEqual(struct.unpack_from('<5I', pages[m.c.DATA_PAGES[1]], obj-m.c.DATA_PAGES[1]+0x1d0),
                (m.heap.ARENA, 0, m.heap.ARENA+64, m.heap.ARENA+8, m.heap.ARENA+8))
            self.assertEqual(struct.unpack_from('<II', pages[m.heap.ARENA]), (0,56))
            self.assertEqual(struct.unpack_from('<I', pages[m.heap.IMAGES[0]], m.realloc.IAT-m.heap.IMAGES[0])[0],m.heap.SERVICE)
            src=source-m.c.DATA_PAGES[3]
            self.assertEqual(pages[m.c.DATA_PAGES[3]].index(0,src)-src,64+n%32)
        for n in (-1,64,True,1.0):
            with self.assertRaises(ValueError):m.state(n)

    def test_model_has_independent_ownership_and_exact_request(self):
        first=m.model();second=m.model()
        self.assertEqual(first.expected_size,120)
        self.assertEqual(first.occupied,[True]*16+[False]*496)
        first.occupied[0]=False
        self.assertTrue(second.occupied[0])
        for size in (0,-1,2,3969,True,1.5):
            with self.assertRaises(ValueError):m.realloc.ReallocateModel(size)

    def test_contract_all_cases(self):
        for n in range(64):
            regs,pages,result,service,_=self.publication(n)
            m.contract(regs,pages,result,service)

    def test_rejects_retention_header_string_and_all_publication_corruption(self):
        regs,pages,result,service,off=self.publication()
        positions=[8192,8192+64,8192+128,8192+132,8192+136,8192+200,
                   3*4096,4*4096,5*4096]
        positions += [4096+off+v for v in (0xd0,0x1d0,0x1d4,0x1d8,0x1dc,0x1e0)]
        for pos in positions:
            bad=copy.deepcopy(result);raw=bytearray.fromhex(bad['pages']);raw[pos]^=1;bad['pages']=raw.hex()
            with self.subTest(pos=pos),self.assertRaises(ValueError):m.contract(regs,pages,bad,service)

    def test_rejects_unchanged_old_payload_after_prefix_fill(self):
        regs,pages,result,service,_=self.publication()
        raw=bytearray.fromhex(result['pages'])
        raw[8192+8:8192+64]=pages[m.heap.ARENA][8:64]
        result['pages']=raw.hex()
        with self.assertRaises(ValueError):m.contract(regs,pages,result,service)

    def test_rejects_wrong_abi_service_count_and_request(self):
        regs,pages,result,service,_=self.publication()
        for i in (0,1,4,5,6,7):
            bad=copy.deepcopy(result);bad['regs'][i]^=4
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,service)
        for count in (0,2):
            service.calls=count
            with self.assertRaises(ValueError):m.contract(regs,pages,result,service)
        service.calls=1;service.expected_size=128
        with self.assertRaises(ValueError):m.contract(regs,pages,result,service)

    def test_transport_binds_real_realloc_bodies_not_allocator_standins(self):
        bodies={r:f'/* authored body {r:x} */' for r in m.UNITS}
        text=m.assemble(bodies,[],m.c.BASE+m.RVA+5)
        for body in bodies.values():self.assertEqual(text.count(body),1)
        self.assertIn('target!=0xA085217Fu',text)
        self.assertIn('adapter_8413B0',text)
        self.assertNotIn('adapter_831A6F',text)
        self.assertNotIn('@',text)
        with self.assertRaises(ValueError):m.assemble({},[],0)

    def test_native_service_ownership_and_negative_controls(self):
        text=m.bridge_source('valid')
        self.assertIn('heap->invoke_reallocate(r)',text)
        self.assertNotIn('invoke_allocate',text)
        self.assertEqual(text.count('heap->allocate('),2)
        self.assertIn('0xA085217Fu',text)
        self.assertIn('s[0]+=8;',m.bridge_source('wrong-result'))
        self.assertIn('if(depth==1) s[7]+=4;',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('unknown')
        self.assertIn('invoke_allocate',m.capacity.bridge_source('valid'))


if __name__ == '__main__':unittest.main()
