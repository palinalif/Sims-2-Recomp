"""Authored nonempty descriptor tests; no original-code inputs or output."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_capacity_growth.py'
spec = importlib.util.spec_from_file_location('capacity_growth',PATH)
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class CapacityGrowthTests(unittest.TestCase):
    def test_deterministic_full_old_buffer_and_separate_input(self):
        for n in range(64):
            regs,pages = m.state(n)
            self.assertEqual((regs,pages),m.state(n))
            sp = regs['esp']-m.c.DATA_PAGES[0]
            _,obj,source = struct.unpack_from('<III',pages[m.c.DATA_PAGES[0]],sp)
            self.assertEqual(struct.unpack_from('<5I',pages[m.c.DATA_PAGES[1]],obj-m.c.DATA_PAGES[1]+0x1d0),
                (m.heap.ARENA,0,m.heap.ARENA+64,m.heap.ARENA+64,m.heap.ARENA+64))
            self.assertEqual(struct.unpack_from('<II',pages[m.heap.ARENA]),(0,56))
            self.assertTrue(m.c.DATA_PAGES[3] <= source < m.c.DATA_PAGES[3]+4096)
        for bad in (-1,64,True,0.0):
            with self.assertRaises(ValueError):m.state(bad)

    def test_model_seeds_two_live_blocks_without_mutating_default_model(self):
        for _ in range(2):
            model = m.model()
            self.assertEqual(model.expected_size,1032)
            self.assertEqual(model.calls,0)
            self.assertEqual(model.occupied,[True]*16+[False]*496)
        self.assertEqual(m.heap.HeapModel(1032).occupied,[False]*512)

    def publication(self,n=15):
        regs,pages = m.state(n)
        sp = regs['esp']-m.c.DATA_PAGES[0]
        _,obj,source = struct.unpack_from('<III',pages[m.c.DATA_PAGES[0]],sp)
        src = source-m.c.DATA_PAGES[3]
        sample = pages[m.c.DATA_PAGES[3]][src:pages[m.c.DATA_PAGES[3]].index(0,src)+1]
        after = copy.deepcopy(pages)
        raw = m.heap.ARENA+128;off = obj-m.c.DATA_PAGES[1]
        struct.pack_into('<II',after[m.heap.ARENA],128,m.heap.ARENA,1024)
        after[m.heap.ARENA][136:136+len(sample)] = sample
        struct.pack_into('<I',after[m.c.DATA_PAGES[1]],off+0xd0,raw+8)
        struct.pack_into('<5I',after[m.c.DATA_PAGES[1]],off+0x1d0,
            raw,0,raw+1032,raw+8+len(sample),raw+8+len(sample))
        out = [regs[r] for r in m.c.REGS];out[0]=1;out[7]+=4
        service = m.model();service.calls=1
        return regs,pages,dict(regs=out,pages=b''.join(after[p] for p in m.heap.PAGES).hex()),service,off

    def test_contract_accepts_independent_publication_all_lengths(self):
        for n in range(64):
            regs,pages,result,service,_ = self.publication(n)
            m.contract(regs,pages,result,service)

    def test_rejects_old_payload_blocker_chunk_link_and_publication_corruption(self):
        regs,pages,result,service,off = self.publication()
        # Entire old buffer, obstructing block, new chunk link/header/string/NUL,
        # raw/cursors, untouched bytes and immutable pages are checked.
        positions = [8192,8192+64,8192+128,8192+132,8192+136,8192+191,
            8192+136,8192+151,4096,3*4096,4*4096,5*4096]
        positions += [4096+off+v for v in (0xd0,0x1d0,0x1d4,0x1d8,0x1dc,0x1e0)]
        for pos in positions:
            bad = copy.deepcopy(result);data = bytearray.fromhex(bad['pages']);data[pos]^=1;bad['pages']=data.hex()
            with self.subTest(pos=pos):
                with self.assertRaises(ValueError):m.contract(regs,pages,bad,service)

    def test_rejects_wrong_return_cleanup_nonvolatiles_and_service_count(self):
        regs,pages,result,service,_ = self.publication()
        for index in (0,1,4,5,6,7):
            bad=copy.deepcopy(result);bad['regs'][index]^=4
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,service)
        for count in (0,2):
            service.calls=count
            with self.assertRaises(ValueError):m.contract(regs,pages,result,service)
        service.calls=1;service.expected_size=64
        with self.assertRaises(ValueError):m.contract(regs,pages,result,service)

    def test_transport_is_allocation_path_not_unreached_realloc(self):
        bodies={r:f'/* authored fixture {r:x} */' for r in m.UNITS}
        text=m.assemble(bodies,[],m.c.BASE+m.RVA+5)
        for b in bodies.values():self.assertEqual(text.count(b),1)
        self.assertIn('target!=0xA08461F2u',text)
        self.assertNotIn('adapter_8413B0',text)
        self.assertNotIn('@',text)
        self.assertNotIn('target==0xA08413B0u) return',text)

    def test_native_bridge_has_real_owned_blocks_and_rejecting_controls(self):
        text=m.bridge_source('valid')
        self.assertIn('heap->invoke_allocate(r)',text)
        self.assertNotIn('invoke_reallocate',text)
        self.assertIn('ownership setup',text)
        self.assertEqual(text.count('heap->allocate('),2)
        self.assertIn('s[0]+=8;',m.bridge_source('wrong-result'))
        self.assertIn('if(depth==1) s[7]+=4;',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('unknown')
        # Scenario construction must not change the settled empty-corpus bridge.
        self.assertNotIn('ownership setup',m.capacity.bridge_source('valid'))


if __name__ == '__main__':unittest.main()
