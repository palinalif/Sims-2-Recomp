"""Authored spare-list fixtures only; never original code or saved CPU states."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_capacity_reuse.py'
spec = importlib.util.spec_from_file_location('capacity_reuse', PATH)
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class CapacityReuseTests(unittest.TestCase):
    def publication(self, n):
        regs, pages = m.state(n)
        sp = regs['esp']-m.c.DATA_PAGES[0]
        _, obj, source = struct.unpack_from('<III', pages[m.c.DATA_PAGES[0]], sp)
        off = obj-m.c.DATA_PAGES[1]
        src = source-m.c.DATA_PAGES[3]
        sample = pages[m.c.DATA_PAGES[3]][src:pages[m.c.DATA_PAGES[3]].index(0, src)+1]
        after = copy.deepcopy(pages)
        struct.pack_into('<I', after[m.heap.ARENA], 0, 0)
        after[m.heap.ARENA][8:8+len(sample)] = sample
        struct.pack_into('<I', after[m.c.DATA_PAGES[1]], off+0xd0, m.heap.ARENA+8)
        struct.pack_into('<5I', after[m.c.DATA_PAGES[1]], off+0x1d0,
            m.heap.ARENA, m.heap.ARENA+64, m.heap.ARENA+64,
            m.heap.ARENA+8+len(sample), m.heap.ARENA+8+len(sample))
        out = [regs[r] for r in m.c.REGS];out[0] = 1;out[7] += 4
        return regs, pages, dict(regs=out, pages=b''.join(after[p] for p in m.heap.PAGES).hex()), off

    def test_deterministic_mapped_chunk_pointer_not_integer_selector(self):
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            sp = regs['esp']-m.c.DATA_PAGES[0]
            obj = struct.unpack_from('<I', pages[m.c.DATA_PAGES[0]], sp+4)[0]
            self.assertEqual(struct.unpack_from('<5I', pages[m.c.DATA_PAGES[1]], obj-m.c.DATA_PAGES[1]+0x1d0),
                             (0, m.heap.ARENA, 0, 0, 0))
            self.assertEqual(struct.unpack_from('<II', pages[m.heap.ARENA]), (m.heap.ARENA+64, 56))
            self.assertEqual(struct.unpack_from('<II', pages[m.heap.ARENA], 64), (0, 56))
        for bad in (-1, 64, True, 0.0):
            with self.assertRaises(ValueError):m.state(bad)

    def test_contract_accepts_independent_spare_pop_all_lengths(self):
        for n in range(64):
            regs, pages, result, _ = self.publication(n)
            m.contract(regs, pages, result, m.model())

    def test_rejects_chain_head_link_header_text_and_immutable_mutations(self):
        regs, pages, result, off = self.publication(15)
        positions = [8192, 8192+4, 8192+8, 8192+23, 8192+64, 8192+68,
                     8192+72, 8192+4095, 4096, 3*4096, 4*4096, 5*4096]
        positions += [4096+off+v for v in (0xd0, 0x1d0, 0x1d4, 0x1d8, 0x1dc, 0x1e0)]
        for pos in positions:
            bad = copy.deepcopy(result);raw = bytearray.fromhex(bad['pages']);raw[pos] ^= 1;bad['pages'] = raw.hex()
            with self.subTest(pos=pos):
                with self.assertRaises(ValueError):m.contract(regs, pages, bad, m.model())

    def test_rejects_wrong_result_cleanup_nonvolatiles_and_truncation(self):
        regs, pages, result, _ = self.publication(15)
        for i in (0, 1, 4, 5, 6, 7):
            bad = copy.deepcopy(result);bad['regs'][i] ^= 4
            with self.assertRaises(ValueError):m.contract(regs, pages, bad, m.model())
        for key in ('regs', 'pages'):
            bad = copy.deepcopy(result);bad[key] = bad[key][:-2]
            with self.assertRaises(ValueError):m.contract(regs, pages, bad, m.model())

    def test_no_allocator_response_on_either_side(self):
        model = m.model()
        self.assertEqual(model.calls, 0)
        with self.assertRaisesRegex(ValueError, 'Unexpected allocator'):model.invoke(None, None, None)
        regs, pages, result, _ = self.publication(1)
        model.calls = 1
        with self.assertRaises(ValueError):m.contract(regs, pages, result, model)
        text = m.bridge_source('valid')
        self.assertIn('unexpected allocation', text)
        self.assertNotIn('heap->invoke_allocate(r)', text)
        self.assertEqual(text.count('heap->allocate('), 2)  # ownership only
        self.assertEqual(m.SERVICE_BOUNDARY['expected_calls_per_case'], 0)

    def test_controls_perturb_root_not_unreached_service(self):
        self.assertIn('if(depth==1) s[0]+=8;', m.bridge_source('wrong-result'))
        self.assertIn('if(depth==1) s[7]+=4;', m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('unknown')
        self.assertIn('heap->invoke_allocate(r)', m.growth.bridge_source('valid'))
        self.assertNotIn('unexpected allocation', m.capacity.bridge_source('valid'))

    def test_transport_retains_each_body_verbatim_and_unknown_target_gate(self):
        bodies = {r:f'/* authored fixture {r:x} */' for r in m.UNITS}
        text = m.assemble(bodies, [], m.c.BASE+m.RVA+5)
        for body in bodies.values():self.assertEqual(text.count(body), 1)
        self.assertNotIn('@', text)
        self.assertIn('target!=0xA08461F2u', text)
        self.assertNotIn('adapter_8413B0', text)


if __name__ == '__main__':unittest.main()
