"""Authored public fixture contracts; no original code or private states."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_opener_success.py'
spec = importlib.util.spec_from_file_location('opener_success', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c, h = m.c, m.heap


def publication(n=0):
    regs, pages = m.state(n)
    after = copy.deepcopy(pages)
    arena = after[h.ARENA]
    def put(off, value):
        struct.pack_into('<I', arena, off, value)
    for off in (0, 4, 0x74, 0xe4, 0xf0):
        put(off, 0)
    for off, value in ((0xe8, c.OPENER_MEMBER_TABLE), (0xf4, 1),
            (0x78, h.ARENA+0x7c), (0xc8, h.ARENA+0x78),
            (0x7c, c.BASE+0x10970), (0x80, c.BASE+0x109a0), (0xb0, c.BASE+0xfcf0)):
        put(off, value)
    arena[0xc5] = 6
    result = dict(regs=[dict(regs, eax=h.ARENA, esp=regs['esp']+4)[r] for r in c.REGS],
                  pages=b''.join(after[p] for p in h.PAGES).hex())
    service = m.model()
    service.calls = 3
    service.occupied[:sum(m.REQUESTS)//8] = [True]*(sum(m.REQUESTS)//8)
    return regs, pages, result, service


class OpenerSuccessTests(unittest.TestCase):
    def test_corpus_deterministic_dirty_and_null(self):
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            frame = struct.unpack_from('<8I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0])
            self.assertEqual(frame, (c.RETURN, 0, 0, 0, 0, 0, 0, 0))
            self.assertNotEqual(pages[h.ARENA][0xec:0xf0], bytes(4))
            self.assertEqual(set(pages), set(h.PAGES))
        for n in (-1, 64, True, 1.0):
            with self.assertRaises(ValueError):
                m.state(n)

    def test_subset_contract_preservation_and_nonmutation(self):
        for n in range(64):
            regs, pages, result, service = publication(n)
            before = copy.deepcopy((regs, pages, result))
            m.contract(regs, pages, result, service)
            self.assertEqual((regs, pages, result), before)

    def test_wrong_publication_preserved_member_and_overrun_reject(self):
        for offset in (0x78, 0xc8, 0xe8, 0xec, 0xf0, 0xf4, sum(m.REQUESTS), 4095):
            regs, pages, result, service = publication()
            raw = bytearray.fromhex(result['pages'])
            raw[2*4096+offset] ^= 1
            result['pages'] = raw.hex()
            with self.assertRaises(ValueError, msg=hex(offset)):
                m.contract(regs, pages, result, service)

    def test_wrong_abi_service_count_and_input_page_reject(self):
        for register in (0, 1, 4, 5, 6, 7):
            regs, pages, result, service = publication()
            result['regs'][register] ^= 4
            with self.assertRaises(ValueError):
                m.contract(regs, pages, result, service)
        regs, pages, result, service = publication()
        service.calls = 2
        with self.assertRaises(ValueError):
            m.contract(regs, pages, result, service)
        service.calls = 3
        raw = bytearray.fromhex(result['pages'])
        raw[4096] ^= 1
        result['pages'] = raw.hex()
        with self.assertRaises(ValueError):
            m.contract(regs, pages, result, service)

    def test_allocation_model_persists_ownership_and_rejects_extra_calls(self):
        import unicorn.x86_const as x
        ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in c.REGS}
        class Cpu:
            def __init__(self):
                self.regs = {ids['esp']: c.DATA_PAGES[0]+0x800}
                self.frame = b''
            def reg_read(self, reg):
                return self.regs[reg]
            def reg_write(self, reg, value):
                self.regs[reg] = value
            def mem_read(self, address, size):
                self.asserted = (address, size)
                return self.frame
        service, cpu = m.model(), Cpu()
        returns = (0x1230, 0x1240, 0x1250)
        offset = 0
        for size, ret in zip(m.REQUESTS, returns):
            cpu.regs[ids['esp']] = c.DATA_PAGES[0]+0x800
            cpu.frame = struct.pack('<4I', ret, h.HANDLE, 0, size)
            service.invoke(cpu, ids, ret)
            self.assertEqual(cpu.regs[ids['eax']], h.ARENA+offset)
            self.assertEqual(cpu.regs[ids['esp']], c.DATA_PAGES[0]+0x810)
            self.assertEqual(cpu.regs[x.UC_X86_REG_EIP], ret)
            self.assertEqual(cpu.asserted, (c.DATA_PAGES[0]+0x800, 16))
            offset += size
        self.assertEqual(service.calls, 3)
        self.assertEqual(sum(service.occupied)*8, sum(m.REQUESTS))
        occupied = list(service.occupied)
        with self.assertRaises(ValueError):
            service.invoke(cpu, ids, returns[-1])
        self.assertEqual(service.occupied, occupied)
        self.assertEqual(sum(m.model().occupied), 0)
        for handle, flags, size, ret in ((0, 0, 528, 0x1230),
                (h.HANDLE, 8, 528, 0x1230), (h.HANDLE, 0, 529, 0x1230),
                (h.HANDLE, 0, 528, 0x9999)):
            service = m.model()
            cpu.regs[ids['esp']] = c.DATA_PAGES[0]+0x800
            cpu.frame = struct.pack('<4I', ret, handle, flags, size)
            with self.assertRaises(ValueError):
                service.invoke(cpu, ids, 0x1230)
            self.assertEqual(service.calls, 0)
            self.assertEqual(sum(service.occupied), 0)

    def test_repeated_edges_have_independent_resettable_counters(self):
        root = c.BASE+m.ROOT_RVA
        target = c.BASE+h.WRAPPER
        edges = [(root, target, root+12), (root, target, root+24), (root, target, root+36)]
        declarations, cases, resets = m.return_schedule(edges)
        self.assertEqual(declarations.count('static unsigned'), 1)
        self.assertIn('case 2:return', cases)
        self.assertIn('default:reject()', cases)
        self.assertEqual(resets, 'edge_0=0;')
        for bad in (edges[::-1], [edges[0]]*2, [(root, 0x1234, root+12)], [(root, target, root+600)], []):
            with self.assertRaises(ValueError):
                m.return_schedule(bad)

    def test_transport_keeps_lifts_and_excludes_unknown_callbacks(self):
        bodies = {r:f'static void capacity_{r:X}(void) {{ /* authored fixture */ }}' for r in m.UNITS}
        root = c.BASE+m.ROOT_RVA
        text = m.assemble(bodies, [(root, c.BASE+h.WRAPPER, root+12)], c.BASE+h.RVA+20)
        for body in bodies.values():
            self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0003A50u,in,adapter_3A50)', text)
        self.assertIn('cache_reset(pages);edge_0=0;', text)
        for mode in ('valid', 'wrong-result', 'wrong-cleanup'):
            bridge = m.bridge_source(mode)
            self.assertIn('0xA0003A50u', bridge)
            self.assertNotIn('0xA00027D0u', bridge)
            self.assertNotIn('0xA00026B0u', bridge)
        with self.assertRaises(ValueError):
            m.bridge_source('stub')

    def test_full_state_comparator_rejects_false_controls_and_truncation(self):
        expected = [dict(case=n, **publication(n)[2]) for n in range(64)]
        good = '\n'.join(json.dumps(row) for row in expected)
        c.assess(good, expected, 'valid')
        for mode in ('wrong-result', 'wrong-cleanup'):
            bad = copy.deepcopy(expected)
            for row in bad:
                row['regs'][0 if mode == 'wrong-result' else 7] ^= 4
            mutated = '\n'.join(json.dumps(row) for row in bad)
            c.assess(mutated, expected, mode)
            with self.assertRaises(ValueError):
                c.assess(good, expected, mode)
            with self.assertRaises(ValueError):
                c.assess(mutated, expected, 'valid')
        with self.assertRaises(ValueError):
            c.assess(good.rsplit('\n', 1)[0], expected, 'valid')


if __name__ == '__main__':
    unittest.main()
