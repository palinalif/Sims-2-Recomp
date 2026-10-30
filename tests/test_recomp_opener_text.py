"""Public authored text composition contracts; no proprietary bytes/fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_opener_text.py'
spec = importlib.util.spec_from_file_location('opener_text', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c, h = m.c, m.heap


def publication(n=0):
    regs, pages = m.state(n)
    after = copy.deepcopy(pages)
    arena = after[h.ARENA]
    def put(off, value):
        struct.pack_into('<I', arena, off, value)
    for off in (0, 4, 0x74, 0xe4, 0xf0, 0x1d4):
        put(off, 0)
    for off, value in ((0xe8, c.OPENER_MEMBER_TABLE), (0xf4, 1),
            (0x78, h.ARENA+0x7c), (0xc8, h.ARENA+0x78),
            (0x7c, c.BASE+0x10970), (0x80, c.BASE+0x109a0),
            (0xb0, c.BASE+0xfcf0)):
        put(off, value)
    arena[0xc5] = 6
    source = pages[c.DATA_PAGES[3]]
    end = source.index(0, m.SOURCE_OFFSET)
    sample = source[m.SOURCE_OFFSET:end+1]
    chunk = sum(m.opener.REQUESTS)
    text = h.ARENA+chunk+8
    for off, value in ((0xd0, text), (0x1d0, h.ARENA+chunk),
            (0x1d8, h.ARENA+sum(m.REQUESTS)),
            (0x1dc, text+len(sample)), (0x1e0, text+len(sample)),
            (chunk, 0), (chunk+4, 1024)):
        put(off, value)
    arena[chunk+8:chunk+8+len(sample)] = sample
    result = dict(regs=[dict(regs, eax=h.ARENA, esp=regs['esp']+4)[r] for r in c.REGS],
                  pages=b''.join(after[p] for p in h.PAGES).hex())
    service = m.model()
    service.calls = len(m.REQUESTS)
    service.occupied[:sum(m.REQUESTS)//8] = [True]*(sum(m.REQUESTS)//8)
    return regs, pages, result, service


class OpenerTextTests(unittest.TestCase):
    def test_deterministic_nonnull_corpus_disjoint_from_heap(self):
        lengths = set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            frame = struct.unpack_from('<8I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0])
            self.assertEqual(frame, (c.RETURN, c.DATA_PAGES[3]+m.SOURCE_OFFSET, 0, 0, 0, 0, 0, 0))
            source = pages[c.DATA_PAGES[3]]
            length = source.index(0, m.SOURCE_OFFSET)-m.SOURCE_OFFSET
            lengths.add(length)
            self.assertLess(length+1, 1024)
            self.assertNotEqual(pages[h.ARENA], bytes(4096))
        self.assertEqual(lengths, {0, 1, 7, 55, 63, 127, 191, 255})
        for bad in (-1, 64, True, 1.0):
            with self.assertRaises(ValueError):
                m.state(bad)

    def test_independent_subset_contract_and_nonmutation(self):
        for n in range(64):
            regs, pages, result, service = publication(n)
            before = copy.deepcopy((regs, pages, result))
            m.contract(regs, pages, result, service)
            self.assertEqual((regs, pages, result), before)

    def test_wrong_pointer_cursor_copy_header_slack_and_member_reject(self):
        chunk = sum(m.opener.REQUESTS)
        for offset in (0x78, 0xc8, 0xd0, 0xec, 0x1d0, 0x1d4, 0x1d8,
                       0x1dc, 0x1e0, chunk, chunk+4, chunk+8, chunk+9,
                       sum(m.REQUESTS)-1, sum(m.REQUESTS), 4095):
            regs, pages, result, service = publication()
            raw = bytearray.fromhex(result['pages'])
            raw[2*4096+offset] ^= 1
            result['pages'] = raw.hex()
            with self.assertRaises(ValueError, msg=hex(offset)):
                m.contract(regs, pages, result, service)

    def test_wrong_abi_service_ownership_immutable_page_and_truncation_reject(self):
        for register in (0, 1, 4, 5, 6, 7):
            regs, pages, result, service = publication()
            result['regs'][register] ^= 4
            with self.assertRaises(ValueError):
                m.contract(regs, pages, result, service)
        for mode in ('calls', 'ownership', 'page', 'truncated'):
            regs, pages, result, service = publication()
            if mode == 'calls':
                service.calls -= 1
            elif mode == 'ownership':
                service.occupied[0] = False
            elif mode == 'page':
                raw = bytearray.fromhex(result['pages'])
                raw[3*4096+m.SOURCE_OFFSET] ^= 1
                result['pages'] = raw.hex()
            else:
                result['pages'] = result['pages'][:-2]
            with self.assertRaises(ValueError, msg=mode):
                m.contract(regs, pages, result, service)

    def test_transport_registers_text_and_capacity_but_not_cleanup(self):
        bodies = {r:f'static void capacity_{r:X}(void) {{ /* authored */ }}' for r in m.UNITS}
        root, writer = c.BASE+m.ROOT_RVA, c.BASE+0x26b0
        edges = [(root, writer, root+20), (writer, c.BASE+0x1af0, writer+30)]
        text = m.assemble(bodies, edges, c.BASE+h.RVA+20)
        for body in bodies.values():
            self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0003A50u,in,adapter_3A50)', text)
        self.assertIn('edge_0=0;edge_1=0;', text)
        for mode in m.rig.MODES:
            bridge = m.bridge_source(mode)
            for target in ('0xA0003A50u', '0xA00026B0u', '0xA0001AF0u'):
                self.assertIn(target, bridge)
            self.assertNotIn('0xA00027D0u', bridge)
        with self.assertRaises(ValueError):
            m.bridge_source('stub')

    def test_extended_allocator_contract_has_isolated_occupancy(self):
        self.assertEqual(m.model().requests, (528, 256, 1024, 1032))
        self.assertEqual(m.opener.model().requests, (528, 256, 1024))
        first, second = m.model(), m.model()
        first.occupied[0] = True
        self.assertFalse(second.occupied[0])
        for bad in ((), [], (True,), (0,), (4097,)):
            with self.assertRaises(ValueError):
                m.opener.AllocationModel(bad)

    def test_four_real_allocation_frames_preserve_separate_ownership(self):
        import unicorn.x86_const as x
        ids = {r: getattr(x, 'UC_X86_REG_'+r.upper()) for r in c.REGS}
        class Cpu:
            def __init__(self):
                self.regs = {ids['esp']: c.DATA_PAGES[0]+0x800}
            def reg_read(self, reg):
                return self.regs[reg]
            def reg_write(self, reg, value):
                self.regs[reg] = value
            def mem_read(self, address, size):
                if address != c.DATA_PAGES[0]+0x800 or size != 16:
                    raise AssertionError('bad service frame')
                return self.frame
        service, cpu = m.model(), Cpu()
        offset = 0
        for index, size in enumerate(m.REQUESTS):
            ret = c.BASE+0x1000+index*16
            cpu.regs[ids['esp']] = c.DATA_PAGES[0]+0x800
            cpu.frame = struct.pack('<4I', ret, h.HANDLE, 0, size)
            service.invoke(cpu, ids, ret)
            self.assertEqual(cpu.regs[ids['eax']], h.ARENA+offset)
            self.assertEqual(cpu.regs[ids['esp']], c.DATA_PAGES[0]+0x810)
            self.assertEqual(cpu.regs[x.UC_X86_REG_EIP], ret)
            offset += size
        self.assertEqual(service.calls, 4)
        self.assertEqual(sum(service.occupied)*8, sum(m.REQUESTS))
        cpu.regs[ids['esp']] = c.DATA_PAGES[0]+0x800
        with self.assertRaises(ValueError):
            service.invoke(cpu, ids, ret)

    def test_full_state_comparator_requires_differences_per_control(self):
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
