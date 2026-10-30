"""Authored, skip-free boundary/safety tests; no private code or fixtures."""
import copy
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_service_input.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('service_input_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ServiceInputTests(unittest.TestCase):
    def test_inputs_deterministic_isolated_nonnull_not_callable_markers(self):
        positions, targets = set(), set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            self.assertEqual(set(pages), set(m.PAGES))
            target = struct.unpack_from('<I', pages[m.OBJECT], regs['esi']-m.OBJECT+0x74)[0]
            targets.add(target); positions.add((regs['esi'], regs['esp']))
            self.assertNotIn(target & ~4095, m.PAGES)
            pages[m.OBJECT][0] ^= 1
            self.assertNotEqual(pages, m.state(n)[1])
        self.assertEqual(targets, set(m.MARKERS))
        self.assertEqual(len(positions), 2)
        for bad in (True, -1, 64):
            with self.assertRaises(ValueError): m.state(bad)

    def test_oracle_argument_provenance_frame_and_scratch_registers(self):
        for n in range(64):
            regs, pages = m.state(n)
            before = copy.deepcopy((regs, pages))
            result = m.oracle(regs, pages)
            sp, obj = regs['esp'], regs['esi']
            context = struct.unpack_from('<I', pages[m.OBJECT], obj-m.OBJECT+0xe0)[0]
            arg = struct.unpack_from('<I', pages[m.STACK], sp-m.STACK+4)[0]
            self.assertEqual(result['site'], m.c.BASE+0x14b7)
            self.assertEqual(result['regs']['edx'], result['target'])
            self.assertEqual(result['regs']['eax'], context)
            self.assertEqual(result['regs']['ecx'], arg)
            self.assertEqual(result['regs']['edi'], sp-24)
            self.assertEqual(result['regs']['ebp'], sp-4)
            self.assertEqual(result['regs']['esp'], sp-1068)
            self.assertEqual(struct.unpack_from('<3I', result['pages'][m.STACK], sp-m.STACK-1068),
                             (context, arg, sp-1048))
            for r in ('esi', 'ebx'): self.assertEqual(result['regs'][r], regs[r])
            self.assertEqual((regs, pages), before)

    def test_oracle_full_pages_preserves_holes_and_initializes_buffer_outputs(self):
        regs, pages = m.state(0); out = m.oracle(regs, pages)
        self.assertEqual(out['pages'][m.OBJECT], pages[m.OBJECT])
        sp = regs['esp']-m.STACK
        expected = bytearray(pages[m.STACK])
        expected[sp-1048:sp-24] = bytes([255])*1024
        struct.pack_into('<3I', expected, sp-24, 0, 0, 0)
        struct.pack_into('<I', expected, sp-4, regs['ebp'])
        struct.pack_into('<I', expected, sp-1056, regs['edi'])
        # Copy outgoing args checked independently in the provenance test.
        expected[sp-1068:sp-1056] = out['pages'][m.STACK][sp-1068:sp-1056]
        self.assertEqual(out['pages'][m.STACK], expected)
        for a, b in ((sp-1052, sp-1048), (sp-12, sp-4), (sp, sp+8)):
            self.assertEqual(out['pages'][m.STACK][a:b], pages[m.STACK][a:b])

    def test_contract_rejects_every_register_page_site_target_and_arg_order(self):
        regs, pages = m.state(0); good = m.oracle(regs, pages)
        m.contract(regs, pages, good)
        for r in m.c.REGS:
            bad = copy.deepcopy(good); bad['regs'][r] ^= 4
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)
        for p in m.PAGES:
            bad = copy.deepcopy(good); data = bytearray(bad['pages'][p]); data[0] ^= 1
            bad['pages'][p] = bytes(data)
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)
        for field in ('site', 'target'):
            bad = copy.deepcopy(good); bad[field] ^= 4
            with self.assertRaises(ValueError): m.contract(regs, pages, bad)
        bad = copy.deepcopy(good); data = bytearray(bad['pages'][m.STACK])
        a = regs['esp']-m.STACK-1068
        x, y = struct.unpack_from('<2I', data, a)
        self.assertNotEqual(x, y); struct.pack_into('<2I', data, a, y, x)
        bad['pages'][m.STACK] = bytes(data)
        with self.assertRaises(ValueError): m.contract(regs, pages, bad)

    def test_oracle_invalid_receiver_frame_target_and_shape_reject(self):
        regs, pages = m.state(0)
        for changes in ({'esi':m.OBJECT+4092}, {'esi':m.OBJECT+1},
                        {'esp':regs['esp']+4}, {'eax':-1}):
            with self.assertRaises(ValueError): m.oracle(dict(regs, **changes), pages)
        bad = copy.deepcopy(pages)
        struct.pack_into('<I', bad[m.OBJECT], regs['esi']-m.OBJECT+0x74, 0)
        with self.assertRaises(ValueError): m.oracle(regs, bad)
        bad = copy.deepcopy(pages); bad[m.STACK] = bytes(4095)
        with self.assertRaises(ValueError): m.oracle(regs, bad)

    @staticmethod
    def authored_fixture(count=4):
        # Authored x86: reserve 16 stack bytes, fill with zeros, call unmapped
        # EDX, return. These are not original-game bytes or a translated body.
        code = (b'\x83\xec\x10\x89\xe7\x31\xc0\xb9'+struct.pack('<I', count)+
                b'\xf3\xab\xff\xd2\xc3')
        _, nodes, _, _ = m.g.decode_flow(code, m.c.BASE+m.g.RVA, lambda i:i)
        base = m.c.BASE+0x1000
        page = bytearray(4096); page[0x460:0x460+len(code)] = code
        return nodes, {base:page}

    def test_authored_rep_executes_but_unmapped_callee_never_entered(self):
        nodes, code = self.authored_fixture()
        regs, pages = m.state(0); regs['edx'] = m.MARKERS[0]
        out, visited = m.prefix_reference(nodes, code, regs, pages)
        self.assertEqual(out['target'], m.MARKERS[0])
        self.assertEqual(nodes[out['site']].mnemonic, 'call')
        self.assertNotIn(out['site'], visited)
        self.assertEqual(out['regs']['esp'], regs['esp']-16)  # No CALL push.
        self.assertEqual(out['regs']['ecx'], 0)
        self.assertEqual(out['regs']['edi'], regs['esp'])
        sp = regs['esp']-m.STACK
        expected = bytearray(pages[m.STACK]); expected[sp-16:sp] = bytes(16)
        self.assertEqual(out['pages'][m.STACK], expected)
        self.assertEqual(out['pages'][m.OBJECT], pages[m.OBJECT])

    def test_rep_bounds_budget_and_code_identity_fail_closed(self):
        regs, pages = m.state(0)
        nodes, code = self.authored_fixture(257)
        with self.assertRaises(ValueError): m.prefix_reference(nodes, code, regs, pages)
        nodes, code = self.authored_fixture()
        for budget in (0, True, 1025, 2):
            with self.assertRaises(ValueError): m.prefix_reference(nodes, code, regs, pages, budget)
        for sp in (m.STACK+8, m.STACK+4100):
            with self.assertRaises(ValueError): m.prefix_reference(nodes, code, dict(regs, esp=sp), pages)
        bad = copy.deepcopy(code); bad[m.c.BASE+0x1000][0x460] ^= 1
        with self.assertRaises(ValueError): m.prefix_reference(nodes, bad, regs, pages)


if __name__ == '__main__': unittest.main()
