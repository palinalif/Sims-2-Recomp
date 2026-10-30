"""Authored contracts only; original bytes/lifts/reference states remain private."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('service_size_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RVA = m.SIZE_QUERY


class ServiceSizeTests(unittest.TestCase):
    def test_pinned_unit_and_transport_are_size_query_not_setter(self):
        slot, sha, size, count, blocks = m.unit(RVA)
        self.assertIsNone(slot)
        self.assertEqual((len(sha), size, count, blocks), (64, 6, 2, ((0, 6),)))
        self.assertEqual(m.body_name(RVA), 'initialization_size_query_102D0')
        self.assertEqual(m.modes(RVA), ('valid', 'wrong-result', 'wrong-cleanup'))
        body = 'static void initialization_size_query_102D0(void) { /* authored fixture */ }'
        text = m.assemble(body, RVA)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA00102D0u,in,adapter_102D0)', text)
        self.assertIn('reject();return 0;', text)
        valid = m.bridge_source(m.BRIDGE.read_text(), 'valid', RVA)
        self.assertIn('targets{0xA00102D0u}', valid)
        self.assertNotIn('s[0]^=4;', valid)
        for bad in (True, 0x102d1, 0):
            with self.assertRaises(ValueError): m.unit(bad)
        with self.assertRaises(ValueError): m.bridge_source(m.BRIDGE.read_text(), 'wrong-slot', RVA)

    def test_randomized_inputs_isolated_and_no_receiver_assumption(self):
        registers = {r:set() for r in m.REGS}
        for n in range(64):
            regs, pages = m.state(n, RVA)
            self.assertEqual((regs, pages), m.state(n, RVA))
            for r, value in regs.items(): registers[r].add(value)
            pages[m.PAGES[1]][17] ^= 1
            self.assertNotEqual(pages, m.state(n, RVA)[1])
        self.assertEqual(len(registers['esp']), 2)
        for r in set(m.REGS)-{'esp'}: self.assertEqual(len(registers[r]), 64)
        for bad in (-1, 64, True):
            with self.assertRaises(ValueError): m.state(bad, RVA)

    def test_oracle_changes_only_result_and_return_stack_pointer(self):
        for n in range(64):
            regs, pages = m.state(n, RVA)
            before = copy.deepcopy((regs, pages))
            out = m.oracle(regs, pages, RVA)
            wanted = dict(regs, eax=1912, esp=regs['esp']+4)
            self.assertEqual(out['regs'], [wanted[r] for r in m.REGS])
            self.assertEqual(out['pages'], b''.join(pages[p] for p in m.PAGES).hex())
            self.assertEqual((regs, pages), before)

    def test_oracle_rejects_malformed_frame_and_pages(self):
        regs, pages = m.state(0, RVA)
        for address in (0, m.DATA_PAGES[0]+1, m.DATA_PAGES[0]+4096):
            with self.assertRaises(ValueError): m.oracle(dict(regs, esp=address), pages, RVA)
        for bad in (True, -1, 0x100000000):
            with self.assertRaises(ValueError): m.oracle(dict(regs, edi=bad), pages, RVA)
        bad = copy.deepcopy(pages)
        struct.pack_into('<I', bad[m.DATA_PAGES[0]], regs['esp']-m.DATA_PAGES[0], 0)
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)
        bad = copy.deepcopy(pages); bad[m.PAGES[-1]] = bytes(4095)
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)
        bad = copy.deepcopy(pages); del bad[m.PAGES[-1]]
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)

    def test_full_comparison_rejects_each_register_page_and_truncation(self):
        rows = [dict(case=n, **m.oracle(*m.state(n, RVA), RVA)) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        self.assertEqual(m.assess(encode(rows), rows, 'valid')['matched'], 64)
        for reg in range(8):
            bad = copy.deepcopy(rows); bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, 'valid')
        for page in range(6):
            bad = copy.deepcopy(rows); data = bytearray.fromhex(bad[0]['pages'])
            data[page*4096] ^= 1; bad[0]['pages'] = data.hex()
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, 'valid')
        with self.assertRaises(ValueError): m.assess(encode(rows[:-1]), rows, 'valid')

    def test_result_and_cleanup_controls_need_real_divergence(self):
        rows = [dict(case=n, **m.oracle(*m.state(n, RVA), RVA)) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        for mode, reg in (('wrong-result', 0), ('wrong-cleanup', 7)):
            bridge = m.bridge_source(m.BRIDGE.read_text(), mode, RVA)
            self.assertIn('s[0]^=4;' if reg == 0 else 's[7]+=8;', bridge)
            with self.assertRaises(ValueError): m.assess(encode(rows), rows, mode)
            bad = copy.deepcopy(rows)
            for row in bad: row['regs'][reg] ^= 4
            self.assertEqual(m.assess(encode(bad), rows, mode)['differing_cases'], 64)


if __name__ == '__main__': unittest.main()
