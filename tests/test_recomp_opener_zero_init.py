"""Public authored contracts; no original bytes or derived bodies in this file."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('opener_zero_init_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RVA = m.ZERO_INIT


class OpenerZeroInitTests(unittest.TestCase):
    def test_pinned_unit_uses_exact_dispatch_and_verbatim_body(self):
        slot, sha, size, count, blocks = m.unit(RVA)
        self.assertIsNone(slot)
        self.assertEqual((len(sha), size, count, blocks), (64, 17, 7, ((0, 17),)))
        self.assertEqual(m.body_name(RVA), 'initialization_zero_init_1A40')
        body = 'static void initialization_zero_init_1A40(void) { /* authored */ }'
        text = m.assemble(body, RVA)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0001A40u,in,adapter_1A40)', text)
        self.assertIn('reject();return 0;', text)
        bridge = m.bridge_source(m.BRIDGE.read_text(), 'valid', RVA)
        self.assertIn('targets{0xA0001A40u}', bridge)
        self.assertEqual(m.modes(RVA), ('valid', 'wrong-result', 'wrong-cleanup'))
        for bad in (True, 0x1a41, 0):
            with self.assertRaises(ValueError): m.unit(bad)

    def test_state_is_deterministic_isolated_and_exercises_page_end(self):
        addresses = set()
        for n in range(64):
            regs, pages = m.state(n, RVA)
            self.assertEqual((regs, pages), m.state(n, RVA))
            addresses.add(regs['eax'])
            self.assertNotEqual(regs['eax'], regs['esi'])
            pages[m.DATA_PAGES[1]][0] ^= 1
            self.assertNotEqual(pages, m.state(n, RVA)[1])
        self.assertEqual(addresses, {m.DATA_PAGES[1]+o for o in (0, 0x80, 0xe00, 4076)})
        for bad in (True, -1, 64):
            with self.assertRaises(ValueError): m.state(bad, RVA)

    def test_oracle_clears_exact_twenty_bytes_and_preserves_everything_else(self):
        for n in range(64):
            regs, pages = m.state(n, RVA)
            before = copy.deepcopy((regs, pages))
            out = m.oracle(regs, pages, RVA)
            want = dict(regs, ecx=0, esp=regs['esp']+4)
            self.assertEqual(out['regs'], [want[r] for r in m.REGS])
            raw = bytes.fromhex(out['pages'])
            for index, p in enumerate(m.PAGES):
                expected = bytearray(pages[p])
                if p == m.DATA_PAGES[1]:
                    offset = regs['eax']-p
                    expected[offset:offset+20] = bytes(20)
                self.assertEqual(raw[index*4096:(index+1)*4096], expected)
            self.assertEqual((regs, pages), before)

    def test_oracle_rejects_invalid_spans_frames_and_boolean_registers(self):
        regs, pages = m.state(0, RVA)
        for address in (0, m.DATA_PAGES[1]-4, m.DATA_PAGES[1]+4077,
                        m.DATA_PAGES[1]+4080, 0xfffffff0):
            with self.assertRaises(ValueError): m.oracle(dict(regs, eax=address), pages, RVA)
        for address in (0, m.DATA_PAGES[0]+1, m.DATA_PAGES[0]+4096):
            with self.assertRaises(ValueError): m.oracle(dict(regs, esp=address), pages, RVA)
        with self.assertRaises(ValueError): m.oracle(dict(regs, edi=True), pages, RVA)
        bad = copy.deepcopy(pages)
        struct.pack_into('<I', bad[m.DATA_PAGES[0]], regs['esp']-m.DATA_PAGES[0], 0)
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)
        bad = copy.deepcopy(pages); bad[m.PAGES[-1]] = bytes(4095)
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)

    def test_comparison_rejects_retained_field_and_neighbor_corruption(self):
        rows = [dict(case=n, **m.oracle(*m.state(n, RVA), RVA)) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        self.assertEqual(m.assess(encode(rows), rows, 'valid')['matched'], 64)
        offset = m.PAGES.index(m.DATA_PAGES[1])*4096
        for byte in (0, 4, 8, 12, 16, 20, 4095):
            bad = copy.deepcopy(rows); raw = bytearray.fromhex(bad[0]['pages'])
            raw[offset+byte] ^= 1; bad[0]['pages'] = raw.hex()
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, 'valid')
        for bad in (rows[:-1], rows[::-1], rows+[rows[-1]]):
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, 'valid')

    def test_controls_require_observed_divergence_not_rejected_execution(self):
        rows = [dict(case=n, **m.oracle(*m.state(n, RVA), RVA)) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        for mode, reg in (('wrong-result', 0), ('wrong-cleanup', 7)):
            bridge = m.bridge_source(m.BRIDGE.read_text(), mode, RVA)
            self.assertIn('s[0]^=4;' if reg == 0 else 's[7]+=8;', bridge)
            with self.assertRaises(ValueError): m.assess(encode(rows), rows, mode)
            bad = copy.deepcopy(rows)
            for row in bad: row['regs'][reg] ^= 4
            self.assertEqual(m.assess(encode(bad), rows, mode)['differing_cases'], 64)
            bad[0] = dict(case=0, rejected=True)
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, mode)


if __name__ == '__main__': unittest.main()
