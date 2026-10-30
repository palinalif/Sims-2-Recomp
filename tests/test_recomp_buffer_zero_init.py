"""Authored contracts for the bounded 1A00 dependency, no original code."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('buffer_zero_init_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RVA = m.BUFFER_INIT


class BufferZeroInitTests(unittest.TestCase):
    def test_profile_and_transport_are_exact_and_fail_closed(self):
        slot, sha, size, count, blocks = m.unit(RVA)
        self.assertEqual((slot, len(sha), size, count, blocks),
                         (None, 64, 14, 6, ((0, 14),)))
        self.assertEqual(m.zero_span(RVA), 16)
        self.assertEqual(m.zero_span(m.ZERO_INIT), 20)
        body = 'static void initialization_zero_init_1A00(void) { /* authored */ }'
        text = m.assemble(body, RVA)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0001A00u,in,adapter_1A00)', text)
        self.assertIn('reject();return 0;', text)
        self.assertIn('targets{0xA0001A00u}', m.bridge_source(m.BRIDGE.read_text(), 'valid', RVA))
        for bad in (True, 0x1a01, m.SIZE_QUERY):
            with self.assertRaises(ValueError): m.zero_span(bad)

    def test_inputs_are_deterministic_isolated_and_page_end_safe(self):
        addresses = set()
        for n in range(64):
            regs, pages = m.state(n, RVA)
            self.assertEqual((regs, pages), m.state(n, RVA))
            addresses.add(regs['eax'])
            pages[m.DATA_PAGES[1]][0] ^= 1
            self.assertNotEqual(pages, m.state(n, RVA)[1])
        self.assertEqual(addresses, {m.DATA_PAGES[1]+o for o in (0, 128, 3584, 4080)})
        for bad in (True, -1, 64):
            with self.assertRaises(ValueError): m.state(bad, RVA)

    def test_independent_oracle_clears_only_sixteen_bytes(self):
        for n in range(64):
            regs, pages = m.state(n, RVA)
            before = copy.deepcopy((regs, pages))
            row = m.oracle(regs, pages, RVA)
            want = dict(regs, ecx=0, esp=regs['esp']+4)
            self.assertEqual(row['regs'], [want[r] for r in m.REGS])
            expected = bytearray(b''.join(pages[p] for p in m.PAGES))
            offset = m.PAGES.index(m.DATA_PAGES[1])*4096+regs['eax']-m.DATA_PAGES[1]
            expected[offset:offset+16] = bytes(16)
            self.assertEqual(bytes.fromhex(row['pages']), expected)
            self.assertEqual((regs, pages), before)

    def test_invalid_spans_frames_and_types_reject(self):
        regs, pages = m.state(0, RVA)
        for address in (0, m.DATA_PAGES[1]-4, m.DATA_PAGES[1]+4081, m.DATA_PAGES[1]+4084):
            with self.assertRaises(ValueError): m.oracle(dict(regs, eax=address), pages, RVA)
        for address in (0, m.DATA_PAGES[0]+1, m.DATA_PAGES[0]+4096):
            with self.assertRaises(ValueError): m.oracle(dict(regs, esp=address), pages, RVA)
        with self.assertRaises(ValueError): m.oracle(dict(regs, ebx=True), pages, RVA)
        bad = copy.deepcopy(pages)
        bad[m.DATA_PAGES[0]][regs['esp']-m.DATA_PAGES[0]] ^= 1
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)
        bad = copy.deepcopy(pages); bad[m.PAGES[-1]] = bytes(4095)
        with self.assertRaises(ValueError): m.oracle(regs, bad, RVA)

    def test_comparator_rejects_neighbor_write_and_truncated_rows(self):
        rows = [dict(case=n, **m.oracle(*m.state(n, RVA), RVA)) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        self.assertEqual(m.assess(encode(rows), rows, 'valid')['matched'], 64)
        offset = m.PAGES.index(m.DATA_PAGES[1])*4096
        for byte in (0, 4, 8, 12, 16, 4095):
            bad = copy.deepcopy(rows); raw = bytearray.fromhex(bad[0]['pages'])
            raw[offset+byte] ^= 1; bad[0]['pages'] = raw.hex()
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, 'valid')
        for bad in (rows[:-1], rows[::-1], rows+[rows[-1]]):
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, 'valid')

    def test_controls_need_behavioral_divergence_not_transport_failure(self):
        rows = [dict(case=n, **m.oracle(*m.state(n, RVA), RVA)) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        for mode, reg, marker in (('wrong-result', 0, 's[0]^=4;'),
                                  ('wrong-cleanup', 7, 's[7]+=8;')):
            self.assertIn(marker, m.bridge_source(m.BRIDGE.read_text(), mode, RVA))
            with self.assertRaises(ValueError): m.assess(encode(rows), rows, mode)
            bad = copy.deepcopy(rows)
            for row in bad: row['regs'][reg] ^= 4
            self.assertEqual(m.assess(encode(bad), rows, mode)['differing_cases'], 64)
            bad[0]['pages'] = 'g'*len(bad[0]['pages'])
            with self.assertRaises(ValueError): m.assess(encode(bad), rows, mode)


if __name__ == '__main__': unittest.main()
