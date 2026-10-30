"""Authored 3700 empty-input contracts; no original code or private states."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_mode_empty.py'
spec = importlib.util.spec_from_file_location('mode_empty', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c


class ModeEmptyTests(unittest.TestCase):
    def test_deterministic_empty_inputs_and_dirty_disjoint_receivers(self):
        sources, receivers = set(), set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            source = regs['eax']-c.DATA_PAGES[2]
            receiver = regs['esi']-c.DATA_PAGES[1]
            sources.add(source); receivers.add(receiver)
            self.assertEqual(pages[c.DATA_PAGES[2]][source], 0)
            self.assertNotEqual(pages[c.DATA_PAGES[1]][receiver:receiver+528], bytes(528))
            self.assertEqual(struct.unpack_from('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0])[0], c.RETURN)
        self.assertEqual(sources, {0, 1, 128, 4095})
        self.assertEqual(receivers, {0, 128, 1024, 3568})
        for bad in (-1, 64, True, 1.5):
            with self.assertRaises(ValueError):
                m.state(bad)

    def test_full_oracle_preserves_input_and_nonstack_pages(self):
        for n in range(64):
            regs, pages = m.state(n)
            before = copy.deepcopy((regs, pages))
            result = m.oracle(regs, pages)
            self.assertEqual((regs, pages), before)
            out = dict(zip(c.REGS, result['regs']))
            self.assertEqual(out, dict(regs, eax=1, ecx=regs['eax'], esp=regs['esp']+4))
            raw = bytes.fromhex(result['pages'])
            sp = regs['esp']-c.DATA_PAGES[0]
            self.assertEqual(struct.unpack_from('<4I', raw, sp-16),
                             (regs['edi'], regs['ebp'], regs['ebx'], regs['eax']))
            self.assertEqual(raw[:sp-16], pages[c.DATA_PAGES[0]][:sp-16])
            self.assertEqual(raw[sp:4096], pages[c.DATA_PAGES[0]][sp:])
            self.assertEqual(raw[4096:], b''.join(pages[p] for p in c.PAGES[1:]))

    def test_invalid_preconditions_reject_not_infer_nonempty_contract(self):
        for mode in ('nonempty', 'source', 'receiver', 'stack', 'return', 'page', 'register'):
            regs, pages = m.state(0)
            if mode == 'nonempty': pages[c.DATA_PAGES[2]][0] = 65
            elif mode == 'source': regs['eax'] = c.DATA_PAGES[2]-1
            elif mode == 'receiver': regs['esi'] = c.DATA_PAGES[1]+4096-527
            elif mode == 'stack': regs['esp'] = c.DATA_PAGES[0]+15
            elif mode == 'return': struct.pack_into('<I', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0], 0)
            elif mode == 'page': pages[c.PAGES[-1]] = pages[c.PAGES[-1]][:-1]
            else: regs['edx'] = True
            with self.assertRaises(ValueError, msg=mode):
                m.oracle(regs, pages)

    def test_transport_retains_body_but_registers_no_callees(self):
        body = 'static void mode_empty_3700(void) { /* authored fixture */ }'
        text = m.assemble(body)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0003700u,in,adapter_3700)', text)
        for target in m.CALLEES:
            self.assertIn(f'address_sub_{c.BASE+target:08X}', text)
            self.assertNotIn(f'case 0x{c.BASE+target:08X}u:', text)
        for mode in m.MODES:
            bridge = m.bridge_source(mode)
            self.assertIn('std::array<uint32_t,1> targets{0xA0003700u}', bridge)
        self.assertIn('s[0]^=4;', m.bridge_source('wrong-result'))
        self.assertIn('s[7]+=8;', m.bridge_source('wrong-cleanup'))
        for bad in ('stub', '', None):
            with self.assertRaises(ValueError): m.bridge_source(bad)
        with self.assertRaises(ValueError): m.assemble('')

    def test_comparator_rejects_wrong_result_cleanup_page_and_truncation(self):
        expected = [dict(case=n, **m.oracle(*m.state(n))) for n in range(64)]
        good = '\n'.join(json.dumps(row) for row in expected)
        c.assess(good, expected, 'valid')
        for mode in ('wrong-result', 'wrong-cleanup'):
            bad = copy.deepcopy(expected)
            for row in bad: row['regs'][0 if mode == 'wrong-result' else 7] ^= 4
            text = '\n'.join(json.dumps(row) for row in bad)
            c.assess(text, expected, mode)
            with self.assertRaises(ValueError): c.assess(text, expected, 'valid')
            with self.assertRaises(ValueError): c.assess(good, expected, mode)
        bad = copy.deepcopy(expected)
        raw = bytearray.fromhex(bad[0]['pages']); raw[4096+128] ^= 1
        bad[0]['pages'] = raw.hex()
        with self.assertRaises(ValueError):
            c.assess('\n'.join(json.dumps(row) for row in bad), expected, 'valid')
        with self.assertRaises(ValueError): c.assess(good.rsplit('\n', 1)[0], expected, 'valid')


if __name__ == '__main__':
    unittest.main()
