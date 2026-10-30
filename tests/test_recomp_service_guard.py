"""Public authored contract/transport tests; no original bytes or private inputs."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_service_guard.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('service_guard_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ServiceGuardTests(unittest.TestCase):
    def test_inputs_are_isolated_null_provider_in_esi_not_eax(self):
        positions = set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs, pages), m.state(n))
            self.assertEqual(set(pages), set(m.c.PAGES))
            self.assertNotEqual(regs['esi'], regs['eax'])
            self.assertEqual(struct.unpack_from('<I', pages[m.c.DATA_PAGES[1]], regs['esi']-m.c.DATA_PAGES[1]+0x74)[0], 0)
            positions.add((regs['esp'], regs['esi']))
            pages[m.c.DATA_PAGES[1]][0] ^= 1
            self.assertNotEqual(pages, m.state(n)[1])
        self.assertEqual(len(positions), 2)
        for bad in (-1, 64, True):
            with self.assertRaises(ValueError): m.state(bad)

    def test_oracle_preserves_all_other_registers_and_only_two_stack_words(self):
        for n in range(64):
            regs, pages = m.state(n)
            original = copy.deepcopy((regs, pages))
            out = m.oracle(regs, pages)
            wanted = dict(regs, eax=18, edx=0, esp=regs['esp']+4)
            self.assertEqual(out['regs'], [wanted[r] for r in m.c.REGS])
            after = bytearray(b''.join(pages[p] for p in m.c.PAGES))
            sp = regs['esp']-m.c.DATA_PAGES[0]
            struct.pack_into('<I', after, sp-4, regs['ebp'])
            struct.pack_into('<I', after, sp-1056, regs['edi'])
            self.assertEqual(out['pages'], after.hex())
            self.assertEqual((regs, pages), original)

    def test_nonnull_provider_invalid_receiver_frame_and_pages_reject(self):
        regs, pages = m.state(0)
        for value in (1, 0xffffffff, m.c.BASE+0x104f0):
            bad = copy.deepcopy(pages)
            struct.pack_into('<I', bad[m.c.DATA_PAGES[1]], regs['esi']-m.c.DATA_PAGES[1]+0x74, value)
            with self.assertRaises(ValueError): m.oracle(regs, bad)
        for address in (0, m.c.DATA_PAGES[1]+1, m.c.DATA_PAGES[1]+4092):
            with self.assertRaises(ValueError): m.oracle(dict(regs, esi=address), pages)
        with self.assertRaises(ValueError): m.oracle(dict(regs, esp=regs['esp']+4), pages)
        bad = copy.deepcopy(pages)
        struct.pack_into('<I', bad[m.c.DATA_PAGES[0]], regs['esp']-m.c.DATA_PAGES[0], 0)
        with self.assertRaises(ValueError): m.oracle(regs, bad)
        bad = copy.deepcopy(pages); bad[m.c.PAGES[-1]] = bytes(4095)
        with self.assertRaises(ValueError): m.oracle(regs, bad)

    def test_transport_keeps_body_verbatim_and_all_callees_unbound(self):
        body = 'static void service_guard_1460(void) { /* authored transport fixture */ }'
        text = m.assemble(body)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0001460u,in,adapter_1460)', text)
        for target in ('A00102D0', 'A0831A6F'):
            self.assertIn('address_sub_'+target, text)
            self.assertNotIn('case 0x'+target+'u:', text)
        self.assertIn('reject();return 0;', text)
        self.assertNotIn('@BODY@', text)
        with self.assertRaises(ValueError): m.assemble('')
        valid = m.bridge_source('valid')
        self.assertIn('targets{0xA0001460u}', valid)
        self.assertNotIn('s[0]^=4;', valid)
        self.assertIn('s[0]^=4;', m.bridge_source('wrong-result'))
        self.assertIn('s[7]+=8;', m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError): m.bridge_source('provider-stub')

    def test_comparison_requires_every_register_and_page(self):
        rows = [dict(case=n, **m.oracle(*m.state(n))) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        self.assertEqual(m.c.assess(encode(rows), rows, 'valid')['matched'], 64)
        for reg in range(8):
            bad = copy.deepcopy(rows); bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError): m.c.assess(encode(bad), rows, 'valid')
        for page in range(6):
            bad = copy.deepcopy(rows); data = bytearray.fromhex(bad[0]['pages'])
            data[page*4096] ^= 1; bad[0]['pages'] = data.hex()
            with self.assertRaises(ValueError): m.c.assess(encode(bad), rows, 'valid')
        with self.assertRaises(ValueError): m.c.assess(encode(rows[:-1]), rows, 'valid')

    def test_controls_must_diverge_and_cannot_count_same_reference_as_kill(self):
        rows = [dict(case=n, **m.oracle(*m.state(n))) for n in range(64)]
        encode = lambda data: '\n'.join(map(json.dumps, data))
        for mode in m.MODES[1:]:
            with self.assertRaises(ValueError): m.c.assess(encode(rows), rows, mode)
            bad = copy.deepcopy(rows)
            for row in bad: row['regs'][0 if mode == 'wrong-result' else 7] ^= 4
            self.assertEqual(m.c.assess(encode(bad), rows, mode)['differing_cases'], 64)


if __name__ == '__main__': unittest.main()
