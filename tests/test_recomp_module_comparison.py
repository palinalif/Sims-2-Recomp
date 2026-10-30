"""Public authored contracts; original-byte execution is a private explicit run."""
import copy
import struct
import unittest

from test_recomp_initialization_classifier import m


class ModuleComparisonTests(unittest.TestCase):
    def test_ascii_fold_value_contract(self):
        for left, right, expected in ((b'', b'', 1), (b'aZ', b'Az', 1),
                (b'abc', b'ab', 0), (b'@', b'`', 0), (b'[', b'{', 0),
                (b'\x80', b'\xa0', 0), (b'\xff', b'\xff', 1)):
            self.assertEqual(m.comparison_equal(left, right), expected)

    def test_fixtures_and_partial_independent_oracle_reject_faults(self):
        outcomes = set()
        for n in range(64):
            regs, pages = m.state(n, m.MODULE_COMPARE)
            self.assertEqual((regs, pages), m.state(n, m.MODULE_COMPARE))
            before = copy.deepcopy((regs, pages))
            left, right = m.comparison_pair(n)
            for reg, data in (('eax', left), ('edx', right)):
                page = regs[reg] & ~4095
                offset = regs[reg]-page
                self.assertEqual(pages[page][offset:offset+len(data)+1], data+b'\0')
            value = m.comparison_equal(left, right)
            outcomes.add(value)
            out = dict(regs, eax=value, esp=regs['esp']+4)
            after = copy.deepcopy(pages)
            struct.pack_into('<I', after[m.DATA_PAGES[0]], regs['esp']-m.DATA_PAGES[0]-4, regs['esi'])
            result = dict(regs=[out[r] for r in m.REGS], pages=b''.join(after[p] for p in m.PAGES).hex())
            m.comparison_contract(regs, pages, result, n)
            for reg in ('eax', 'ebx', 'ebp', 'esi', 'edi', 'esp'):
                bad = copy.deepcopy(result); bad['regs'][m.REGS.index(reg)] ^= 1
                with self.assertRaises(ValueError): m.comparison_contract(regs, pages, bad, n)
            bad = copy.deepcopy(result); bad['pages'] = ('01' if bad['pages'][:2] != '01' else '02')+bad['pages'][2:]
            with self.assertRaises(ValueError): m.comparison_contract(regs, pages, bad, n)
            self.assertEqual((regs, pages), before)
        self.assertEqual(outcomes, {0, 1})

    def test_verbatim_body_exact_dispatch_and_two_controls(self):
        body = 'static void initialization_module_compare_FCB0(void) { /* authored marker */ }'
        text = m.assemble(body, m.MODULE_COMPARE)
        self.assertEqual(text.count(body), 1)
        self.assertIn('case 0xA000FCB0u: initialization_module_compare_FCB0();', text)
        self.assertIn('cache_invoke(0xA000FCB0u,in,adapter_FCB0)', text)
        valid = m.bridge_source(m.BRIDGE.read_text(), 'valid', m.MODULE_COMPARE)
        self.assertIn('targets{0xA000FCB0u}', valid)
        self.assertIn('default:reject();', text)
        for mode, fault in (('wrong-result', 's[0]^=4;'), ('wrong-cleanup', 's[7]+=8;')):
            changed = m.bridge_source(m.BRIDGE.read_text(), mode, m.MODULE_COMPARE)
            self.assertEqual(changed, valid.replace('    current(s.data());', '    current(s.data());\n    '+fault))
        with self.assertRaises(ValueError): m.bridge_source(m.BRIDGE.read_text(), 'wrong-slot', m.MODULE_COMPARE)
        for n in (-1, 64, True):
            with self.assertRaises(ValueError): m.comparison_pair(n)

    def test_target_shape(self):
        _, _, size, count, blocks = m.unit(m.MODULE_COMPARE)
        self.assertEqual((size, count, len(blocks)), (51, 26, 11))
        self.assertEqual(m.modes(m.MODULE_COMPARE), ('valid', 'wrong-result', 'wrong-cleanup'))
        for rva in (0xfcaf, 0xfcb1, True):
            with self.assertRaises(ValueError): m.unit(rva)
