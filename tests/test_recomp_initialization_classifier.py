"""Authored EDI-zero path contracts; not a scan-path implementation/reference."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('classifier_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InitializationClassifierTests(unittest.TestCase):
    def test_zero_context_full_contract_and_fixture_isolation(self):
        for n in range(64):
            regs, pages = m.state(n, m.CLASSIFIER)
            self.assertEqual((regs, pages), m.state(n, m.CLASSIFIER))
            self.assertEqual(regs['edi'], 0)
            before = copy.deepcopy((regs, pages))
            result = m.oracle(regs, pages, m.CLASSIFIER)
            wanted = dict(regs, eax=6, esp=regs['esp']+4)
            self.assertEqual(result['regs'], [wanted[r] for r in m.REGS])
            self.assertEqual(result['pages'], b''.join(pages[p] for p in m.PAGES).hex())
            self.assertEqual((regs, pages), before)
            pages[m.PAGES[0]][0] ^= 1
            self.assertNotEqual(pages, before[1])

    def test_nonzero_edi_is_not_a_supported_oracle(self):
        regs, pages = m.state(0, m.CLASSIFIER)
        for value in (1, 6, 0x80000000, 0xffffffff):
            with self.assertRaises(ValueError):
                m.oracle(dict(regs, edi=value), pages, m.CLASSIFIER)
        for n in (-1, 64, True):
            with self.assertRaises(ValueError): m.state(n, m.CLASSIFIER)
        for rva in (0xfcb1, 0x109d0, True):
            with self.assertRaises(ValueError): m.unit(rva)

    def test_whole_body_verbatim_exact_target_and_faults(self):
        body = 'static void initialization_classifier_10700(void) { /* 1090 unchanged */ }'
        text = m.assemble(body, m.CLASSIFIER)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0010700u,in,adapter_10700)', text)
        self.assertIn('case 0xA0010700u: initialization_classifier_10700();', text)
        self.assertIn('default:reject();', text)
        self.assertIn('static constexpr unsigned address_sub_A000FCB0=0xA000FCB0u;', text)
        self.assertNotIn('case 0xA000FCB0u:', text)
        self.assertNotIn('void sub_A000FCB0(', text)
        self.assertIn('static uint32_t direct_return(uint32_t caller,uint32_t target) {\n    \n    reject();return 0;', text)
        valid = m.bridge_source(m.BRIDGE.read_text(), 'valid', m.CLASSIFIER)
        self.assertIn('targets{0xA0010700u}', valid)
        for mode, fault in [('wrong-result', 's[0]^=4;'), ('wrong-cleanup', 's[7]+=8;')]:
            changed = m.bridge_source(m.BRIDGE.read_text(), mode, m.CLASSIFIER)
            self.assertEqual(changed, valid.replace('    current(s.data());', '    current(s.data());\n    '+fault))
        with self.assertRaises(ValueError): m.bridge_source(m.BRIDGE.read_text(), 'wrong-slot', m.CLASSIFIER)

    def test_controls_must_differ_and_full_state_mutations_reject(self):
        expected = [dict(case=n, **m.oracle(*m.state(n, m.CLASSIFIER), m.CLASSIFIER)) for n in range(64)]
        encode = lambda rows: '\n'.join(map(json.dumps, rows))
        self.assertEqual(m.assess(encode(expected), expected, 'valid')['matched'], 64)
        for mode, reg in [('wrong-result', 0), ('wrong-cleanup', 7)]:
            with self.assertRaises(ValueError): m.assess(encode(expected), expected, mode)
            bad = copy.deepcopy(expected)
            for row in bad: row['regs'][reg] ^= 4
            self.assertEqual(m.assess(encode(bad), expected, mode)['differing_cases'], 64)
        for reg in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError): m.assess(encode(bad), expected, 'valid')
        for p in range(6):
            bad = copy.deepcopy(expected)
            b = bytearray.fromhex(bad[0]['pages']); b[p*4096] ^= 1
            bad[0]['pages'] = b.hex()
            with self.assertRaises(ValueError): m.assess(encode(bad), expected, 'valid')
        with self.assertRaises(ValueError): m.assess(encode(expected[:-1]), expected, 'wrong-result')

    def test_index_extent_is_whole_function_not_tested_path(self):
        _, _, size, count, blocks = m.unit(m.CLASSIFIER)
        self.assertEqual((size, count, len(blocks)), (49, 21, 7))
        self.assertEqual(len(m.CLASSIFIER_PATH), 4)
        env = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=m.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals={'error':1}, result=dict(query={'rva':'0x10700'},
            program={'imageBaseVa':hex(m.BASE)}, truncation={}, function=dict(
                resolution='function-at', entryRva='0x10700', disassembly=dict(
                    instructionCount=21, extentBytes=49, extentEndVa='0xa0010730',
                    items=[{'va':'0xa0010700'}]+[{} for _ in range(20)]))))
        self.assertTrue(m.check_index(env, m.CLASSIFIER)['reliable_boundaries'])
        for key, value in [('instructionCount',4), ('extentBytes',48), ('extentEndVa','0xa0010731')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad, m.CLASSIFIER)
        bad = copy.deepcopy(env); bad['provenance']['analysisPerformed'] = True
        with self.assertRaises(ValueError): m.check_index(bad, m.CLASSIFIER)
