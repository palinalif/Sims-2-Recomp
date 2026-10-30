"""Authored descriptor-getter contracts; no private input or toolchain needed."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('descriptor_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InitializationDescriptorTests(unittest.TestCase):
    def test_full_contract_immutable_pages_and_preserved_registers(self):
        for n in range(64):
            regs, pages = m.state(n, m.DESCRIPTOR)
            self.assertEqual((regs, pages), m.state(n, m.DESCRIPTOR))
            before = copy.deepcopy(pages)
            result = m.oracle(regs, pages, m.DESCRIPTOR)
            wanted = dict(regs, eax=0xa0e17d90, esp=regs['esp']+4)
            self.assertEqual(result['regs'], [wanted[r] for r in m.REGS])
            self.assertEqual(bytes.fromhex(result['pages']), b''.join(pages[p] for p in m.PAGES))
            self.assertEqual(pages, before)
            pages[m.PAGES[0]][0] ^= 1
            self.assertNotEqual(pages, before)

    def test_verbatim_transport_exact_target_and_distinct_controls(self):
        body = 'static void initialization_descriptor_10960(void) { /* 1090 unchanged */ }'
        text = m.assemble(body, m.DESCRIPTOR)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0010960u,in,adapter_10960)', text)
        self.assertIn('case 0xA0010960u: initialization_descriptor_10960();', text)
        valid = m.bridge_source(m.BRIDGE.read_text(), 'valid', m.DESCRIPTOR)
        self.assertIn('targets{0xA0010960u}', valid)
        self.assertEqual(m.modes(m.DESCRIPTOR), ('valid', 'wrong-result', 'wrong-cleanup'))
        for mode, fault in [('wrong-result', 's[0]^=4;'), ('wrong-cleanup', 's[7]+=8;')]:
            changed = m.bridge_source(m.BRIDGE.read_text(), mode, m.DESCRIPTOR)
            self.assertEqual(changed, valid.replace('    current(s.data());', '    current(s.data());\n    '+fault))
        with self.assertRaises(ValueError): m.bridge_source(m.BRIDGE.read_text(), 'wrong-slot', m.DESCRIPTOR)
        with self.assertRaises(ValueError): m.bridge_source(m.BRIDGE.read_text(), 'wrong-result', m.RVA)
        with self.assertRaises(ValueError): m.unit(0x10970)

    def test_result_cleanup_memory_and_all_register_faults_reject(self):
        expected = [dict(case=n, **m.oracle(*m.state(n, m.DESCRIPTOR), m.DESCRIPTOR)) for n in range(64)]
        self.assertEqual(m.assess('\n'.join(map(json.dumps, expected)), expected, 'valid')['matched'], 64)
        for mode, reg in [('wrong-result', 0), ('wrong-cleanup', 7)]:
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps, expected)), expected, mode)
            bad = copy.deepcopy(expected)
            for row in bad: row['regs'][reg] ^= 4
            self.assertEqual(m.assess('\n'.join(map(json.dumps, bad)), expected, mode)['differing_cases'], 64)
        for reg in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps, bad)), expected, 'valid')
        for p in range(6):
            bad = copy.deepcopy(expected)
            b = bytearray.fromhex(bad[0]['pages']); b[p*4096] ^= 1
            bad[0]['pages'] = b.hex()
            with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps, bad)), expected, 'valid')
        with self.assertRaises(ValueError): m.assess('\n'.join(map(json.dumps, expected[:-1])), expected, 'wrong-result')

    def test_index_boundary_and_provenance_fail_closed(self):
        self.assertEqual(m.unit(m.DESCRIPTOR)[2:], (6, 2, ((0, 6),)))
        env = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=m.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals={'error':1}, result=dict(query={'rva':'0x10960'},
            program={'imageBaseVa':hex(m.BASE)}, truncation={}, function=dict(
                resolution='function-at', entryRva='0x10960', disassembly=dict(
                    instructionCount=2, extentBytes=6, extentEndVa='0xa0010965',
                    items=[{'va':'0xa0010960'}, {'va':'0xa0010965'}]))))
        self.assertTrue(m.check_index(env, m.DESCRIPTOR)['reliable_boundaries'])
        for key, value in [('instructionCount',1), ('extentBytes',5), ('extentEndVa','0xa0010966')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad, m.DESCRIPTOR)
        bad = copy.deepcopy(env); bad['provenance']['analysisPerformed'] = True
        with self.assertRaises(ValueError): m.check_index(bad, m.DESCRIPTOR)
