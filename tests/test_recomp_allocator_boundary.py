"""Authored x86 only: bounded allocator inventory, never game behavior."""
import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/inspect_allocator_boundary.py'
spec = importlib.util.spec_from_file_location('allocator_boundary', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class AllocatorBoundaryTests(unittest.TestCase):
    def test_calls_are_recorded_not_followed(self):
        # CALL outside window, absolute IAT CALL, load global, RET 4.
        code = bytes.fromhex('e8ffffff00 ff15001000a0 a1002000a0 c20400')
        pe = SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(
            dll=b'fixture.dll', imports=[SimpleNamespace(address=0xa0001000,
                name=b'FixtureAllocate', ordinal=None)])])
        r = m.inventory(code, pe)
        self.assertFalse(r['targets_followed'])
        self.assertFalse(r['abi_established'])
        self.assertEqual(r['body']['returns'][0]['encoded_cleanup_bytes'], 4)
        self.assertEqual(r['dependencies']['direct_calls'], [hex(m.RVA + 0x1000004)])
        self.assertEqual(r['dependencies']['indirect_call_sites'][0]['import_metadata']['name'],
                         'FixtureAllocate')
        self.assertEqual(r['dependencies']['absolute_memory_va'], ['0xa0001000', '0xa0002000'])

    def test_scope_escape_and_truncated_instruction_reject(self):
        for code in (b'', b'\x90' * (m.BOUND + 1), b'\xeb\x7f', b'\xe8'):
            with self.subTest(size=len(code)), self.assertRaises(ValueError):
                m.inventory(code, SimpleNamespace())

    def test_indirect_jump_rejects(self):
        with self.assertRaises(ValueError):
            m.inventory(b'\xff\xe0', SimpleNamespace())

    def envelope(self):
        return dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=m.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals={'errors': 1}, result=dict(query=dict(rva=hex(m.RVA)),
                program=dict(imageBaseVa=hex(m.BASE)), truncation=dict(instructions=True),
                function=dict(resolution='function-at', entryRva=hex(m.RVA),
                    disassembly=dict(items=[dict(rva=hex(m.RVA))]))))

    def test_capped_prefix_is_not_full_boundary_agreement(self):
        body = m.inventory(b'\x90\xc3', SimpleNamespace())['body']
        r = m.check_index(self.envelope(), body)
        self.assertTrue(r['prefix_boundaries_agree'])
        self.assertFalse(r['complete_boundary_agreement'])
        self.assertEqual(r['log_signals'], {'errors': 1})

    def test_wrong_provenance_or_boundary_rejects(self):
        body = m.inventory(b'\x90\xc3', SimpleNamespace())['body']
        base = self.envelope()
        mutations = [('mode', 'write'), ('sourceImageSha256', 'wrong'),
                     ('analysisPerformed', True), ('headlessExitCode', 1)]
        for key, value in mutations:
            e = copy.deepcopy(base)
            e['provenance'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.check_index(e, body)
        e = copy.deepcopy(base)
        e['result']['function']['disassembly']['items'][0]['rva'] = hex(m.RVA+1)
        with self.assertRaises(ValueError):
            m.check_index(e, body)


if __name__ == '__main__':
    unittest.main()
