"""Authored instruction fixtures, not original-game code or behavior."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/inspect_handle_writers.py'
spec = importlib.util.spec_from_file_location('handle_writers', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class HandleWriterTests(unittest.TestCase):
    def inspect(self, code):
        return m.inventory(bytes.fromhex(code), 0x1000, SimpleNamespace())

    def test_constant_zero_and_immediate_assignments(self):
        r = self.inspect('31ff 897e74 c786d000000078563412 c3')
        self.assertEqual([w['constant'] for w in r['writes']], [0, 0x12345678])
        self.assertEqual([w['field_displacement'] for w in r['writes']], ['0x74', '0xd0'])
        self.assertTrue(all(not w['receiver_identity_verified'] for w in r['writes']))
        self.assertFalse(r['executed'])
        self.assertFalse(r['callee_effects_modeled'])

    def test_call_kills_nonvolatile_constants_too(self):
        r = self.inspect('31ff e800100000 897e74 c3')
        self.assertIsNone(r['writes'][0]['constant'])
        self.assertEqual(r['dependencies']['direct_calls'], ['0x2007'])

    def test_conflicting_join_is_unknown(self):
        # Two incoming values of EDI; both normal-flow branches included.
        r = self.inspect('85c0 7407 bf01000000 eb05 bf02000000 897e74 c3')
        self.assertIsNone(r['writes'][0]['constant'])

    def test_agreeing_join_retains_constant(self):
        r = self.inspect('85c0 7407 bf02000000 eb05 bf02000000 897e74 c3')
        self.assertEqual(r['writes'][0]['constant'], 2)

    def test_loop_reaches_fixed_point_without_claiming_feasibility(self):
        r = self.inspect('31ff 85c0 75fc 897e74 c3')
        self.assertEqual(r['writes'][0]['constant'], 0)

    def test_partial_register_write_invalidates_parent(self):
        r = self.inspect('31c0 b001 894674 c3')
        self.assertIsNone(r['writes'][0]['constant'])

    def test_memory_load_is_unknown_and_unrelated_offset_ignored(self):
        r = self.inspect('31ff 8b3b 897e74 897e70 c3')
        self.assertEqual(len(r['writes']), 1)
        self.assertIsNone(r['writes'][0]['constant'])

    def test_read_modify_write_not_source_assignment(self):
        r = self.inspect('31ff 017e74 c3')
        self.assertEqual(r['writes'][0]['source_kind'], 'unknown')
        self.assertIsNone(r['writes'][0]['constant'])

    def test_early_return_does_not_hide_other_path(self):
        r = self.inspect('85c0 7401 c3 c7467401000000 c3')
        self.assertEqual(len(r['writes']), 1)
        self.assertEqual(r['writes'][0]['constant'], 1)
        self.assertEqual(r['body']['instructions'], 5)

    def test_index_and_segment_candidates_are_not_handle_proof(self):
        r = self.inspect('31c0 648944be74 c3')
        w = r['writes'][0]
        self.assertTrue(w['segmented'])
        self.assertTrue(w['indexed'])
        self.assertFalse(w['receiver_identity_verified'])

    def test_invalid_scope_escape_and_truncation_reject(self):
        for code in (b'', b'\x90'*(m.BOUND+1), b'\xeb\x7f', b'\xe8', b'\xff\xe0'):
            with self.subTest(size=len(code)), self.assertRaises(ValueError):
                m.inventory(code, 0x1000, SimpleNamespace())

    def test_output_must_be_private_before_any_input_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                m.inspect(Path(tmp), Path(tmp)/'output')
            self.assertFalse((Path(tmp)/'output').exists())


if __name__ == '__main__':
    unittest.main()
