"""Authored encodings only; original code and index output remain private."""
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/inspect_resource_dependency.py'
spec = importlib.util.spec_from_file_location('resource_dependency', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
ENTRY = bench.BASE+0x2000
TARGET = bench.BASE+0x4000
PE = SimpleNamespace()


def call(address):
    return b'\xe8'+struct.pack('<i', TARGET-address-5)


class ResourceDependencyTests(unittest.TestCase):
    def test_index_extent_and_adjacent_trap_are_distinct(self):
        code = call(ENTRY)+b'\xcc'
        result = bench.characterize(code, ENTRY, 5, PE)
        self.assertEqual(result['body']['instructions'], 1)
        self.assertEqual(result['body']['size_bytes'], 5)
        self.assertFalse(result['indexed']['accepted'])
        self.assertEqual(result['indexed']['reason'], 'Escaping normal flow')
        extended = result['with_one_adjacent_instruction']
        self.assertFalse(extended['accepted'])
        self.assertEqual(extended['reason'], 'Interrupt requires explicit nonreturn policy')
        self.assertEqual(extended['evidence']['rejected_instruction_rva'], '0x2005')
        self.assertEqual(extended['evidence']['adjacent_call_target_rva'], '0x4000')
        self.assertTrue(result['adjacent_instruction_is_interrupt'])
        self.assertFalse(result['adjacent_instruction_owned_by_function'])
        self.assertFalse(result['linear_dependencies_are_complete_cfg'])

    def test_branch_and_valid_return_do_not_hide_other_rejected_path(self):
        # JZ local RET; otherwise CALL external, then fall outside indexed extent.
        code = b'\x74\x01\xc3'+call(ENTRY+3)+b'\xcc'
        result = bench.characterize(code, ENTRY, 8, PE)
        self.assertEqual(result['body']['instructions'], 3)
        self.assertFalse(result['straight_prefix']['accepted'])
        self.assertFalse(result['indexed']['accepted'])
        self.assertFalse(result['with_one_adjacent_instruction']['accepted'])
        self.assertFalse(result['indexed']['evidence']['complete_cfg'])

    def test_returning_body_does_not_acquire_adjacent_trap(self):
        result = bench.characterize(b'\x90\xc3\xcc', ENTRY, 2, PE)
        self.assertTrue(result['indexed']['accepted'])
        self.assertTrue(result['with_one_adjacent_instruction']['accepted'])
        self.assertTrue(result['adjacent_instruction_is_interrupt'])
        self.assertFalse(result['adjacent_predecessor_is_direct_call'])
        self.assertIsNone(result['adjacent_predecessor_target_rva'])

    def test_indirect_call_not_promoted_to_direct_target(self):
        result = bench.characterize(b'\xff\xd0\xcc', ENTRY, 2, PE)
        self.assertEqual(result['linear_dependencies']['indirect_calls'], 1)
        self.assertEqual(result['linear_dependencies']['direct_calls'], [])
        self.assertFalse(result['adjacent_predecessor_is_direct_call'])
        self.assertFalse(result['straight_prefix']['accepted'])

    def test_partial_and_unbounded_windows_reject(self):
        for code, size in ((b'\xe8\x00\xcc', 2), (b'\xc3', 1),
                           (b'\xc3\xcc', 0), (b'\xc3\xcc', True),
                           (bytes(257), 2)):
            with self.subTest(size=size), self.assertRaises(ValueError):
                bench.characterize(code, ENTRY, size, PE)

    def test_private_output_pin_exclusivity_and_symlink_guards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            (private/'link').symlink_to(outside)
            for output in (outside/'out.json', private/'link/out.json'):
                with self.assertRaisesRegex(ValueError, 'Private'):
                    bench.run(root/'index', output)
            output = private/'out.json'
            with patch.object(bench, 'digest', return_value='bad'):
                with self.assertRaisesRegex(ValueError, 'pin'):
                    bench.run(root/'index', output)
            self.assertFalse(output.exists())
            output.write_text('preserved')
            with self.assertRaises(FileExistsError):
                bench.run(root/'index', output)
            self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
