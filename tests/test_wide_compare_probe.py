"""Authored oracle/runner controls only; no original comparator bytes."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import wide_compare_probe as p


class WideCompareTests(unittest.TestCase):
    def test_oracle_exact_unsigned_difference_not_casefold_or_sign(self):
        self.assertEqual(p.oracle((65,), (97,), 1), 0xFFFFFFE0)
        self.assertEqual(p.oracle((65535,), (0,), 1), 65535)
        self.assertEqual(p.oracle((0,), (65535,), 1), 0xFFFF0001)
        self.assertEqual(p.oracle((0xD800,), (0x7FFF,), 1), 0x5801)

    def test_oracle_units_bounds_and_early_termination(self):
        self.assertEqual(p.oracle((), (), 0), 0)
        self.assertEqual(p.oracle((7, 1), (7, 2), 1), 0)
        self.assertEqual(p.oracle((7, 1), (7, 2), 2), p.r.NEG)
        self.assertEqual(p.oracle((0,), (0,), 32), 0)
        self.assertEqual(p.oracle((1,), (2,), 32), p.r.NEG)
        for args in (((1,), (1,), 2), ((), (), -1), ((65536,), (0,), 1),
                     ((1,), (1,), 33)):
            with self.assertRaises(ValueError):
                p.oracle(*args)

    def test_authored_runner_return_and_unmapped_zero_count(self):
        # Immediate return fixture, not a reconstruction of the original body.
        p.exercise(b'\x31\xc0\xc3', (), (), 0, 0)
        p.exercise(b'\xb8' + struct.pack('<I', 65535) + b'\xc3',
                   (1,), (2,), 1, 65535, unaligned=True)

    def test_guard_rejects_input_overread(self):
        # Load left pointer then read one unit beyond its supplied single unit.
        code = b'\x8b\x44\x24\x04\x0f\xb7\x40\x02\xc3'
        with self.assertRaises(p.UcError):
            p.exercise(code, (7,), (7,), 1, 0)
        with self.assertRaises(p.UcError):
            p.exercise(b'\x8b\x44\x24\x04\x8b\x00\xc3', (), (), 0, 0)

    def test_runner_rejects_write_abi_result_escape_and_budget(self):
        variants = (b'\x31\xc0\x43\xc3', b'\x31\xc0\xc2\x0c\x00',
                    b'\xb8\x01\x00\x00\x00\xc3', b'\xeb\xfe',
                    b'\xeb\x40', b'\xff\x44\x24\x04\x31\xc0\xc3',
                    b'\x8b\x44\x24\x04\x66\xff\x00\x31\xc0\xc3')
        for code in variants:
            with self.subTest(code=code), self.assertRaises(ValueError):
                p.exercise(code, (7,), (7,), 1, 0)

    def test_cli_rejects_pin_without_output_or_input_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'private.bin'
            path.write_bytes(b'authored private input')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(p.r, 'IMAGE', path), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main(), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('authored', err.getvalue())
            self.assertEqual(path.read_bytes(), b'authored private input')


if __name__ == '__main__':
    unittest.main()
