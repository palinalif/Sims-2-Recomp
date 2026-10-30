"""Authored controls only: no original-code fixtures or proprietary tables."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import os_error_probe as p
r = p.r


def table():
    return [(10000+n, 0x80000000+n) for n in range(p.COUNT)]


class OsErrorProbeTests(unittest.TestCase):
    def test_unsigned_interval_boundaries_and_no_success_special_case(self):
        for error, expected in ((0, 22), (18, 22), (19, 13), (36, 13), (37, 22),
                                (187, 22), (188, 8), (202, 8), (203, 22),
                                (0x80000000, 22), (r.NEG, 22)):
            with self.subTest(error=error):
                state = p.oracle(error, table())
                self.assertEqual(state['registers'][0], expected)
                self.assertEqual(state['registers'][2], error if expected == 13 else 14)
                self.assertEqual(state['registers'][7], r.SP+4)

    def test_exact_table_precedes_ranges_and_first_match_wins(self):
        for error in (0, 19, 188, r.NEG):
            fixture = table()
            fixture[0] = (error, 0)
            fixture[-1] = (error, r.NEG)
            state = p.oracle(error, fixture)
            self.assertEqual(state['registers'][0], 0)
            self.assertEqual(state['registers'][2], error)
            self.assertEqual(state['flags'], 0x444)
            fixture[0] = (10000, 1)
            self.assertEqual(p.oracle(error, fixture)['registers'][0], r.NEG)

    def test_stack_and_nonvolatile_state(self):
        for error, temporary in ((19, 13), (188, 14), (0, 14), (10000, None)):
            regs, stack, _ = p.init.inputs(3)
            state = p.oracle(error, table(), 3)
            for index in (1, 3, 4, 5, 6):
                self.assertEqual(state['registers'][index], regs[index])
            self.assertEqual(struct.unpack_from('<I', state['stack'], r.SP-r.STACK-4)[0], regs[6])
            if temporary is not None:
                self.assertEqual(struct.unpack_from('<I', state['stack'], r.SP-r.STACK-8)[0], temporary)
            self.assertEqual(state['stack'][:r.SP-r.STACK-8], bytes(stack[:r.SP-r.STACK-8]))

    def test_flags_arithmetic_independent_examples(self):
        # 0 - 17 has low byte EF (seven set bits): PF must be clear.
        self.assertEqual(p.arithmetic_flags(0, 17, subtract=True), 0x491)
        authored = p.exercise(b'\xb8\x00\x00\x00\x00\x83\xe8\x11\xc3', 0, table())
        self.assertEqual(authored['flags'], 0x491)
        self.assertEqual(p.arithmetic_flags(17, 17, subtract=True), 0x444)
        self.assertEqual(p.arithmetic_flags(0, 8), 0x400)
        self.assertEqual(p.arithmetic_flags(14, 8), 0x410)
        self.assertEqual(p.arithmetic_flags(0x7FFFFFFF, 1), 0xC94)

    def test_authored_runner_cdecl_and_read_only_table(self):
        # Authored absolute table read / RET, not recovered mapper instructions.
        code = b'\xa1'+struct.pack('<I', p.TABLE+4)+b'\xc3'
        state = p.exercise(code, 0, table())
        self.assertEqual(state['registers'][0], 0x80000000)
        self.assertEqual(state['registers'][7], r.SP+4)
        for target in (p.TABLE, p.ENTRY+128):
            with self.assertRaises(ValueError):
                p.exercise(b'\xa3'+struct.pack('<I', target)+b'\xc3', 0, table())
        with self.assertRaises(ValueError):
            r.verify(p.exercise(b'\xc2\x04\x00', 0, table()), p.oracle(0, table()))

    def test_budget_decode_and_input_controls(self):
        for code in (b'\xeb\xfe', b'\xc2', b''):
            with self.assertRaises(ValueError):
                p.exercise(code, 0, table())
        for error, fixture in ((-1, table()), (r.NEG+1, table()), (0, []),
                                (0, [(1, -1)]*p.COUNT)):
            with self.assertRaises(ValueError):
                p.oracle(error, fixture)

    def test_every_state_component_compared(self):
        state = p.oracle(19, table())
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'registers':
                wrong[key][1] ^= 1
            elif key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)

    def test_pin_failure_sanitized_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'
            image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__':
    unittest.main()
