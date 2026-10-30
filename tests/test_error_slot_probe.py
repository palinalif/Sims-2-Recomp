"""Authored controls only; never opens an original-code fixture."""
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
import error_slot_probe as p
r = p.r


class ErrorSlotProbeTests(unittest.TestCase):
    def test_null_returns_fallback_address_not_contents(self):
        state = p.oracle(0, clobber=True)
        self.assertEqual(state['registers'][0], p.FALLBACK)
        self.assertEqual(state['events'], [('provider', [], 0x831B1C, r.SP-4)])
        self.assertEqual(state['flags'], 0x444)

    def test_nonnull_offset_wrap_and_not_boolean(self):
        for pointer, expected in ((1, 17), (0x80000000, 0x80000010),
                                  (0xFFFFFFF0, 0), (r.NEG, 15)):
            state = p.oracle(pointer, 3, clobber=True)
            self.assertEqual(state['registers'][0], expected)
            self.assertEqual(state['registers'][2:4], [0xFEEDFACE, 0xDEADBEEF])
            before, _, _ = p.init.inputs(3)
            for index in (1, 4, 5, 6):
                self.assertEqual(state['registers'][index], before[index])
            self.assertEqual(state['registers'][7], r.SP+4)
        for pointer in (-1, r.NEG+1):
            with self.assertRaises(ValueError):
                p.oracle(pointer)

    def test_add_flags_independent_boundaries(self):
        self.assertEqual(p.add_flags(0x7FFFFFF0, 16), 0xC84)  # signed overflow
        self.assertEqual(p.add_flags(0xFFFFFFF0, 16), 0x445)  # carry/zero
        self.assertEqual(p.add_flags(r.NEG, 16), 0x405)  # low-byte parity
        self.assertEqual(p.add_flags(1, 16), 0x404)

    def test_authored_provider_cdecl_and_volatile_effects(self):
        # Authored CALL-provider/RET, not the recovered accessor body.
        code = b'\xb8'+struct.pack('<I', p.PROVIDER)+b'\xff\xd0\xc3'
        for clobber in (False, True):
            state = p.exercise(code, 0x80000000, clobber=clobber)
            self.assertEqual(state['registers'][0], 0x80000000)
            self.assertEqual(state['registers'][7], r.SP+4)
            self.assertEqual(state['events'], [('provider', [], p.RVA+7, r.SP-4)])
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 1, pop=4)

    def test_budget_decode_and_unmapped_address_controls(self):
        self.assertEqual(p.exercise(b'\xc3', 1)['registers'][7], r.SP+4)
        for code in (b'\xeb\xfe', b'\xc2'):
            with self.assertRaises(ValueError):
                p.exercise(code, 1)
        for target in (p.ENTRY+128, p.PROVIDER):
            with self.assertRaises(ValueError):
                p.exercise(b'\xa3'+struct.pack('<I', target)+b'\xc3', 1)
        with self.assertRaises(p.UcError):
            p.exercise(b'\xa1'+struct.pack('<I', p.FALLBACK)+b'\xc3', 0)

    def test_every_state_component_compared(self):
        state = p.oracle(1)
        for key in state:
            wrong = copy.deepcopy(state)
            if key == 'events':
                wrong[key] = []
            elif key == 'registers':
                wrong[key][1] ^= 1
            elif key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, state)

    def test_pin_failure_is_sanitized_and_read_only(self):
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
