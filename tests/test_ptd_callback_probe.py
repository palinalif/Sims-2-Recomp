"""Authored controls; do not open original game inputs."""
import contextlib
import copy
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import ptd_callback_probe as p
r = p.r


class CallbackProbeTests(unittest.TestCase):
    def test_only_null_and_exact_static_context_are_exempt(self):
        for context in (0, p.STATIC, p.STATIC-1, p.STATIC+1, 1, 0x80000000, r.NEG):
            state = p.oracle(context, 0xABCDEF80)
            self.assertEqual(len(state['events']), int(context not in (0, p.STATIC)))
            self.assertEqual(state['registers'][7], r.SP+8)
            self.assertEqual(struct.unpack_from('<I', state['stack'], r.SP-r.STACK+4)[0], context)
            if state['events']:
                self.assertEqual(state['events'][0][1], [context])
                self.assertEqual(state['registers'][0], 0xABCDEF80)
            else:
                self.assertEqual(state['registers'][0], context)

    def test_volatile_free_effects_and_saved_registers(self):
        state = p.oracle(1, r.NEG, clobber=True)
        original, _ = p.inputs(1, 0)
        self.assertEqual(state['registers'][2:4], [1, 0xDEADBEEF])
        self.assertEqual(state['flags'], 0xC95)
        for index in (1, 4, 5, 6):
            self.assertEqual(state['registers'][index], original[index])
        self.assertEqual(p.cmp_flags(p.STATIC, p.STATIC), 0x444)
        self.assertEqual(p.cmp_flags(0, 1), 0x495)
        self.assertEqual(p.cmp_flags(0x80000000, 1), 0xC14)

    def test_wrong_states_reject(self):
        baseline = p.oracle(1, 0)
        for key in baseline:
            wrong = copy.deepcopy(baseline)
            if key == 'events':
                wrong[key] = []
            elif key == 'registers':
                wrong[key][7] -= 4
            elif key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            else:
                wrong[key] ^= 16
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, baseline)
        for context in (-1, r.NEG+1):
            with self.assertRaises(ValueError):
                p.inputs(context, 0)

    def test_authored_callback_cleanup_budget_and_immutable_code(self):
        baseline = p.exercise(b'\xc2\x04\x00', 1, 0)
        self.assertEqual(baseline['registers'][7], r.SP+8)
        with self.assertRaises(ValueError):
            r.verify(p.exercise(b'\xc3', 1, 0), baseline)
        with self.assertRaises(ValueError):
            p.exercise(b'\xeb\xfe', 1, 0)
        # Never let zero-filled executable padding supply a missing RET operand.
        with self.assertRaises(ValueError):
            p.exercise(b'\xc2', 1, 0)
        store = b'\xa3' + struct.pack('<I', p.ENTRY+64) + b'\xc2\x04\x00'
        with self.assertRaises(ValueError):
            p.exercise(store, 1, 0)

    def test_authored_free_is_cdecl_with_caller_owned_argument(self):
        # An unrelated synthetic immediate-argument call with explicit ADD cleanup.
        code = b'\x6a\x07\xb8' + struct.pack('<I', p.FREE)
        code += b'\xff\xd0\x83\xc4\x04\xc2\x04\x00'
        state = p.exercise(code, 1, 0xFEDCBA98, clobber=True)
        self.assertEqual(state['events'][0][1], [7])
        self.assertEqual(state['registers'][0], 0xFEDCBA98)
        self.assertEqual(state['registers'][7], r.SP+8)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 1, 0, pop=4)

    def test_pin_failure_suppresses_private_details_and_preserves_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'secret.bin'
            image.write_bytes(b'private input')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private input', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private input')


if __name__ == '__main__':
    unittest.main()
