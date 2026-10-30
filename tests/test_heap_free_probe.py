"""Authored controls only; never open original game inputs."""
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
import heap_free_probe as p
r = p.r


class HeapFreeProbeTests(unittest.TestCase):
    def test_no_wrapper_null_or_static_exemption(self):
        for context in (0, p.callback.STATIC, 1, 0x80000000, r.NEG):
            state = p.oracle(context, r.NEG)
            self.assertEqual(state['events'], [('provider', [context], 0x831A6C, r.SP-16, 0)])
            self.assertEqual(state['registers'][0], r.NEG)
            self.assertEqual(state['registers'][2], context)
            self.assertEqual(state['registers'][7], r.SP+4)
            self.assertEqual(struct.unpack_from('<I', state['stack'], r.SP-r.STACK-8)[0], 0)

    def test_volatile_effects_and_nonvolatile_preservation(self):
        original, _ = p.callback.inputs(1, 7)
        state = p.oracle(1, 0x80000000, 7, clobber=True)
        self.assertEqual(state['registers'][2:4], [1, 0xDEADBEEF])
        self.assertEqual(state['flags'], 0xC95)
        for index in (1, 4, 5, 6):
            self.assertEqual(state['registers'][index], original[index])

    def test_every_state_component_is_checked(self):
        baseline = p.oracle(1, 0)
        for key in baseline:
            wrong = copy.deepcopy(baseline)
            if key == 'events':
                wrong[key][0] = ('provider', [1], 0x831A6C, r.SP-16, 1)
            elif key == 'registers':
                wrong[key][2] = 0
            elif key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            else:
                wrong[key] ^= 16
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, baseline)
        for context in (-1, r.NEG+1):
            with self.assertRaises(ValueError):
                p.oracle(context, 0)

    def test_authored_cdecl_provider_and_full_eax_input_capture(self):
        # Unrelated immediate argument, no original wrapper fixture.
        code = b'\x6a\x07\xb8'+struct.pack('<I', p.PROVIDER)
        code += b'\xff\xd0\x83\xc4\x04\xc3'
        state = p.exercise(code, 1, r.NEG, clobber=True)
        self.assertEqual(state['events'][0][1], [7])
        self.assertEqual(state['events'][0][4], p.PROVIDER)
        self.assertEqual(state['registers'][0], r.NEG)
        self.assertEqual(state['registers'][7], r.SP+4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 1, 0, pop=4)

    def test_leave_can_hide_wrong_provider_cleanup_from_esp_check(self):
        # Synthetic framed caller: a zero local and immediate argument seven.
        code = b'\x55\x89\xe5\x6a\x00\x6a\x07\xb8'
        code += struct.pack('<I', p.PROVIDER)+b'\xff\xd0\x5a\xc9\xc3'
        correct = p.exercise(code, 1, 0)
        wrong = p.exercise(code, 1, 0, pop=4)
        self.assertEqual(correct['registers'][7], r.SP+4)
        self.assertEqual(wrong['registers'][7], r.SP+4)
        self.assertEqual(correct['registers'][3], 7)
        self.assertEqual(wrong['registers'][3], 0)
        with self.assertRaises(ValueError):
            r.verify(wrong, correct)

    def test_authored_return_budget_decode_and_immutable_pages(self):
        self.assertEqual(p.exercise(b'\xc3', 1, 0)['registers'][7], r.SP+4)
        for code in (b'\xeb\xfe', b'\xc2'):
            with self.assertRaises(ValueError):
                p.exercise(code, 1, 0)
        store = b'\xa3'+struct.pack('<I', p.ENTRY+64)+b'\xc3'
        with self.assertRaises(ValueError):
            p.exercise(store, 1, 0)

    def test_pin_failure_is_sanitized_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'
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
