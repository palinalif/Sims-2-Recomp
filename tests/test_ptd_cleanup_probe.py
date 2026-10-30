"""Authored boundary controls; no original image is opened."""
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
import ptd_cleanup_probe as p
r = p.r


class CleanupProbeTests(unittest.TestCase):
    def test_sentinel_skips_free_and_preserves_stack(self):
        state = p.oracle(r.NEG, 0)
        regs, stack, data = p.inputs(r.NEG, 0)
        self.assertEqual(state['events'], [])
        self.assertEqual(state['stack'], bytes(stack))
        self.assertEqual(state['data'], bytes(data))
        self.assertEqual(state['registers'][0], 0xFFFFFF01)
        self.assertEqual(state['registers'][2], regs[2])

    def test_zero_valid_full_result_high_bits_and_post_call_reset(self):
        for index in (0, 1, 0x80000000):
            for result in (0, 1, 0x80000000, r.NEG):
                state = p.oracle(index, result)
                self.assertEqual(state['events'], [('free', [index], 0x828C26, r.SP - 8, index)])
                self.assertEqual(struct.unpack_from('<I', state['data'], p.SLOT - p.PAGE)[0], r.NEG)
                self.assertEqual(state['registers'][0], (result & 0xFFFFFF00) | 1)
                self.assertEqual(state['registers'][2], index)
                self.assertEqual(state['registers'][7], r.SP + 4)

    def test_oracle_rejects_state_and_order_mutations(self):
        baseline = p.oracle(0, r.NEG)
        for key in baseline:
            wrong = copy.deepcopy(baseline)
            if key in ('data', 'stack'):
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            elif key == 'events':
                wrong[key][0] = ('free', [0], 0x828C26, r.SP - 8, r.NEG)
            elif key == 'registers':
                wrong[key][0] = 1
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, baseline)
        with self.assertRaises(ValueError):
            p.oracle(-1, 0)

    def test_authored_cdecl_free_and_injected_interference(self):
        # Authored push/call/add/ret fixture, not original bytes.
        code = b'\x6a\x00\xb8' + struct.pack('<I', p.FREE) + b'\xff\xd0\x83\xc4\x04\xc3'
        state = p.exercise(code, 0, 0x80000000, interference=0xFEDCBA98)
        self.assertEqual(state['events'][0][1], [0])
        self.assertEqual(state['registers'][0], 0x80000000)
        self.assertEqual(state['registers'][7], r.SP + 4)
        self.assertEqual(struct.unpack_from('<I', state['data'], p.SLOT - p.PAGE)[0], 0xFEDCBA98)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 0, 0, pop=4)

    def test_runner_saved_state_immutable_pages_and_budget(self):
        baseline = p.exercise(b'\xc3', 0, 0)
        for code in (b'\x43\xc3', b'\xc2\x04\x00'):
            with self.assertRaises(ValueError):
                r.verify(p.exercise(code, 0, 0), baseline)
        for code in (b'\xeb\xfe', b'\xa3' + struct.pack('<I', r.RETURN + 16) + b'\xc3'):
            with self.assertRaises(ValueError):
                p.exercise(code, 0, 0)

    def test_cli_pin_failure_sanitized_and_readonly(self):
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
