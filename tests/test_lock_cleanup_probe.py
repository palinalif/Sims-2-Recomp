"""Authored boundary controls; never open the private game fixture."""
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
import lock_cleanup_probe as p

r = p.r


class CleanupProbeTests(unittest.TestCase):
    def test_reverse_stride_and_post_call_counter(self):
        expected = p.oracle(3, 0)
        self.assertEqual([e[0] for e in expected['events']],
                         [p.OBJECT + 48, p.OBJECT + 24, p.OBJECT])
        self.assertEqual([e[1] for e in expected['events']], [3, 2, 1])
        self.assertEqual(struct.unpack_from('<I', expected['data'], p.COUNTER - r.GLOBAL)[0], 0)
        self.assertEqual(expected['registers'][0], (p.response(2, 0) & 0xFFFFFF00) | 1)
        for n in (-1, 9, r.NEG):
            with self.assertRaises(ValueError):
                p.oracle(n, 0)

    def test_interference_does_not_change_loop_bound(self):
        expected = p.oracle(3, 1, True)
        self.assertEqual(len(expected['events']), 3)
        self.assertEqual([e[1] for e in expected['events']], [3, 0x7FFFFFFF, 0x80000000])
        self.assertEqual(struct.unpack_from('<I', expected['data'], p.COUNTER - r.GLOBAL)[0],
                         0x80000001)
        zero = p.oracle(0, 1, True)
        self.assertEqual(zero['events'], [])
        self.assertEqual(zero['registers'][0], (p.inputs(0, 1)[0][0] & 0xFFFFFF00) | 1)

    def test_wrong_models_reject(self):
        expected = p.oracle(3, 0)
        for key in expected:
            wrong = copy.deepcopy(expected)
            if key in ('stack', 'data'):
                changed = bytearray(wrong[key]); changed[0] ^= 1
                wrong[key] = bytes(changed)
            elif key == 'events':
                wrong[key].reverse()
            elif key == 'registers':
                wrong[key][0] = 1  # wrong zero-extended result
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, expected)

    def test_authored_runner_return_and_saved_state_controls(self):
        baseline = p.exercise(b'\xc3', 0)
        self.assertEqual(baseline['registers'][7], r.SP + 4)
        for suffix in (b'\x43\xc3', b'\xc2\x04\x00',
                       b'\xff\x44\x24\x04\xc3'):
            with self.assertRaises(ValueError):
                r.verify(p.exercise(suffix, 0), baseline)
        for code in (b'\xeb\xfe', b'\xff\x05' + struct.pack('<I', p.SLOT) + b'\xc3'):
            with self.assertRaises(ValueError):
                p.exercise(code, 0)

    def test_authored_provider_requires_stdcall_pop4(self):
        # Authored push immediate / register-indirect call, not original bytes.
        code = b'\x68' + struct.pack('<I', p.OBJECT)
        code += b'\xb8' + struct.pack('<I', p.PROVIDER) + b'\xff\xd0\xc3'
        observed = p.exercise(code, 1)
        self.assertEqual(observed['events'], [(p.OBJECT, 1, p.RVA + 12, r.SP - 8)])
        self.assertEqual(observed['registers'][7], r.SP + 4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 1, cleanup=0)

    def test_cli_pin_failure_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'secret-input.bin'
            image.write_bytes(b'private contents')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(p.main([]), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('private contents', err.getvalue())
            self.assertNotIn(str(image), err.getvalue())
            self.assertEqual(image.read_bytes(), b'private contents')


if __name__ == '__main__':
    unittest.main()
