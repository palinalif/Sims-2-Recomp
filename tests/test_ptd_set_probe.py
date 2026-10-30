"""Authored ABI controls; no original image is opened."""
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
import ptd_set_probe as p
r = p.r


class SetProbeTests(unittest.TestCase):
    def test_both_paths_forward_exact_words_and_full_result(self):
        for target in (0, p.FLS):
            for result in (0, 1, 0x80000000, r.NEG):
                state = p.oracle(target, result, r.NEG, 0xFEDCBA98)
                self.assertEqual(state['events'][0][1], [3, p.NAME, p.BEGIN, p.END])
                self.assertEqual(state['events'][-1][1], [r.NEG, 0xFEDCBA98])
                self.assertEqual(state['registers'][0], result)
                self.assertEqual(state['registers'][7], r.SP + 4)
                original, _ = p.inputs(r.NEG, 0xFEDCBA98, 0)
                for n in (1, 3, 4, 5, 6):
                    self.assertEqual(state['registers'][n], original[n])
                self.assertEqual(struct.unpack_from('<II', state['stack'], r.SP - r.STACK + 4),
                                 (r.NEG, 0xFEDCBA98))

    def test_fallback_is_call_not_allocation_style_tail_jump(self):
        state = p.oracle(0, 1, 0, 0)
        self.assertEqual([e[0] for e in state['events']], ['resolve', 'tls'])
        self.assertEqual(state['events'][-1][2:4], (0x82A3E9, r.SP - 20))
        self.assertNotEqual(state['events'][-1][2], r.RETURN - r.BASE)
        dynamic = p.oracle(p.FLS, 1, 0, 0)
        self.assertEqual([e[0] for e in dynamic['events']], ['resolve', 'guard', 'fls'])
        self.assertEqual(dynamic['events'][1][4], p.FLS)
        self.assertEqual(dynamic['events'][-1][2:4], (0x82A3E1, r.SP - 20))

    def test_oracle_divergences_reject(self):
        baseline = p.oracle(p.FLS, 0x80000000, 0, 0)
        for key in baseline:
            wrong = copy.deepcopy(baseline)
            if key == 'stack':
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            elif key == 'events':
                wrong[key].reverse()
            elif key == 'registers':
                wrong[key][0] = 0
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, baseline)
        with self.assertRaises(ValueError):
            p.oracle(123, 0, 0, 0)
        with self.assertRaises(ValueError):
            p.inputs(-1, 0, 0)

    def test_authored_two_argument_providers_require_pop8(self):
        for target in (p.FLS, p.TLS):
            # Authored value/index pushes and register call, not original bytes.
            code = b'\x68' + struct.pack('<I', 0xFEDCBA98) + b'\x6a\x00'
            code += b'\xb8' + struct.pack('<I', target) + b'\xff\xd0\xc3'
            state = p.exercise(code, p.FLS, r.NEG, 0, 0)
            self.assertEqual(state['events'][0][1], [0, 0xFEDCBA98])
            self.assertEqual(state['registers'][0], r.NEG)
            self.assertEqual(state['registers'][7], r.SP + 4)
            with self.assertRaises((ValueError, p.UcError)):
                p.exercise(code, p.FLS, 1, 0, 0, provider_pop=0)

    def test_authored_resolver_requires_caller_cleanup(self):
        code = b''.join(b'\x68' + struct.pack('<I', v) for v in (4, 3, 2, 1))
        code += b'\xb8' + struct.pack('<I', p.RESOLVE) + b'\xff\xd0\x83\xc4\x10\xc3'
        state = p.exercise(code, p.FLS, 0, 0, 0)
        self.assertEqual(state['events'][0][1], [1, 2, 3, 4])
        self.assertEqual(state['registers'][7], r.SP + 4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, p.FLS, 0, 0, 0, resolver_pop=16)

    def test_runner_register_stack_immutable_pages_and_budget(self):
        baseline = p.exercise(b'\xc3', 0, 0, 0, 0)
        for code in (b'\x43\xc3', b'\xc2\x08\x00'):
            with self.assertRaises(ValueError):
                r.verify(p.exercise(code, 0, 0, 0, 0), baseline)
        for code in (b'\xeb\xfe', b'\xa3' + struct.pack('<I', r.TRAPS + 64) + b'\xc3'):
            with self.assertRaises(ValueError):
                p.exercise(code, 0, 0, 0, 0)

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
