"""Public authored controls; never open the original image."""
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
import ptd_alloc_probe as p
r = p.r


class AllocProbeTests(unittest.TestCase):
    def test_fallback_uses_original_return_and_no_callback(self):
        state = p.oracle(0, r.NEG)
        self.assertEqual([e[0] for e in state['events']], ['resolve', 'tls'])
        self.assertEqual(state['events'][0][1], [0, p.NAME, p.BEGIN, p.END])
        self.assertEqual(state['events'][1][1:4], ([], r.RETURN - r.BASE, r.SP))
        self.assertEqual(state['registers'][0], r.NEG)
        self.assertEqual(state['registers'][7], r.SP + 4)

    def test_dynamic_guard_receiver_callback_and_full_result(self):
        for result in (0, 1, 0x80000000, r.NEG):
            state = p.oracle(p.FLS, result)
            self.assertEqual([e[0] for e in state['events']], ['resolve', 'guard', 'fls'])
            self.assertEqual(state['events'][1][4], p.FLS)
            self.assertEqual(state['events'][2][1], [0x87654321])
            self.assertEqual(state['registers'][0], result)
            self.assertEqual(state['registers'][2], p.FLS)
            original, _, _ = p.init.inputs(0)
            for index in (1, 3, 4, 5, 6):
                self.assertEqual(state['registers'][index], original[index])

    def test_oracle_divergences_reject(self):
        baseline = p.oracle(p.FLS, 0x80000000)
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
            p.oracle(123, 0)

    def test_runner_preservation_stack_and_budget(self):
        baseline = p.exercise(b'\xc3', 0, 0)
        self.assertEqual(baseline['registers'][7], r.SP + 4)
        for code in (b'\x43\xc3', b'\xc2\x04\x00'):
            with self.assertRaises(ValueError):
                r.verify(p.exercise(code, 0, 0), baseline)
        with self.assertRaises(ValueError):
            p.exercise(b'\xeb\xfe', 0, 0)

    def test_authored_stdcall_provider_and_tail_return(self):
        # Authored push immediate / register call / ret, not original bytes.
        code = b'\x68' + struct.pack('<I', 0x87654321)
        code += b'\xb8' + struct.pack('<I', p.FLS) + b'\xff\xd0\xc3'
        state = p.exercise(code, p.FLS, r.NEG)
        self.assertEqual(state['registers'][0], r.NEG)
        self.assertEqual(state['registers'][7], r.SP + 4)
        self.assertEqual(state['events'][0][1], [0x87654321])
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, p.FLS, r.NEG, fls_pop=0)
        # Authored register tail jump reaches TLS with the caller's return word.
        tail = b'\xb8' + struct.pack('<I', p.TLS) + b'\xff\xe0'
        state = p.exercise(tail, 0, 0x80000000)
        self.assertEqual(state['events'][0][1:4], ([], r.RETURN - r.BASE, r.SP))
        self.assertEqual(state['registers'][7], r.SP + 4)

    def test_authored_resolver_cdecl_and_immutable_pages(self):
        # Four authored arguments, register call, explicit caller cleanup.
        code = b''.join(b'\x68' + struct.pack('<I', value) for value in (4, 3, 2, 1))
        code += b'\xb8' + struct.pack('<I', p.RESOLVE) + b'\xff\xd0\x83\xc4\x10\xc3'
        state = p.exercise(code, p.FLS, 0)
        self.assertEqual(state['events'][0][1], [1, 2, 3, 4])
        self.assertEqual(state['registers'][7], r.SP + 4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, p.FLS, 0, resolver_pop=16)
        # An authored write to a mapped non-stack page must not pass silently.
        store = b'\xa3' + struct.pack('<I', r.TRAPS + 64) + b'\xc3'
        with self.assertRaises(ValueError):
            p.exercise(store, 0, 0)

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
