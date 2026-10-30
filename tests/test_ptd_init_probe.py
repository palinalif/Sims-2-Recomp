"""Authored controls only; never read the private image."""
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
import ptd_init_probe as p
r = p.r


class PtdProbeTests(unittest.TestCase):
    def test_index_zero_valid_and_failure_sentinel_stored(self):
        good = p.oracle(0, 1, 0)
        self.assertEqual([e[0] for e in good['events']], ['alloc', 'set'])
        self.assertEqual([e[4] for e in good['events']], [0x96969696, 0])
        bad = p.oracle(r.NEG, 1, 0)
        self.assertEqual([e[0] for e in bad['events']], ['alloc'])
        self.assertEqual(struct.unpack_from('<I', bad['data'], p.SLOT - p.PAGE)[0], r.NEG)
        self.assertEqual(bad['registers'][0], 0xFFFFFF00)

    def test_set_uses_full_result_and_returns_only_al(self):
        for result in (1, 0x80000000, 0xFFFFFF00):
            good = p.oracle(3, result, 0)
            self.assertEqual(len(good['events']), 2)
            self.assertEqual(good['registers'][0], (result & 0xFFFFFF00) | 1)
        bad = p.oracle(3, 0, 0x98765432)
        self.assertEqual([e[0] for e in bad['events']], ['alloc', 'set', 'cleanup'])
        self.assertEqual(bad['registers'][0], 0x98765400)
        # Cleanup wrapper is injected: no invented reset of the index word.
        self.assertEqual(struct.unpack_from('<I', bad['data'], p.SLOT - p.PAGE)[0], 3)

    def test_full_state_wrong_models_reject(self):
        baseline = p.oracle(0, 0x80000000, 0)
        for key in baseline:
            wrong = copy.deepcopy(baseline)
            if key in ('data', 'stack'):
                data = bytearray(wrong[key]); data[0] ^= 1; wrong[key] = bytes(data)
            elif key == 'events':
                wrong[key].reverse()
            elif key == 'registers':
                wrong[key][0] = 1
            else:
                wrong[key] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify(wrong, baseline)
        with self.assertRaises(ValueError):
            p.oracle(-1, 1, 0)

    def test_authored_runner_preservation_budget_and_stack(self):
        baseline = p.exercise(b'\xc3', 0, 0, 0)
        self.assertEqual(baseline['registers'][7], r.SP + 4)
        for code in (b'\x43\xc3', b'\xc2\x04\x00'):
            with self.assertRaises(ValueError):
                r.verify(p.exercise(code, 0, 0, 0), baseline)
        with self.assertRaises(ValueError):
            p.exercise(b'\xeb\xfe', 0, 0, 0)

    def test_authored_cdecl_provider_requires_caller_cleanup(self):
        # Authored push argument / register call / pop ECX / return.
        code = b'\x68' + struct.pack('<I', p.CALLBACK)
        code += b'\xb8' + struct.pack('<I', p.ALLOC) + b'\xff\xd0\x59\xc3'
        state = p.exercise(code, 0x80000000, 0, 0)
        self.assertEqual(state['events'], [('alloc', [p.CALLBACK], p.RVA + 12, r.SP - 8, 0x96969696)])
        self.assertEqual(state['registers'][0], 0x80000000)
        self.assertEqual(state['registers'][2], p.CALLBACK)
        self.assertEqual(state['registers'][7], r.SP + 4)
        with self.assertRaises((ValueError, p.UcError)):
            p.exercise(code, 0x80000000, 0, 0, pop=4)

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
