"""Authored policy and x86 runner fixtures; no private game input needed."""
import contextlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import loader_policy_probe as probe

r = probe.resolver


class LoaderPolicyProbeTests(unittest.TestCase):
    def test_success_keeps_pointer_and_avoids_error_query(self):
        for value in (1, 0x80000000, 0xFFFFFFFE):
            result = probe.oracle(value, 87, 1, 0)
            self.assertEqual(result['eax'], value)
            self.assertEqual(result['events'], [
                ('load', [r.NAME, 0, 0x800], 0x82A2C5, r.SP - 20)])

    def test_only_error87_compares_and_only_nonzero_comparison_retries(self):
        for error in (0, 5, 87, r.NEG):
            for comparison in (0, 1, r.NEG):
                result = probe.oracle(0, error, comparison, 0x80000000)
                kinds = [e[0] for e in result['events']]
                expected = ['load', 'error']
                if error == 87:
                    expected.append('compare')
                    self.assertEqual(result['events'][2][1], [r.NAME, probe.PREFIX, 7])
                    if comparison:
                        expected.append('load')
                        self.assertEqual(result['events'][-1][1], [r.NAME, 0, 0])
                self.assertEqual(kinds, expected)
                retry = error == 87 and comparison != 0
                self.assertEqual(result['eax'], 0x80000000 if retry else 0)

    def test_retry_failure_stays_zero_and_wrong_models_reject(self):
        expected = probe.oracle(0, 87, r.NEG, 0)
        self.assertEqual(expected['eax'], 0)
        for observed in (
                {**expected, 'eax': r.NEG},
                {**expected, 'events': expected['events'][:-1]},
                {**expected, 'events': expected['events'] + expected['events'][-1:]},
                {**expected, 'esp': r.SP + 8}):
            with self.assertRaises(ValueError):
                r.verify(observed, expected)
        with self.assertRaises(ValueError):
            probe.oracle(0, 87, -1, 0)

    def fixture(self, suffix=b'\xc3'):
        # Authored immediate return, unrelated to original helper implementation.
        return (b'\xb8' + struct.pack('<I', 0x80000000) + suffix,
                {'events': [], 'eax': 0x80000000, 'esp': r.SP + 4})

    def test_authored_runner_return(self):
        code, expected = self.fixture()
        probe.exercise(code, (0, 0, 0, 0), expected)

    def test_authored_runner_dependency_stdcall_cleanup(self):
        # Authored direct trap invocation, with its own return RVA and call ESP.
        code = b'\x68' + struct.pack('<I', 0x800) + b'\x6a\x00'
        code += b'\x68' + struct.pack('<I', r.NAME)
        code += b'\xb8' + struct.pack('<I', probe.LOAD) + b'\xff\xd0'
        return_rva = probe.ENTRY_RVA + len(code)
        code += b'\xc3'
        expected = {'events': [('load', [r.NAME, 0, 0x800], return_rva, r.SP - 16)],
                    'eax': 0x80000000, 'esp': r.SP + 4}
        probe.exercise(code, (0x80000000, 0, 0, 0), expected)

    def test_authored_comparator_requires_caller_cleanup(self):
        code = b'\x6a\x07' + b'\x68' + struct.pack('<I', probe.PREFIX)
        code += b'\x68' + struct.pack('<I', r.NAME)
        code += b'\xb8' + struct.pack('<I', probe.COMPARE) + b'\xff\xd0'
        return_rva = probe.ENTRY_RVA + len(code)
        expected = {'events': [('compare', [r.NAME, probe.PREFIX, 7],
                                return_rva, r.SP - 16)],
                    'eax': r.NEG, 'esp': r.SP + 4}
        probe.exercise(code + b'\x83\xc4\x0c\xc3', (0, 0, r.NEG, 0), expected)
        with self.assertRaises((ValueError, probe.UcError)):
            probe.exercise(code + b'\xc3', (0, 0, r.NEG, 0), expected)

    def test_runner_rejects_saved_register_stack_iat_and_loop_mutations(self):
        for suffix in (b'\x43\xc3', b'\xc2\x04\x00',
                       b'\xff\x05' + struct.pack('<I', probe.IAT) + b'\xc3',
                       b'\xff\x44\x24\x04\xc3', b'\xeb\xfe'):
            code, expected = self.fixture(suffix)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                probe.exercise(code, (0, 0, 0, 0), expected)

    def test_cli_pin_failure_sanitized_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'private.bin'
            image.write_bytes(b'private fixture contents')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(probe.main(), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture contents')


if __name__ == '__main__':
    unittest.main()
