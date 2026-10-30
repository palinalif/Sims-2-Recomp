"""Authored fixtures only: no original image is needed by the host suite."""
from pathlib import Path
import contextlib
import io
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import resolver_probe as probe


class ResolverProbeTests(unittest.TestCase):
    def test_export_failure_does_not_try_next_module(self):
        result, selected = probe.oracle((probe.H1, probe.H2), (0, 0), 0, (11, 22))
        self.assertEqual(selected, 0)
        self.assertEqual(result['events'], [
            ('export', [probe.H1, probe.NAME], 0x82A2A5, probe.SP - 36)])
        self.assertEqual(result['eax'], 0)
        self.assertEqual(result['cache'], probe.NEG)
        with self.assertRaises(ValueError):
            probe.verify({**result, 'cache': 0}, result)
        with self.assertRaises(ValueError):
            probe.verify({**result, 'events': result['events'] * 2}, result)

    def test_negative_module_skips_zero_load_failure_caches(self):
        result, selected = probe.oracle((probe.NEG, 0), (probe.H1, 0), 99, (11, 22))
        self.assertIsNone(selected)
        self.assertEqual(result['modules'], [probe.NEG, probe.NEG])
        self.assertEqual(result['events'], [('load', [22], 0x82A263, probe.SP - 32)])
        self.assertEqual(result['eax'], 0)

    def test_first_load_failure_advances_full_export_retained(self):
        result, selected = probe.oracle((0, 0), (0, probe.H2), 0x80000000, (11, 22))
        self.assertEqual(selected, 1)
        self.assertEqual([e[0] for e in result['events']], ['load', 'load', 'export'])
        self.assertEqual(result['modules'], [probe.NEG, probe.H2])
        self.assertEqual(result['eax'], 0x80000000)
        self.assertEqual(result['cache'], 0x80000000)
        with self.assertRaises(ValueError):
            probe.verify({**result, 'eax': 1}, result)

    def test_oracle_validates_shape_and_uint32(self):
        for modules, loads, export, names in [((0,), (0, 0), 0, (1, 2)),
                ((0, 0), (0, 0), -1, (1, 2)),
                ((0, 0), (0, 0), 0, (1, 0x100000000))]:
            with self.assertRaises(ValueError):
                probe.oracle(modules, loads, export, names)

    def fixture(self, suffix=b'\xc3'):
        # Authored mov eax, immediate; mov [absolute cache], eax; ret.
        # Not a transcription of the original resolver or a reference to it.
        code = b'\xb8' + struct.pack('<I', 0x80000000)
        code += b'\xa3' + struct.pack('<I', probe.CACHE) + suffix
        expected = {'events': [], 'eax': 0x80000000, 'cache': 0x80000000,
                    'modules': [probe.H1, probe.H2], 'esp': probe.SP + 4}
        return code, expected

    def test_runner_authored_return_and_same_memory_reentry(self):
        code, expected = self.fixture()
        probe.exercise(code, bytes(4096), (probe.H1, probe.H2), (0, 0), 0, 1, expected)

    def test_runner_rejects_register_stack_memory_and_budget_mutations(self):
        # inc ebx; ret / ret 4 / inc dword [cache+4]; ret / infinite loop.
        for suffix in (b'\x43\xc3', b'\xc2\x04\x00',
                       b'\xff\x05' + struct.pack('<I', probe.CACHE + 4) + b'\xc3',
                       b'\xeb\xfe'):
            code, expected = self.fixture(suffix)
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                probe.exercise(code, bytes(4096), (probe.H1, probe.H2), (0, 0), 0, 0, expected)

    def test_cli_fails_closed_without_echoing_private_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'image.bin'
            image.write_bytes(b'private malformed contents')
            before = image.read_bytes()
            out, err = io.StringIO(), io.StringIO()
            with patch.object(probe, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(probe.main(), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('contents', err.getvalue())
            self.assertEqual(image.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
