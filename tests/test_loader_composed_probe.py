"""Authored composition runner/oracle controls; no private image required."""
import contextlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import loader_composed_probe as c
p, r = c.p, c.p.resolver


class ComposedProbeTests(unittest.TestCase):
    def test_vectors_cover_all_paths_and_bound(self):
        cases = list(c.vectors())
        self.assertEqual(len(cases), 9 * 2 * 3 * 2 + 2)
        kinds = {tuple(e[0] for e in c.expected_for(v)['events']) for v in cases}
        self.assertEqual(kinds, {('load',), ('load', 'error'),
                                ('load', 'error', 'compare'),
                                ('load', 'error', 'compare', 'load')})
        # Difference only after seventh unit must not cause a retry.
        right = tuple(range(1, 9))
        same_prefix = (right[:7] + (999,), right, 0, 87, 1)
        self.assertEqual(c.expected_for(same_prefix)['eax'], 0)
        self.assertEqual(c.expected_for(((0,), (0,), 0, 87, 1))['eax'], 0)
        self.assertEqual(c.expected_for(((0xFFFF,), (1,), 0, 87, 1))['eax'], 1)

    def fixture(self):
        # Authored caller, and an authored comparator that reads/subtracts one
        # unsigned unit. It must actually execute: no injected comparison value.
        code = b'\x6a\x07\x68' + struct.pack('<I', p.PREFIX)
        code += b'\x68' + struct.pack('<I', r.NAME)
        code += b'\xb8' + struct.pack('<I', p.COMPARE) + b'\xff\xd0'
        ret = p.ENTRY_RVA + len(code)
        code += b'\x83\xc4\x0c\xc3'
        comparator = bytes.fromhex('8b4424040fb7008b5424080fb71229d0c3')
        expected = {'events': [('compare', [r.NAME, p.PREFIX, 7], ret, r.SP - 16)],
                    'eax': 0xFFFE, 'esp': r.SP + 4}
        return code, comparator, expected

    def test_actual_comparator_and_cdecl_return(self):
        code, comparator, expected = self.fixture()
        p.exercise(code, (0, 0, 123, 0), expected,
                   comparator=comparator, operands=((0xFFFF,), (1,)))
        for bad in (b'\x31\xc0\xc3', comparator[:-1] + b'\xc2\x0c\x00',
                    b'\x43' + comparator,
                    bytes.fromhex('8b44240466c7000000') + comparator):
            with self.subTest(bad=bad), self.assertRaises((ValueError, p.UcError)):
                p.exercise(code, (0, 0, expected['eax'], 0), expected,
                           comparator=bad, operands=((0xFFFF,), (1,)))

    def test_native_transport_is_exact_and_bounded(self):
        case = ((65,), (66,), 0, 87, 0xFFFFFFFE)
        expected = c.expected_for(case)
        calls = [e for e in expected['events'] if e[0] != 'compare']
        words = [expected['eax'], len(calls)]
        for kind, args, _, _ in calls:
            words += [{'load': 1, 'error': 2}[kind], *(args or [0, 0, 0])]
        good = ' '.join(map(str, words)) + '\n'
        with patch.object(c.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 0, good, '')) as run:
            c.compare_native('/authored/probe', [case])
            self.assertEqual(run.call_args.kwargs['input'],
                             '0 87 4294967294 1 1 65 66\n')
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
        for out, err, code in ((good + good, '', 0), ('', '', 0),
                               ('malformed\n', '', 0), (good, 'error', 0),
                               (good, '', 2), (good.replace('4294967294', '0'), '', 0)):
            with self.subTest(out=out, err=err, code=code):
                with patch.object(c.subprocess, 'run', return_value=
                                  subprocess.CompletedProcess([], code, out, err)):
                    with self.assertRaises(ValueError):
                        c.compare_native('/authored/probe', [case])

    def test_cli_pin_failure_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / 'private.bin'
            image.write_bytes(b'private fixture contents')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn('fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture contents')


if __name__ == '__main__':
    unittest.main()
