"""Synthetic tables only; missing native binaries fail, never skip."""
import contextlib
import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import check_os_error_abi as c


class OsErrorAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = os.environ.get('TS2_GUEST_OS_ERROR_ABI_PROBE',
                                   'build/host/ts2_guest_os_error_abi_probe')
        cls.runner = os.environ.get('TS2_GUEST_OS_ERROR_ABI_RUNNER')

    def test_full_integer_state_all_slots_intervals_duplicates(self):
        sweep = c.cases()
        self.assertEqual(c.verify(c.run(sweep, self.native, self.runner), sweep), len(sweep))
        self.assertGreater(len(sweep), 1400)

    def test_every_observed_component_mutation_rejects(self):
        # Exact match, first interval, second interval and default final frames.
        table = [(10000+n, n) for n in range(45)]
        for error in (10000, 19, 188, c.r.NEG):
            case = (error, table, 1)
            state = c.p.oracle(*case)
            for i in range(8):
                bad = copy.deepcopy(state); bad['registers'][i] ^= 1
                with self.assertRaises(ValueError): c.verify([bad], [case])
            for bit in (1, 4, 16, 64, 128, 1024, 2048):
                bad = copy.deepcopy(state); bad['flags'] ^= bit
                with self.assertRaises(ValueError): c.verify([bad], [case])
            for i in range(4096):
                bad = dict(state); stack = bytearray(state['stack']); stack[i] ^= 1
                bad['stack'] = bytes(stack)
                with self.assertRaises(ValueError): c.verify([bad], [case])
            for bad in ([], [state, state]):
                with self.assertRaises(ValueError): c.verify(bad, [case])

    def test_strict_response_transport(self):
        state = c.p.oracle(*c.cases()[0])
        words = [0, *state['registers'], state['flags'], *[0]*1024]
        good = ' '.join(map(str, words))+'\n'
        self.assertEqual(len(c.parse(good, 1)), 1)
        for text in ('', good+'\n', good+good, good.replace('0 ', '1 ', 1),
                     good.replace('0 ', '-1 ', 1), good.replace('0 ', '１ ', 1),
                     good.replace('0 ', '4294967296 ', 1), good.rstrip()+' extra\n',
                     ' '.join(good.split()[:-1])):
            with self.assertRaises(ValueError): c.parse(text, 1)

    def test_native_rejects_malformed_requests(self):
        command = ([self.runner] if self.runner else [])+[str(Path(self.native).resolve())]
        good = c.request(c.cases()[0])
        for text in ('', '0\n', good.rstrip()+' 1\n', '-1 '+good.split(' ', 1)[1],
                     '+0 '+good.split(' ', 1)[1], '4294967296 '+good.split(' ', 1)[1]):
            done = subprocess.run(command, input=text, capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 2)
            self.assertEqual(done.stdout, '')

    def test_failed_child_cannot_pass(self):
        for done in (subprocess.CompletedProcess([], 2, '', ''),
                     subprocess.CompletedProcess([], 0, '', 'warning'),
                     subprocess.CompletedProcess([], 0, '', '')):
            with patch.object(c.subprocess, 'run', return_value=done), self.assertRaises(ValueError):
                c.run([c.cases()[0]], self.native, self.runner)

    def test_private_wrong_pin_sanitized_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp)/'private.bin'; image.write_bytes(b'private fixture')
            out, err = io.StringIO(), io.StringIO()
            with patch.object(c.r, 'IMAGE', image), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(c.main(['--private-x86']), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertNotIn(str(image), err.getvalue())
            self.assertNotIn('private fixture', err.getvalue())
            self.assertEqual(image.read_bytes(), b'private fixture')


if __name__ == '__main__': unittest.main()
