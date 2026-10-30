"""Public synthetic tables only; missing native binaries fail, never skip."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import check_os_error_policy as c


class OsErrorPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = os.environ.get('TS2_GUEST_OS_ERROR_PROBE',
                                   'build/host/ts2_guest_os_error_probe')
        cls.runner = os.environ.get('TS2_GUEST_OS_ERROR_RUNNER')

    def test_all_slots_boundaries_duplicates_and_unsigned_values(self):
        sweep = c.cases()
        values = c.run(sweep, self.native, self.runner)
        self.assertEqual(c.verify(values, sweep), len(sweep))
        self.assertGreater(len(sweep), 700)

    def test_every_result_and_count_required(self):
        sweep = c.cases()
        values = [c.p.oracle(*case)['registers'][0] for case in sweep]
        for i in range(len(values)):
            with self.assertRaises(ValueError):
                c.verify([values[i] ^ 1], [sweep[i]])
        for bad in (values[:-1], values+[0]):
            with self.assertRaises(ValueError): c.verify(bad, sweep)

    def test_strict_transport(self):
        self.assertEqual(c.parse('0 0\n1 4294967295\n', 2), [0, c.r.NEG])
        for text in ('', '0 0\n', '0 0\n0 1\n', '1 0\n0 1\n',
                     '0 0\n1 4294967296\n', '0 0\n1 -1\n', '0 0\n1 １\n',
                     '0 0\n1 1 extra\n', '0 0\n1 1\n2 2\n'):
            with self.subTest(text=text), self.assertRaises(ValueError): c.parse(text, 2)

    def test_native_rejects_malformed_requests(self):
        command = ([self.runner] if self.runner else [])+[str(Path(self.native).resolve())]
        good = c.request(c.cases()[0])
        for text in ('', '0\n', good.rstrip()+' 1\n', good.replace('0 ', '-1 ', 1),
                     good.replace('0 ', '4294967296 ', 1), good.replace('0 ', '+0 ', 1)):
            done = subprocess.run(command, input=text, capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 2)
            self.assertEqual(done.stdout, '')

    def test_failed_child_cannot_pass(self):
        for done in (subprocess.CompletedProcess([], 2, '0 22\n', ''),
                     subprocess.CompletedProcess([], 0, '0 22\n', 'warning'),
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
