"""Transport rejection tests; real host/x86 comparison is a separate command."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import wide_compare_probe as probe


class NativeWideTransportTests(unittest.TestCase):
    def test_unsigned_exact_result_and_fail_closed_output(self):
        cases = [((0xffff,), (1,), 1, True), ((1,), (0xffff,), 1, False),
                 ((), (), 0, False)]
        good = '65534\n4294901762\n0\n'
        with patch.object(probe.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 0, good, '')) as run:
            probe.compare_native('/authored/probe', cases)
            self.assertEqual(run.call_args.kwargs['input'],
                             '1 1 1 1 65535 1\n1 1 1 0 1 65535\n0 0 0 0\n')
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
        for stdout, stderr, code in ((good + good, '', 0), ('', '', 0),
                                     (good, 'error', 0), (good, '', 2),
                                     ('1\n4294967295\n0\n', '', 0),
                                     ('malformed\n', '', 0)):
            with self.subTest(stdout=stdout, stderr=stderr, code=code):
                with patch.object(probe.subprocess, 'run', return_value=
                                  subprocess.CompletedProcess([], code, stdout, stderr)):
                    with self.assertRaises(ValueError):
                        probe.compare_native('/authored/probe', cases)


if __name__ == '__main__':
    unittest.main()
