import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import resolver_composed_probe as c


class ResolverNativeTests(unittest.TestCase):
    def test_transport_exact_and_bounded(self):
        cases = list(c.vectors())[::100]
        good = '\n'.join(' '.join(map(str, c.native_words(case))) for case in cases) + '\n'
        with patch.object(c.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, good, '')) as run:
            c.compare_native('unused', cases)
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
            self.assertEqual(len(run.call_args.kwargs['input'].splitlines()), len(cases))
        for result in (subprocess.CompletedProcess([], 1, good, ''),
                       subprocess.CompletedProcess([], 0, good, 'error'),
                       subprocess.CompletedProcess([], 0, good + '1\n', ''),
                       subprocess.CompletedProcess([], 0, '\n'.join(good.splitlines()[:-1]), ''),
                       subprocess.CompletedProcess([], 0, good.replace(' ', ' 999 ', 1), ''),
                       subprocess.CompletedProcess([], 0, 'not-an-integer\n', '')):
            with patch.object(c.subprocess, 'run', return_value=result):
                with self.assertRaises(ValueError):
                    c.compare_native('unused', cases)

    def test_export_failure_stops_and_failed_load_advances(self):
        prefix = c.PREFIX
        case = ((0, 0), ((c.r.H1, 5, 0), (c.r.H2, 5, 0)), 0,
                (prefix, prefix, prefix))
        words = c.native_words(case)
        self.assertEqual(words[:6], [0, c.r.NEG, c.r.H1, 0, 0, 2])
        case = ((0, 0), ((0, 5, 0), (c.r.H2, 5, 0)), c.r.H1,
                (prefix, prefix, prefix))
        self.assertEqual(c.native_words(case)[:6], [c.r.H1, c.r.H1, c.r.NEG, c.r.H2, c.r.H1, 4])


if __name__ == '__main__':
    unittest.main()
