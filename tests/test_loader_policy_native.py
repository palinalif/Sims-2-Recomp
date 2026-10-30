"""Authored transport controls; actual native/x86 comparison is a separate probe."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import loader_policy_probe as policy


class NativePolicyTransportTests(unittest.TestCase):
    def test_ordered_high_bit_result_and_arguments(self):
        values = (0, 87, 0xffffffff, 0x80000000)
        expected = policy.oracle(*values)
        words = [expected['eax'], 4]
        for kind, args, _, _ in expected['events']:
            words.extend([{'load': 1, 'error': 2, 'compare': 3}[kind],
                          *(args or [0, 0, 0])])
        good = ' '.join(map(str, words)) + '\n'
        with patch.object(policy.subprocess, 'run', return_value=
                          subprocess.CompletedProcess([], 0, good, '')) as run:
            policy.compare_native('/authored/probe', [values])
            self.assertEqual(run.call_args.kwargs['input'],
                             f'{policy.resolver.NAME} 0 87 4294967295 2147483648\n')
            self.assertEqual(run.call_args.kwargs['timeout'], 30)
        for stdout, stderr, code in ((good + good, '', 0), ('', '', 0),
                                     (good, 'failure', 0), (good, '', 2),
                                     (good.replace('2147483648', '0'), '', 0),
                                     ('malformed\n', '', 0)):
            with self.subTest(stdout=stdout, stderr=stderr, code=code):
                with patch.object(policy.subprocess, 'run', return_value=
                                  subprocess.CompletedProcess([], code, stdout, stderr)):
                    with self.assertRaises(ValueError):
                        policy.compare_native('/authored/probe', [values])


if __name__ == '__main__':
    unittest.main()
