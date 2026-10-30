"""Public loading integration output has a fixed, independently specified oracle.

Run after the native build (scripts/test-host.sh does so). Override the binary
with TS2_GUEST_LOADING_SMOKE; TS2_GUEST_LOADING_RUNNER may select arm64-run.sh.
Missing artifacts/runners are failures, never skips or synthetic success.
"""
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GuestLoadingSmokeTests(unittest.TestCase):
    def test_loading_results_and_cache_effects(self):
        suffix = '.exe' if os.name == 'nt' else ''
        binary = os.environ.get('TS2_GUEST_LOADING_SMOKE',
                                str(ROOT / 'build/host' / ('ts2_guest_loading_smoke' + suffix)))
        runner = os.environ.get('TS2_GUEST_LOADING_RUNNER')
        command = ([runner] if runner else []) + [binary]
        result = subprocess.run(command, capture_output=True, timeout=75, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        self.assertEqual(result.stdout.decode().splitlines(), [
            'scenario=0 result=e7654321 caches=e7654321,f1234567,0 events=4',
            'scenario=1 result=e7654321 caches=e7654321,ffffffff,f1234567 events=5',
            'scenario=2 result=0 caches=ffffffff,f1234567,0 events=4',
            'synthetic-loading: mapping guards policies cache isolation passed',
        ])


if __name__ == '__main__':
    unittest.main()
