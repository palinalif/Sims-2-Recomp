"""Fail-closed contract tests for the Phase 1 acceptance entry point.

These tests do not assert game execution. The external validator has to verify that.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "phase1-acceptance.sh"


class Phase1AcceptanceGateTest(unittest.TestCase):
    def run_gate(self, value=None):
        env = os.environ.copy()
        env.pop("TS2_TRUSTED_PHASE1_VALIDATOR", None)
        if value is not None:
            env["TS2_TRUSTED_PHASE1_VALIDATOR"] = str(value)
        return subprocess.run(
            ["sh", str(GATE)], cwd=ROOT, env=env,
            capture_output=True, text=True, check=False,
        )

    def test_unconfigured_fails_closed(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 78)
        self.assertIn("BLOCKED", result.stderr)

    def test_relative_path_rejected(self):
        self.assertEqual(self.run_gate("relative/validator").returncode, 78)

    def test_missing_validator_rejected(self):
        self.assertEqual(self.run_gate("/does/not/exist/ts2-validator").returncode, 78)

    def test_repo_owned_file_rejected(self):
        self.assertEqual(self.run_gate(GATE).returncode, 78)

    def test_external_validator_exit_status_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="ts2-gate-test-") as td:
            validator = Path(td) / "validator.sh"
            validator.write_text("#!/bin/sh\nexit 43\n", encoding="utf-8")
            validator.chmod(0o700)
            result = self.run_gate(validator)
            self.assertEqual(result.returncode, 43)


if __name__ == "__main__":
    unittest.main()
