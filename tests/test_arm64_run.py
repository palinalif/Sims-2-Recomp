"""Fail-closed runner checks; synthetic headers are never executed."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/campaign/arm64-run.sh"


class Arm64RunnerTests(unittest.TestCase):
    def invoke(self, *args):
        env = dict(os.environ, TS2_QEMU_AARCH64="/nonexistent/ts2-qemu-aarch64")
        return subprocess.run([str(RUNNER), *map(str, args)], env=env,
                              capture_output=True, text=True, timeout=5)

    def test_usage_and_missing_input_fail(self):
        self.assertEqual(self.invoke().returncode, 64)
        self.assertEqual(self.invoke("/nonexistent/ts2-elf").returncode, 66)

    def test_wrong_isa_class_endian_and_truncation_reject(self):
        valid = bytearray(20)
        valid[:7] = b"\x7fELF\x02\x01\x01"
        valid[18:20] = b"\xb7\x00"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "header"
            for offset, value in [(0, 0), (4, 1), (5, 2), (6, 0), (18, 62)]:
                damaged = valid.copy()
                damaged[offset] = value
                path.write_bytes(damaged)
                result = self.invoke(path)
                self.assertEqual(result.returncode, 65, result.stderr)
            path.write_bytes(valid[:19])
            self.assertNotEqual(self.invoke(path).returncode, 0)

    def test_missing_qemu_is_visible_failure_with_provisioning_command(self):
        header = bytearray(20)
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[18:20] = b"\xb7\x00"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "header"
            path.write_bytes(header)
            result = self.invoke(path)
            self.assertEqual(result.returncode, 78)
            self.assertIn("provision-qemu-aarch64.sh --verify", result.stderr)


if __name__ == "__main__":
    unittest.main()
