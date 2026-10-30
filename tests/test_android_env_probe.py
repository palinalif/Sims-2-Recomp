"""Metadata-only fixtures; no substitute SDK tools are executed."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('android_env_probe', ROOT / 'tools/android_env_probe.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AndroidEnvProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='android inventory ')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sdk = self.root / 'sdk'
        self.java = self.root / 'jdk'
        self.gradle = self.root / 'gradle'

    def result(self):
        return MODULE.probe(self.sdk, self.java, self.gradle, self.root / 'no-kvm')

    def touch(self, path, content=''):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o700)

    def populate(self):
        # Files are inventory fixtures, not working tool implementations.
        for item in self.result()['checks'].values():
            if 'path' in item:
                self.touch(Path(item['path']))
        self.touch(self.sdk / 'ndk/27.2.12479018/source.properties', 'Pkg.Revision = 27.2.12479018\n')
        self.touch(self.java / 'release', 'JAVA_VERSION="25.0.1"\n')

    def test_absent_is_blocked_and_never_android_execution(self):
        result = self.result()
        self.assertFalse(result['prerequisites_present'])
        self.assertFalse(result['android_executed'])
        self.assertFalse(result['kvm_accessible'])

    def test_complete_inventory_is_not_runtime_evidence(self):
        self.populate()
        result = self.result()
        self.assertTrue(result['prerequisites_present'])
        self.assertEqual(result['checks']['jdk_17_plus']['observed_major'], 25)
        self.assertFalse(result['android_executed'])
        self.assertFalse(result['gradle_8_13_cached'])

    def test_wrong_ndk_revision_rejects(self):
        self.populate()
        self.touch(self.sdk / 'ndk/27.2.12479018/source.properties', 'Pkg.Revision = 28.0.0\n')
        self.assertFalse(self.result()['prerequisites_present'])

    def test_missing_or_nonexecutable_component_rejects(self):
        self.populate()
        for check in self.result()['checks'].values():
            if 'path' not in check:
                continue
            path = Path(check['path'])
            data = path.read_bytes()
            path.unlink()
            self.assertFalse(self.result()['prerequisites_present'], str(path))
            path.write_bytes(data)
            path.chmod(0o700)
        (self.java / 'bin/javac').chmod(0o600)
        self.assertFalse(self.result()['prerequisites_present'])

    def test_old_or_unparseable_jdk_rejects(self):
        self.populate()
        for text in ('JAVA_VERSION="11.0.2"', 'unrecognized'):
            self.touch(self.java / 'release', text)
            self.assertFalse(self.result()['prerequisites_present'])

    def test_cli_paths_with_spaces_and_exit_contract(self):
        command = [sys.executable, str(ROOT / 'tools/android_env_probe.py'),
                   '--sdk', str(self.sdk), '--java-home', str(self.java),
                   '--gradle-home', str(self.gradle)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 78, result.stderr)
        self.assertFalse(json.loads(result.stdout)['prerequisites_present'])
        self.populate()
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['prerequisites_present'])


if __name__ == '__main__':
    unittest.main()
