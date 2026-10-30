"""Authored metadata fixtures only; no SDK tool or license acceptance is simulated."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('sdk_install', Path(__file__).resolve().parents[1] / 'tools/install_android_sdk_package.py')
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


class SdkPackageInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'fixture.zip'
        self.destination = self.root / 'sdk with spaces'

    def fixture(self, package='platform', extras=(), revision=None, missing=False):
        pin = sdk.PACKAGES[package].copy()
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.writestr(str(Path(pin['root'])/'source.properties'), 'Pkg.Revision = '+(revision or pin['revision'])+'\n')
            if not missing:
                for name, executable in pin['required'].items():
                    info = zipfile.ZipInfo(str(Path(pin['root'])/name))
                    info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
                    z.writestr(info, 'authored metadata, NOT an SDK tool')
            for name, mode in extras:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                z.writestr(info, 'not a tool')
        data = self.archive.read_bytes()
        pin.update(size=len(data), sha1=hashlib.sha1(data).hexdigest(), sha256=hashlib.sha256(data).hexdigest())
        return patch.dict(sdk.PACKAGES, {package: pin})

    def test_all_packages_permissions_receipts_and_no_clobber(self):
        for package in sdk.PACKAGES:
            with self.subTest(package=package), self.fixture(package):
                dest = sdk.install(package, self.archive, self.destination)
                receipt = json.loads((dest/'ts2-install-receipt.json').read_text())
                self.assertFalse(receipt['licenses_accepted'])
                self.assertFalse(receipt['android_executed'])
                for name, executable in sdk.PACKAGES[package]['required'].items():
                    self.assertEqual((dest/name).stat().st_mode & 0o777, 0o755 if executable else 0o644)
                with self.assertRaises(FileExistsError):
                    sdk.install(package, self.archive, self.destination)

    def test_each_integrity_pin_rejects_before_any_write(self):
        with self.fixture():
            for field, value in [('size', 0), ('sha1', '0'*40), ('sha256', '0'*64)]:
                with self.subTest(field=field), patch.dict(sdk.PACKAGES['platform'], {field: value}):
                    with self.assertRaises(ValueError):
                        sdk.install('platform', self.archive, self.destination)
                    self.assertFalse(self.destination.exists())

    def test_unsafe_archive_members_reject_before_writes(self):
        root = sdk.PACKAGES['platform']['root']
        for name, mode in [('../escape', stat.S_IFREG), ('/absolute', stat.S_IFREG),
                (root+'/../escape', stat.S_IFREG), (root+'/link', stat.S_IFLNK),
                (root+'/fifo', stat.S_IFIFO), (root+'/a\\b', stat.S_IFREG),
                (root+'/android.jar', stat.S_IFREG)]:
            with self.subTest(name=name), self.fixture(extras=[(name, mode)]):
                with self.assertRaises(ValueError):
                    sdk.install('platform', self.archive, self.destination)
                self.assertFalse(self.destination.exists())

    def test_file_parent_collision_rejects(self):
        root = sdk.PACKAGES['platform']['root']
        with self.fixture(extras=[(root+'/parent', stat.S_IFREG), (root+'/parent/child', stat.S_IFREG)]):
            with self.assertRaises(ValueError):
                sdk.install('platform', self.archive, self.destination)
            self.assertFalse(self.destination.exists())

    def test_invalid_revision_and_missing_required_file_clean_staging(self):
        for options in ({'revision': 'wrong'}, {'missing': True}):
            with self.subTest(options=options), self.fixture(**options):
                with self.assertRaises(ValueError):
                    sdk.install('platform', self.archive, self.destination)
                self.assertEqual(list((self.destination/'platforms').iterdir()), [])

    def test_low_disk_space_rejects(self):
        with self.fixture(), patch.object(sdk.shutil, 'disk_usage') as usage:
            usage.return_value.free = 0
            with self.assertRaises(OSError):
                sdk.install('platform', self.archive, self.destination)
            self.assertEqual(list((self.destination/'platforms').iterdir()), [])

    def test_redirected_sdk_directory_rejects(self):
        other = self.root/'other'
        other.mkdir()
        self.destination.symlink_to(other, target_is_directory=True)
        with self.fixture(), self.assertRaises(ValueError):
            sdk.install('platform', self.archive, self.destination)
        self.assertEqual(list(other.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
