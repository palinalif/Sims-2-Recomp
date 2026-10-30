"""Authored archive fixtures only; no fake compiler is executed or counted as NDK."""
import hashlib
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location('install_ndk', Path(__file__).resolve().parents[1] / 'tools/install_android_ndk.py')
ndk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ndk)


class NdkInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = self.root / 'fixture.zip'
        self.sdk = self.root / 'sdk with spaces'

    def make(self, extras=(), revision=ndk.REVISION):
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.writestr(ndk.ROOT+'/source.properties', 'Pkg.Revision = '+revision+'\n')
            info = zipfile.ZipInfo(ndk.ROOT+'/toolchains/llvm/prebuilt/linux-x86_64/bin/clang')
            info.external_attr = (stat.S_IFREG | 0o755) << 16
            z.writestr(info, 'metadata fixture, NOT a compiler')
            for name, data, mode in extras:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                z.writestr(info, data)
        data = self.archive.read_bytes()
        return patch.multiple(ndk, SIZE=len(data), SHA1=hashlib.sha1(data).hexdigest(),
                              SHA256=hashlib.sha256(data).hexdigest())

    def test_install_receipt_permissions_links_and_no_clobber(self):
        link = ndk.ROOT+'/toolchains/llvm/prebuilt/linux-x86_64/bin/clang-link'
        with self.make([(link, 'clang', stat.S_IFLNK | 0o777)]):
            dest = ndk.install(self.archive, self.sdk)
            self.assertTrue((dest/'ts2-install-receipt.json').is_file())
            clang = dest/'toolchains/llvm/prebuilt/linux-x86_64/bin/clang'
            self.assertEqual(clang.stat().st_mode & 0o777, 0o755)
            self.assertTrue(clang.with_name('clang-link').is_symlink())
            self.assertEqual(clang.with_name('clang-link').read_bytes(), clang.read_bytes())
            with self.assertRaises(FileExistsError):
                ndk.install(self.archive, self.sdk)

    def test_corrupt_size_sha1_and_sha256_fail_before_writes(self):
        with self.make():
            for key, value in [('SIZE', 1), ('SHA1', '0'*40), ('SHA256', '0'*64)]:
                with self.subTest(key=key), patch.object(ndk, key, value):
                    with self.assertRaises(ValueError):
                        ndk.install(self.archive, self.sdk)
                    self.assertFalse(self.sdk.exists())

    def test_unsafe_paths_and_links_reject(self):
        for name, data, mode in [('../escape', '', stat.S_IFREG),
                (ndk.ROOT+'/../escape', '', stat.S_IFREG),
                (ndk.ROOT+'/link', '../../escape', stat.S_IFLNK),
                (ndk.ROOT+'/link', '/absolute', stat.S_IFLNK),
                (ndk.ROOT+'/fifo', '', stat.S_IFIFO)]:
            with self.subTest(name=name, data=data), self.make([(name, data, mode)]):
                with self.assertRaises(ValueError):
                    ndk.install(self.archive, self.sdk)
                self.assertFalse((self.sdk/'ndk'/ndk.REVISION).exists())

    def test_members_cannot_write_through_symlink(self):
        with self.make([(ndk.ROOT+'/alias', '.', stat.S_IFLNK),
                        (ndk.ROOT+'/alias/file', 'bad', stat.S_IFREG)]):
            with self.assertRaises(ValueError):
                ndk.install(self.archive, self.sdk)

    def test_revision_failure_cleans_staging(self):
        with self.make(revision='wrong'):
            with self.assertRaises(ValueError):
                ndk.install(self.archive, self.sdk)
            self.assertEqual(list((self.sdk/'ndk').iterdir()), [])

    def test_low_disk_rejects_before_staging(self):
        with self.make(), patch.object(ndk.shutil, 'disk_usage') as usage:
            usage.return_value.free = 0
            with self.assertRaises(OSError):
                ndk.install(self.archive, self.sdk)
            self.assertEqual(list((self.sdk/'ndk').iterdir()), [])


if __name__ == '__main__':
    unittest.main()
