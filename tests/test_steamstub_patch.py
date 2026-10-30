"""Authored fixtures only; never opens a user game executable."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import pefile
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Cipher = None
from test_analysis import synthetic_pe

ROOT = Path(__file__).resolve().parents[1]


class SteamStubPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if Cipher is None:
            raise unittest.SkipTest('Install tools/interop-requirements.txt for isolated patch fixtures')
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e/tools/drm/steamstub.py'
        if not pristine.exists():
            raise unittest.SkipTest('Fetch pinned pcrecomp to run independent patch fixtures')
        if hashlib.sha256(pristine.read_bytes()).hexdigest() != '6a3724044bdb471454646d8504d53fe60f6aad45a07dc1d841e7bacaff0433f7':
            raise RuntimeError('Pristine SteamStub source does not match pinned revision')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        source = Path(cls.temp.name)/'tools/drm/steamstub.py'
        source.parent.mkdir(parents=True)
        shutil.copyfile(pristine, source)
        patch = ROOT/'patches/pcrecomp/0001-steamstub-analysis-metadata.patch'
        if patch.exists():
            subprocess.run(['patch', '--batch', '-p1', '-i', str(patch)], cwd=cls.temp.name,
                           check=True, capture_output=True, timeout=10)
        spec = importlib.util.spec_from_file_location('steamstub_patch_fixture', source)
        cls.stub = importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.stub)

    def fixture(self, *, corrupt_code=False):
        data = bytearray(synthetic_pe());data.extend(bytes(0x400))
        struct.pack_into('<H', data, 0x86, 2)
        struct.pack_into('<I', data, 0x98+16, 0x3100)
        struct.pack_into('<I', data, 0x98+56, 0x4000)
        section = 0x98+224+40
        data[section:section+8] = b'.bind\0\0\0'
        struct.pack_into('<4I', data, section+8, 0x400, 0x3000, 0x400, 0x400)
        struct.pack_into('<I', data, section+36, 0x60000020)
        plain = bytes(range(16));key = bytes(range(32));iv = bytes(range(16,32))
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(plain+b'\x10'*16)
        header = bytearray(0xf0)
        for offset, value in [(0,0x12345678),(4,0xc0dec0df),(8,0x400000),
                              (0x20,0x1000),(0x38,123),(0x3c,0),(0x48,0x1000),(0x50,16)]:
            struct.pack_into('<I', header, offset, value)
        header[0x58:0x78] = key
        header[0x78:0x88] = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(iv)
        header[0x88:0x98] = cipher[:16]
        data[0x200:0x210] = bytes(16) if corrupt_code else cipher[16:]
        self.encode_header(data, header)
        data[0x500:0x500+len(self.stub.V3_PROLOGUE)] = self.stub.V3_PROLOGUE
        data.extend(b'AUTHORED_OVERLAY')
        return bytes(data), plain, header

    @staticmethod
    def encode_header(data, header):
        previous = struct.unpack_from('<I', header)[0]
        encoded = bytearray(header[:4])
        for offset in range(4,len(header),4):
            previous ^= struct.unpack_from('<I', header, offset)[0]
            encoded.extend(struct.pack('<I', previous))
        data[0x410:0x500] = encoded

    def test_inspection_api_is_separate_from_recovery(self):
        self.assertTrue(hasattr(self.stub,'inspect_v3'), 'Missing metadata-only inspection API')
        raw, _, _ = self.fixture(corrupt_code=True)
        digest = hashlib.sha256(raw).hexdigest()
        header, info = self.stub.inspect_v3(raw,header_size=0xf0,expected_appid=123)
        self.assertEqual(info['oep'],0x401000)
        self.assertEqual(info['code_offset'],0x200)
        self.assertEqual(info['code_size'],16)
        self.assertEqual(info['metadata_locator'],'reviewed-explicit-size')
        self.assertEqual(len(header),0xf0)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),digest)

    def test_recovery_preserves_headers_entry_wrapper_and_overlay(self):
        self.assertTrue(hasattr(self.stub,'recover_v3_analysis'), 'Missing analysis-only recovery API')
        raw, plain, _ = self.fixture()
        recovered, info = self.stub.recover_v3_analysis(raw,header_size=0xf0,expected_appid=123)
        self.assertEqual(recovered[0x200:0x210],plain)
        self.assertEqual(recovered[:0x200],raw[:0x200])
        self.assertEqual(recovered[0x210:],raw[0x210:])
        self.assertEqual(len(recovered),len(raw))
        self.assertEqual(pefile.PE(data=recovered).OPTIONAL_HEADER.AddressOfEntryPoint,0x3100)
        self.assertTrue(info['analysis_only'])

    def test_bad_metadata_fails_before_recovery(self):
        self.assertTrue(hasattr(self.stub,'inspect_v3'), 'Missing metadata-only inspection API')
        raw, _, header = self.fixture()
        for offset, value in [(4,0),(8,0x500000),(0x20,0x3000),(0x48,0x2000),
                              (0x50,0),(0x50,0x10000),(0x50,15)]:
            with self.subTest(offset=offset,value=value):
                changed = bytearray(raw);bad = bytearray(header)
                struct.pack_into('<I',bad,offset,value);self.encode_header(changed,bad)
                with self.assertRaises(self.stub.StubError):
                    self.stub.inspect_v3(bytes(changed),header_size=0xf0,expected_appid=123)
        for size in [0x40,0x401,0x301,0xF4]:
            with self.assertRaises(self.stub.StubError):self.stub.inspect_v3(raw,header_size=size)
        with self.assertRaises(self.stub.StubError):self.stub.inspect_v3(raw,header_size=0xf0,expected_appid=456)
        with self.assertRaises(self.stub.StubError):self.stub.inspect_v3(raw[:0x510],header_size=0xf0)

    def test_corrupt_ciphertext_is_not_accepted_as_recovered_code(self):
        self.assertTrue(hasattr(self.stub,'recover_v3_analysis'), 'Missing analysis-only recovery API')
        raw, _, _ = self.fixture(corrupt_code=True)
        with self.assertRaises(self.stub.StubError):
            self.stub.recover_v3_analysis(raw,header_size=0xf0,expected_appid=123)

    def test_code_cannot_alias_headers_or_wrapper_raw_bytes(self):
        raw, _, _ = self.fixture()
        text_section=0x98+224
        for raw_offset in [0x100,0x400,0x600]:
            with self.subTest(raw_offset=raw_offset):
                changed=bytearray(raw)
                struct.pack_into('<I',changed,text_section+20,raw_offset)
                with self.assertRaises(self.stub.StubError):
                    self.stub.inspect_v3(bytes(changed),header_size=0xf0,expected_appid=123)

    def test_code_cannot_overlap_certificate_data(self):
        raw, _, _ = self.fixture();changed=bytearray(raw)
        struct.pack_into('<II',changed,0x98+96+4*8,0x200,16)
        with self.assertRaises(self.stub.StubError):
            self.stub.inspect_v3(bytes(changed),header_size=0xf0,expected_appid=123)

    def test_existing_known_copy_pattern_needs_no_size_override(self):
        raw, _, _ = self.fixture();changed=bytearray(raw)
        pattern=b'\x68'+struct.pack('<I',0xf0)+b'\x8d\x83'+struct.pack('<i',-0xf0)+b'\x50'
        changed[0x580:0x580+len(pattern)]=pattern
        _,info=self.stub.inspect_v3(bytes(changed),expected_appid=123)
        self.assertEqual(info['header_size'],0xf0)
        self.assertEqual(info['metadata_locator'],'known-copy-pattern')


if __name__ == '__main__':unittest.main()
