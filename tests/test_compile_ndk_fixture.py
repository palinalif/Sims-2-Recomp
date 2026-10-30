"""Public checks for the NDK command/audit contract, not compiler execution."""
import importlib.util
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('ndk_fixture', Path(__file__).resolve().parents[1] / 'scripts/recomp/compile_ndk_fixture.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NdkFixtureTests(unittest.TestCase):
    def test_commands_use_ndk_api26_and_production_core(self):
        commands = dict(module.commands(Path('/SDK with spaces/ndk/27.2.12479018'),
                                       Path('/private fixture'), Path('/output')))
        self.assertIn('-DANDROID_ABI=arm64-v8a', commands['configure'])
        self.assertIn('-DANDROID_PLATFORM=android-26', commands['configure'])
        self.assertIn('ts2_core', commands['core-build'])
        link = list(map(str, commands['fixture-link']))
        self.assertEqual(link[0], '/SDK with spaces/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang++')
        self.assertIn('-static', link)
        self.assertIn(str(module.ROOT/'scripts/recomp/ndk_static_tls.S'), link)
        self.assertIn('/output/core/libts2_core.a', link)
        self.assertIn('/private fixture/transport.cpp', link)
        self.assertFalse(any('zig' in arg for arg in link))

    def test_elf_requires_aarch64_little_endian_64bit(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'elf'
            header = bytearray(20)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = (183).to_bytes(2, 'little')
            p.write_bytes(header)
            module.check_elf(p)
            for offset, value in ((4, 1), (5, 2), (18, 62)):
                bad = bytearray(header)
                bad[offset] = value
                p.write_bytes(bad)
                with self.assertRaises(ValueError):
                    module.check_elf(p)
            p.write_bytes(b'')
            with self.assertRaises(ValueError):
                module.check_elf(p)

    @staticmethod
    def tls_elf(alignment=64):
        data = bytearray(120)
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 183)
        struct.pack_into('<Q', data, 32, 64)
        struct.pack_into('<HH', data, 54, 56, 1)
        struct.pack_into('<IIQQQQQQ', data, 64, 7, 4, 0, 0, 0, 0, 1, alignment)
        return data

    def test_static_tls_accepts_bionic_alignment(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'elf'
            for alignment in (64, 128):
                p.write_bytes(self.tls_elf(alignment))
                self.assertEqual(module.check_static_tls(p), alignment)

    def test_static_tls_rejects_original_failure_and_non_power_of_two(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'elf'
            for alignment in (0, 8, 32, 65):
                p.write_bytes(self.tls_elf(alignment))
                with self.assertRaisesRegex(ValueError, 'underaligned'):
                    module.check_static_tls(p)

    def test_static_tls_rejects_absent_truncated_and_malformed_headers(self):
        valid = self.tls_elf()
        mutations = [valid[:60], valid[:119]]
        for offset, fmt, value in ((32, '<Q', 0), (54, '<H', 55),
                                   (56, '<H', 0), (64, '<I', 1),
                                   (72, '<Q', 1), (104, '<Q', 0)):
            bad = bytearray(valid)
            struct.pack_into(fmt, bad, offset, value)
            if offset == 104:  # filesz > memsz
                struct.pack_into('<Q', bad, 96, 1)
            mutations.append(bad)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'elf'
            for bad in mutations:
                p.write_bytes(bad)
                with self.assertRaises(ValueError):
                    module.check_static_tls(p)

    def test_audit_rejects_mutation_and_missing_input(self):
        with tempfile.TemporaryDirectory() as d:
            fixture = Path(d)
            with self.assertRaises(FileNotFoundError):
                module.audit(fixture)
            (fixture/'body').write_text('authored test body')
            (fixture/'transport.cpp').write_text('authored test body')
            (fixture/'switch').mkdir()
            (fixture/'switch/lifted.c').write_text('authored test body')
            pins = {n: module.digest(fixture/n) for n in ('transport.cpp', 'switch/lifted.c')}
            with patch.object(module, 'PINS', pins):
                module.audit(fixture)
                (fixture/'transport.cpp').write_text('mutant')
                with self.assertRaises(ValueError):
                    module.audit(fixture)

    def test_output_must_be_new_and_private(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                module.run(Path('/absent-ndk'), Path('/absent-fixture'), Path(d))


if __name__ == '__main__':
    unittest.main()
