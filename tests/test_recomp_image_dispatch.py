"""Public controls for persistent GuestImage dispatch; no owner input required."""
import importlib.util
import os
from pathlib import Path
import struct
import shutil
import subprocess
import tempfile
import unittest

from test_analysis import synthetic_pe

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('image_bench', ROOT/'scripts/recomp/verify_existing_group.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class ImageAssemblyTests(unittest.TestCase):
    def test_only_explicit_bridge_seams_change(self):
        text = ('#include "readonly_dispatch_bridge.h"\n'
                '/* authored body must remain untouched */\n'
                'ts2_bridge_read32(a); ts2_read_dispatch(a,b,c,d,e,f);\n')
        changed = bench.image_source(text)
        self.assertIn('/* authored body must remain untouched */', changed)
        self.assertIn('ts2_image_dispatch(a,b,c,d,e,f)', changed)
        self.assertNotIn('ts2_read_dispatch(', changed)
        for bad in (text+text, text.replace('ts2_bridge_read32(', 'other(')):
            with self.assertRaises(ValueError):
                bench.image_source(bad)

    def test_missing_input_never_claims_image_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = bench.ROOT
            bench.ROOT = Path(tmp)
            try:
                output = bench.ROOT/'work/recomp-bench/missing'
                with self.assertRaises(OSError):
                    bench.run(output, image_memory=True)
                import json
                report = json.loads((output/'result.json').read_text())
                self.assertTrue(report['persistent_image_memory'])
                self.assertFalse(report['success'])
                self.assertFalse(report['arm64_executed'])
            finally:
                bench.ROOT = old


class ImageNativeTests(unittest.TestCase):
    def test_authored_persistent_reads_faults_and_recovery(self):
        # Compile the actual image-backed adapter against production sources,
        # not a replacement bridge. A missing tool is a failure, never a skip.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            exe = directory/'probe'
            opts = os.environ.get('TS2_IMAGE_TEST_TARGET', '').split()
            compiler = ('zig-cxx' if opts else os.environ.get('CXX') or
                        shutil.which('c++') or shutil.which('clang++') or 'g++')
            command = [compiler, *opts, '-std=c++20', '-O0',
                       '-I'+str(ROOT/'native/include'), '-I'+str(ROOT/'tools'),
                       '-I'+str(ROOT/'scripts/recomp'),
                       str(ROOT/'scripts/recomp/image_dispatch.cpp'),
                       str(ROOT/'tests/fixtures/image_dispatch_authored.cpp'),
                       *[str(ROOT/'native/src'/name) for name in
                         ('guest_image.cpp', 'guest_memory.cpp', 'guest_dispatch.cpp')],
                       '-o', str(exe)]
            built = subprocess.run(command, capture_output=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr.decode())
            data = bytearray(synthetic_pe())
            struct.pack_into('<I', data, 0x98+28, 0xa0000000)
            image = directory/'authored.bin'
            image.write_bytes(data)
            runner = os.environ.get('TS2_IMAGE_TEST_RUNNER')
            prefix = [runner] if runner else []
            for args, expected in (([str(image)], 0), ([], 1)):
                result = subprocess.run([*prefix, str(exe), *args], capture_output=True, timeout=60)
                self.assertEqual(result.returncode, expected, result.stderr.decode())
            self.assertEqual(image.read_bytes(), data)
            image.write_bytes(b'not a PE')
            result = subprocess.run([*prefix, str(exe), str(image)], capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 1)


if __name__ == '__main__':
    unittest.main()
