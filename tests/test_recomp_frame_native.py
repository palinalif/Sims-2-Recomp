"""Authored transport/oracle controls, NOT original helper reference tests."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('frame_native', ROOT/'scripts/recomp/execute_frame.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def states():
    return [dict(case=n, regs=[0]*8, stack=bytes(4096), fs=bytes(4096),
                 cookie=bytes(4096)) for n in range(64)]


def stream(rows):
    return '\n'.join(json.dumps({k: v.hex() if isinstance(v, bytes) else v
                                for k, v in row.items()}) for row in rows)


class FrameNativeTests(unittest.TestCase):
    def test_complete_match_and_native_rejection_are_distinct(self):
        expected = states()
        self.assertTrue(bench.compare(stream(expected), expected)['verified'])
        rows = copy.deepcopy(expected)
        rows[0] = dict(case=0, rejected='memory-contract')
        result = bench.compare(stream(rows), expected)
        self.assertEqual(result['matched'], 63)
        self.assertEqual(result['rejected'], 1)
        self.assertFalse(result['verified'])

    def test_every_register_and_full_pages_are_required(self):
        expected = states()
        for i in range(8):
            rows = copy.deepcopy(expected)
            rows[1]['regs'][i] = 1
            self.assertEqual(bench.compare(stream(rows), expected)['mismatched_cases'], [1])
        for key in ('stack', 'fs', 'cookie'):
            for index in (0, 2048, 4095):
                rows = copy.deepcopy(expected)
                data = bytearray(rows[2][key]); data[index] ^= 1
                rows[2][key] = bytes(data)
                self.assertFalse(bench.compare(stream(rows), expected)['verified'])

    def test_partial_duplicate_extra_malformed_and_unknown_rejection_fail(self):
        rows = states()
        for bad in (rows[:-1], rows+[rows[-1]], rows[:1]+rows[:1]+rows[2:]):
            with self.assertRaises(ValueError):
                bench.compare(stream(bad), states())
        for key, value in (('regs', [False]*8), ('regs', [0]*7), ('regs', [-1]*8),
                           ('stack', '00'), ('extra', 1), ('case', False)):
            bad = states();bad[0][key] = value
            with self.assertRaises(ValueError):
                bench.compare(stream(bad), states())
        for record in ({'case': 0, 'rejected': 'success'}, {'case': 0}):
            bad = states();bad[0] = record
            with self.assertRaises(ValueError):
                bench.compare(stream(bad), states())

    def test_body_is_inserted_once_without_rewrite(self):
        body = 'void startup_825BB0(void) { /* authored fixture */ }'
        self.assertEqual(bench.assemble(body).count(body), 1)
        for bad in ('', ' ', None):
            with self.assertRaises(ValueError):
                bench.assemble(bad)

    def test_missing_private_input_records_failure_not_native_success(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bench, 'ROOT', Path(tmp)):
            out = Path(tmp)/'work/recomp-bench/attempt'
            with self.assertRaises(OSError):
                bench.run(out, Path(tmp)/'index')
            result = json.loads((out/'result.json').read_text())
            self.assertFalse(result['success'])
            self.assertFalse(result['android_executed'])
            self.assertEqual(result['failed_stage'], 'reference')
            self.assertEqual(result['runs'], {})
            before = (out/'result.json').read_bytes()
            with self.assertRaises(FileExistsError):
                bench.run(out, Path(tmp)/'index')
            self.assertEqual((out/'result.json').read_bytes(), before)

    def test_private_output_cannot_escape_through_symlink(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bench, 'ROOT', Path(tmp)):
            private = Path(tmp)/'work/recomp-bench';private.mkdir(parents=True)
            outside = Path(tmp)/'outside';outside.mkdir()
            (private/'link').symlink_to(outside)
            with self.assertRaises(ValueError):
                bench.run(private/'link/attempt', Path(tmp)/'index')
            self.assertEqual(list(outside.iterdir()), [])

    def test_actual_checked_transport_with_authored_body_and_nonzero_fs(self):
        # Public authored header fixture tests transport only, NOT pcrecomp ABI.
        # No private upstream checkout is required by this regression test.
        body = 'void startup_825BB0(void) { g_eax=MEM32(FS_BASE); MEM32(FS_BASE)=g_ecx; }'
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp)/'fixture.c', Path(tmp)/'fixture'
            (Path(tmp)/'recomp_types.h').write_text(
                '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n'
                'static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;\n'
                '#define FS_BASE g_fs_base\n')
            source.write_text(bench.assemble(body))
            compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
            self.assertIsNotNone(compiler, 'C compiler required for transport regression')
            subprocess.run([compiler, '-D_POSIX_C_SOURCE=200809L', '-std=c11',
                str(source), '-o', str(binary)], check=True,
                capture_output=True, timeout=120)
            data, expected = bytearray(), []
            for n in range(64):
                regs = [1, 2, n+3, 4, 5, 6, 7, 0x700007F4]
                data.extend(struct.pack('<11I', *regs, 0x74000000, 17, 19))
                stack = bytes([0xA5])*4096;data.extend(stack)
                regs[0] = 17
                fs = bytearray([0x6D])*4096;struct.pack_into('<I', fs, 0, n+3)
                cookie = bytearray([0xB6])*4096;struct.pack_into('<I', cookie, 0x540, 19)
                expected.append(dict(case=n, regs=regs, stack=stack, fs=bytes(fs), cookie=bytes(cookie)))
            result = subprocess.run([str(binary)], input=bytes(data), capture_output=True,
                                    check=True, timeout=30)
            self.assertTrue(bench.compare(result.stdout.decode(), expected)['verified'])
            # Changing FS to zero must reject, not silently alias absolute VA0.
            bad = bytearray(data);struct.pack_into('<I', bad, 8*4, 0)
            self.assertEqual(subprocess.run([str(binary)], input=bad, capture_output=True,
                                           timeout=30).returncode, 91)


if __name__ == '__main__':
    unittest.main()
