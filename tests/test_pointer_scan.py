from pathlib import Path
import json
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import pointer_scan
from test_analysis import synthetic_pe
from test_pe_details import tls_pe64


class PointerScanTests(unittest.TestCase):
    target = 0xA0DCBC50

    def image(self):
        data = bytearray(synthetic_pe())
        data.extend(b'\0' * (0x400 - len(data)))
        return data

    def test_unaligned_high_va_headers_sections_and_overlay(self):
        data = self.image()
        for offset in (0x41, 0x201, 0x3FC):
            struct.pack_into('<I', data, offset, self.target)
        data.extend(struct.pack('<I', self.target))  # Overlay has no RVA.
        before = bytes(data)
        self.assertEqual(pointer_scan.scan(data, self.target), {
            'rvas': ['0x41', '0x1001', '0x11FC'], 'count': 3, 'truncated': False})
        self.assertEqual(bytes(data), before)

    def test_capped_output_retains_total_and_no_match(self):
        data = self.image()
        for offset in (0x201, 0x209):
            struct.pack_into('<I', data, offset, self.target)
        self.assertEqual(pointer_scan.scan(data, self.target, 1), {
            'rvas': ['0x1001'], 'count': 2, 'truncated': True})
        self.assertEqual(pointer_scan.scan(data, self.target + 1), {
            'rvas': [], 'count': 0, 'truncated': False})

    def test_overlapping_matches_and_no_cross_region_word(self):
        data = self.image()
        data[0x210:0x216] = b'\xAA' * 6
        self.assertEqual(pointer_scan.scan(data, 0xAAAAAAAA)['rvas'],
                         ['0x1010', '0x1011', '0x1012'])
        struct.pack_into('<I', data, 0x1FE, self.target)
        self.assertEqual(pointer_scan.scan(data, self.target)['count'], 0)

    def test_rejects_ambiguous_truncated_and_out_of_image_mapping(self):
        section = 0x98 + 224
        for field, value in ((20, 0x100), (12, 0x100), (16, 0x400), (12, 0x2000)):
            with self.subTest(field=field, value=value):
                data = self.image()
                struct.pack_into('<I', data, section + field, value)
                with self.assertRaises(ValueError):
                    pointer_scan.scan(data, self.target)

    def test_rejects_pe64_invalid_va_and_limits(self):
        with self.assertRaises(ValueError):
            pointer_scan.scan(tls_pe64(), self.target)
        for target, limit in ((-1, 1), (0x100000000, 1), (1, 0), (1, 100001)):
            with self.assertRaises(ValueError):
                pointer_scan.scan(self.image(), target, limit)

    def test_cli_read_only_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'authored.bin'
            data = self.image()
            struct.pack_into('<I', data, 0x203, self.target)
            path.write_bytes(data)
            script = Path(__file__).resolve().parents[1] / 'scripts/pointer-scan.sh'
            result = subprocess.run(['sh', str(script), '--image', str(path),
                                     '--va', hex(self.target)], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                'rvas': ['0x1003'], 'count': 1, 'truncated': False})
            self.assertEqual(result.stderr, '')
            self.assertEqual(path.read_bytes(), data)
            path.write_bytes(b'private malformed contents')
            failed = subprocess.run(['sh', str(script), '--image', str(path),
                                     '--va', hex(self.target)], capture_output=True,
                                    text=True, timeout=5)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(failed.stdout, '')
            self.assertNotIn('private', failed.stderr)


if __name__ == '__main__':
    unittest.main()
