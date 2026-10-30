"""The CLI's decoded stdout is a byte stream, including on Windows."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def probe_path():
    paths = [os.environ.get('TS2_DBPF_PROBE'),
             ROOT / 'build/host/ts2_dbpf_probe',
             ROOT / 'build/host/ts2_dbpf_probe.exe',
             ROOT / 'work/dbpf-probe-host.exe']
    return next((Path(path) for path in paths if path and Path(path).is_file()), None)


def fixture(payload):
    data = bytearray(100 + 20)
    data[:4] = b'DBPF'
    struct.pack_into('<II', data, 4, 1, 1)
    struct.pack_into('<IIII', data, 32, 7, 1, 100, 20)
    struct.pack_into('<I', data, 60, 1)
    data[96:96 + len(payload)] = payload
    struct.pack_into('<IIIII', data, 100, 1, 2, 3, 96, len(payload))
    return data


class DbpfProbeCliTests(unittest.TestCase):
    def test_decoded_stdout_preserves_lf_bytes(self):
        probe = probe_path()
        if probe is None:
            self.skipTest('Build ts2_dbpf_probe first')
        payload = b'\x01\n\x02\n'
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'authored.package'
            package.write_bytes(fixture(payload))
            result = subprocess.run([str(probe), str(package), '1', '2', '3'],
                                    capture_output=True, check=True)
        self.assertEqual(payload, result.stdout)


if __name__ == '__main__':
    unittest.main()
