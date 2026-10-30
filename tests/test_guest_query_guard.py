"""Authored C fixture for bounded guest reads and registered dispatch."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "guest_query_guard.h"

static unsigned char object_bytes[0x108];
static unsigned char stack_bytes[8];
static uint32_t result;
static Ts2GuestSpan spans[] = {
    {0xA1000000u, sizeof object_bytes, object_bytes},
    {0xA1020000u, sizeof stack_bytes, stack_bytes},
};
static Ts2GuestView view = {spans, 2};

static void query(void) {
    result = ts2_checked_read32(&view, 0xA1000100u)
           + ts2_checked_read32(&view, 0xA1020000u);
}

int main(int argc, char **argv) {
    static const Ts2GuestEntry entries[] = {{0xA0001240u, query}};
    if (argc != 2) return 9;
    object_bytes[0x100] = 0x44;
    object_bytes[0x101] = 0x33;
    object_bytes[0x102] = 0x22;
    object_bytes[0x103] = 0x11;
    stack_bytes[0] = 0x88;
    stack_bytes[1] = 0x77;
    stack_bytes[2] = 0x66;
    stack_bytes[3] = 0x55;
    if (!strcmp(argv[1], "valid")) {
        ts2_dispatch(0xA0001240u, entries, 1);
        printf("%08x\n", result);
    } else if (!strcmp(argv[1], "uncommitted")) {
        (void)ts2_checked_read32(&view, 0xA1000106u);
    } else if (!strcmp(argv[1], "wrap")) {
        (void)ts2_checked_read32(&view, 0xFFFFFFFEu);
    } else if (!strcmp(argv[1], "unknown")) {
        ts2_dispatch(0xA0001250u, entries, 1);
    } else {
        return 8;
    }
    return 0;
}
'''


class GuestQueryGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        work = ROOT / 'work'
        work.mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(dir=work)
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        source = folder / 'fixture.c'
        source.write_text(FIXTURE)
        cls.binary = folder / ('fixture.exe' if os.name == 'nt' else 'fixture')
        compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
        zig = ROOT / 'work/deps/zig-windows-x86_64-0.14.0/zig.exe'
        if compiler:
            command = [compiler]
        elif zig.exists():
            command = [str(zig), 'cc']
        else:
            raise unittest.SkipTest('No host C compiler; install cc/clang/gcc or verified local Zig')
        env = os.environ.copy()
        env['ZIG_GLOBAL_CACHE_DIR'] = str(ROOT / 'work/zig-cache-global')
        env['ZIG_LOCAL_CACHE_DIR'] = str(folder / 'zig-local')
        for key in ('TMP', 'TEMP', 'TMPDIR'):
            env[key] = str(folder)
        cls.build = subprocess.run(command + ['-std=c11', '-I', str(ROOT / 'tools'),
                                             str(source), '-o', str(cls.binary)],
                                   capture_output=True, text=True, timeout=180, env=env)

    def run_case(self, name):
        self.assertEqual(self.build.returncode, 0, self.build.stderr)
        return subprocess.run([str(self.binary), name], capture_output=True,
                              text=True, timeout=10)

    def test_valid_high_bit_object_and_stack_reads(self):
        run = self.run_case('valid')
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), '6688aacc')

    def test_rejects_uncommitted_read(self):
        run = self.run_case('uncommitted')
        self.assertEqual(run.returncode, 102)
        self.assertIn('TS2_GUEST_READ_REJECT', run.stderr)

    def test_rejects_wraparound_read(self):
        run = self.run_case('wrap')
        self.assertEqual(run.returncode, 102)
        self.assertIn('TS2_GUEST_READ_REJECT', run.stderr)

    def test_rejects_unregistered_function(self):
        run = self.run_case('unknown')
        self.assertEqual(run.returncode, 103)
        self.assertIn('TS2_UNRESOLVED_FUNCTION', run.stderr)


if __name__ == '__main__':
    unittest.main()
