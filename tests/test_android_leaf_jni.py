"""Authored F3 transport/runner tests; no proprietary fixture, ADB or Android pass."""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts/recomp'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prepare = load('prepare_android_leaf')
runner = load('run_android_leaf')


class AndroidLeafJniTests(unittest.TestCase):
    def test_expected_records_are_little_endian_and_strict(self):
        rows = [dict(case=n, regs=[0x87654321]*8, pages='00'*(6*4096)) for n in range(64)]
        data = prepare.expected_bytes(rows)
        self.assertEqual(len(data), 64*(32+6*4096))
        self.assertEqual(data[:4], b'\x21\x43\x65\x87')
        for value in ([], rows[:-1], [dict(rows[0], case=True)]+rows[1:],
                      [dict(rows[0], regs=[True]*8)]+rows[1:],
                      [dict(rows[0], pages='00')]+rows[1:]):
            with self.assertRaises(ValueError):
                prepare.expected_bytes(value)

    def test_source_retains_body_and_replaces_only_cli(self):
        transport = '// authored body\nint main() { return 99; }'
        source = prepare.source(transport, b'ab', b'cd')
        self.assertTrue(source.startswith('// authored body\n'))
        self.assertNotIn('int main()', source)
        self.assertIn('cache_invoke(0xA0009550u,regs,adapter_009550)', source)
        self.assertIn('ts2_probe::check', source)
        for bad in ('', transport+transport):
            with self.assertRaises(ValueError):
                prepare.source(bad, b'', b'')

    def test_device_helper_loads_the_explicit_bundle_not_search_path(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = Path(d)
            (bundle/'android_probe.py').write_text('authored_marker = 123\n')
            self.assertEqual(runner.device_helpers(bundle).authored_marker, 123)

    def test_output_and_missing_private_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                prepare.prepare(Path('/absent'), Path(d))
        with self.assertRaises(FileNotFoundError):
            prepare.prepare(ROOT/'work/absent-f3-fixture', ROOT/'work/absent-f3-output')
        self.assertFalse((ROOT/'work/absent-f3-output').exists())

    def test_nonce_bound_exact_completion(self):
        row = dict(event='private_leaf_probe', nonce='a'*32,
                   result=dict(available=True, cases=64, matched=64, passed=True))
        text = json.dumps(row)
        self.assertEqual(runner.parse_result(text, 'a'*32), row['result'])
        self.assertIsNone(runner.parse_result(text, 'b'*32))
        self.assertIsNone(runner.parse_result('malformed', 'a'*32))
        duplicate=text.replace('"passed": true', '"passed": false, "passed": true')
        self.assertIsNone(runner.parse_result(duplicate, 'a'*32))
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            runner.parse_result(text+'\n'+text, 'a'*32)
        for key, value in (('available', False), ('passed', False), ('matched', 63),
                           ('cases', True), ('matched', '64')):
            bad = dict(row, result=dict(row['result'], **{key:value}))
            with self.assertRaises(ValueError):
                runner.parse_result(json.dumps(bad), 'a'*32)

    def test_bundle_hashes_and_default_preflight_issue_no_adb(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = Path(d)
            for name in ('probe.apk', 'run_probe.py', 'android_probe.py'):
                (bundle/name).write_text('authored')
            manifest = dict(schema='ts2-jni-device-bundle/1', rva='0x9550', cases=64,
                            sha256={n:runner.sha(bundle/n) for n in ('probe.apk','run_probe.py','android_probe.py')})
            (bundle/'manifest.json').write_text(json.dumps(manifest))
            with patch.object(runner.subprocess, 'run', side_effect=AssertionError('ADB called')):
                self.assertEqual(runner.preflight(bundle), manifest)
            (bundle/'probe.apk').write_text('mutant')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                runner.preflight(bundle)
            manifest['sha256']['../escape'] = 'bad'
            (bundle/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'invalid bundle'):
                runner.preflight(bundle)

    def test_public_comparator_executes_and_rejects_reg_page_and_truncation(self):
        compiler = shutil.which('c++') or shutil.which('clang++')
        self.assertIsNotNone(compiler, 'real C++ compiler required')
        source = r'''
#include "leaf_differential.hpp"
#include <stdexcept>
#include <vector>
static int fault;
static void execute(uint32_t* regs,unsigned char* pages) {
    if(fault==1) regs[7]^=1;
    if(fault==2) pages[ts2_probe::page_bytes-1]^=1;
    if(fault==3) throw std::runtime_error("reject");
}
int main() {
    std::vector<unsigned char> input(ts2_probe::cases*ts2_probe::record_bytes,0);
    auto expected=input;
    for(int n=0;n<4;++n) {
        fault=n;
        auto r=ts2_probe::check(input.data(),input.size(),expected.data(),expected.size(),execute);
        if(n==0 && (!r.complete || r.matched!=64)) return 1;
        if(n!=0 && r.matched!=0) return 2;
        if(n==3 && r.complete) return 3;
    }
    if(ts2_probe::check(input.data(),input.size()-1,expected.data(),expected.size(),execute).complete) return 4;
    if(ts2_probe::check(nullptr,input.size(),expected.data(),expected.size(),execute).complete) return 5;
    fault=0;
    return ts2_probe::check(input.data(),input.size(),expected.data(),expected.size(),execute).matched==64?0:6;
}
'''
        with tempfile.TemporaryDirectory() as d:
            src, binary = Path(d)/'test.cpp', Path(d)/'test'
            src.write_text(source)
            subprocess.run([compiler, '-std=c++20', '-pthread', '-I'+str(ROOT/'scripts/recomp'),
                            str(src), '-o', str(binary)], check=True, capture_output=True, timeout=60)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=20)

    def test_device_failure_is_durable_and_never_a_pass(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = Path(d)
            dependency = SimpleNamespace(select_usb_device=lambda *args: 'authored-serial',
                                         validate_device=lambda device: None)
            with patch.object(runner, 'preflight', return_value={'sha256':{'probe.apk':'pin'}}), \
                 patch.object(runner, 'device_helpers', return_value=dependency), \
                 patch.object(runner.subprocess, 'run', side_effect=RuntimeError('authored ADB failure')):
                report = runner.run(bundle, 'absent-adb')
            self.assertFalse(report['android_executed'])
            self.assertFalse(report['phase1_complete'])
            self.assertFalse(report['differential_passed'])
            self.assertIn('authored ADB failure', report['failure'])
            saved = list(bundle.glob('results-*/result.json'))
            self.assertEqual(len(saved), 1)
            self.assertEqual(json.loads(saved[0].read_text()), report)

    def test_device_success_requires_installed_hash_and_nonce(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = Path(d)
            (bundle/'probe.apk').write_bytes(b'authored APK')
            nonce = 'a'*32
            dependency = SimpleNamespace(select_usb_device=lambda *args: 'authored-serial',
                                         validate_device=lambda device: None)
            calls = []
            def command(argv, **kwargs):
                calls.append(argv)
                if argv[2:4] == ['pull', '/authored/base.apk']:
                    Path(argv[4]).write_bytes(b'authored APK')
                text = ''
                if argv[2:5] == ['shell', 'pm', 'path']: text='package:/authored/base.apk'
                if argv[2:4] == ['shell', 'pidof']: text='123'
                if argv[2] == 'logcat':
                    text=json.dumps(dict(event='private_leaf_probe', nonce=nonce,
                        result=dict(available=True,cases=64,matched=64,passed=True)))
                return SimpleNamespace(stdout=text)
            with patch.object(runner, 'preflight', return_value={'sha256':{'probe.apk':runner.sha(bundle/'probe.apk')}}), \
                 patch.object(runner, 'device_helpers', return_value=dependency), \
                 patch.object(runner.uuid, 'uuid4', return_value=SimpleNamespace(hex=nonce)), \
                 patch.object(runner.subprocess, 'run', side_effect=command):
                report = runner.run(bundle, 'authored-adb')
            self.assertTrue(report['differential_passed'])
            self.assertTrue(report['android_executed'])  # mocked runner contract ONLY
            self.assertFalse(report['phase1_complete'])
            self.assertTrue(all(call[1] == '-d' for call in calls))
            self.assertTrue(any(call[2:4] == ['install','-r'] for call in calls))
            self.assertFalse(any('rm' in call or 'uninstall' in call for call in calls))

    def test_production_wiring_is_opt_in_debug_and_nonce_guarded(self):
        cmake = (ROOT/'android/app/src/main/cpp/CMakeLists.txt').read_text()
        self.assertIn('if(TS2_PRIVATE_LEAF_DIR)', cmake)
        self.assertIn('debug-only', cmake)
        self.assertIn('TS2_PRIVATE_LEAF_PROBE=1', cmake)
        java = (ROOT/'android/app/src/main/java/org/ts2native/diagnostic/MainActivity.java').read_text()
        self.assertIn('probeNonce.matches("[0-9a-f]{32}")', java)
        self.assertIn('scanner.execute', java)
        bridge = (ROOT/'android/app/src/main/cpp/leaf_probe.cpp').read_text()
        self.assertIn('matched == 64', bridge)
        self.assertIn('available\\\":false', bridge)


if __name__ == '__main__':
    unittest.main()
