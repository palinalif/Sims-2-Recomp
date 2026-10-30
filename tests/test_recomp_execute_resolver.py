"""Public oracle/transport controls only; no original image or generated bodies."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_encoded_resolver.py'
spec = importlib.util.spec_from_file_location('execute_resolver', PATH)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


class ExecuteResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.expected = b.reference()
        cls.lines = list(map(json.dumps, cls.expected))

    def test_packing_preserves_old_cases_and_all_rotate_counts(self):
        self.assertEqual(len(self.inputs), 1336*4140)
        self.assertEqual({cookie & 31 for cookie, *_ in b.cases()}, set(range(32)))
        self.assertEqual(len(list(b.cases())), 1332)
        import encoded_cache_probe as hot
        for n, (cookie, value, index, salt) in enumerate(b.cases()):
            block = self.inputs[n*4140:(n+1)*4140]
            regs, stack = hot.inputs(index, salt)
            self.assertEqual(struct.unpack('<11I', block[:44]),
                             (*regs, cookie, hot.encode(value, cookie), index))
            self.assertEqual(block[44:], stack)
        self.assertEqual(sum('rejected' in x for x in self.expected), 4)

    def test_strict_complete_comparison_and_every_observed_component(self):
        text = '\n'.join(self.lines)
        self.assertEqual(b.compare(text, self.expected), dict(cases=1332, matched=1332, cold_rejections=4))
        for k in range(8):
            rows = self.lines.copy(); row = copy.deepcopy(self.expected[0]); row['registers'][k] ^= 1
            rows[0] = json.dumps(row)
            with self.assertRaises(ValueError): b.compare('\n'.join(rows), self.expected)
        for field, value in (('stack', 'ff'+self.expected[0]['stack'][2:]),
                             ('case', False), ('registers', [False]*8), ('extra', 1)):
            rows = self.lines.copy(); row = dict(self.expected[0]); row[field] = value; rows[0] = json.dumps(row)
            with self.assertRaises(ValueError): b.compare('\n'.join(rows), self.expected)
        for rejected in (False, 1):
            rows = self.lines.copy(); rows[-1] = json.dumps(dict(case=1335, rejected=rejected))
            with self.assertRaises(ValueError): b.compare('\n'.join(rows), self.expected)

    def test_partial_duplicate_extra_malformed_cannot_pass(self):
        for rows in (self.lines[:-1], self.lines+[self.lines[0]], [self.lines[0]]*1336):
            with self.assertRaises(ValueError): b.compare('\n'.join(rows), self.expected)
        rows = self.lines.copy(); rows[0] = rows[0].replace('"case": 0', '"case": 123, "case": 0')
        with self.assertRaises(ValueError): b.compare('\n'.join(rows), self.expected)
        with self.assertRaises(ValueError): b.compare('bad', self.expected)

    def test_verbatim_body_and_unconditional_external_rejection(self):
        body = 'void startup_847E6C(void) { /* authored control only */ }'
        source = b.assemble(body)
        self.assertEqual(source.count(body), 1)
        self.assertNotIn('@BODY@', source)
        for macro in ('RECOMP_ICALL', 'RECOMP_ITAIL'):
            self.assertIn('#undef '+macro, source)
            self.assertIn('#define '+macro+'(va) do { (void)(va); longjmp(escape,1);', source)
        self.assertIn('memcmp(cookie_page,original_cookie', source)
        self.assertIn('memcmp(cache_page,original_cache', source)
        for bad in ('', ' ', None):
            with self.assertRaises(ValueError): b.assemble(bad)

    def test_actual_native_transport_calls_bounds_immutability_reset_and_truncation(self):
        # A public authored fixture drives adapter controls; NOT a resolver model
        # and never counted as a translation or a game-code correctness check.
        body = '''void startup_847E6C(void) {
            switch(g_eax) {
            case 1: RECOMP_ICALL(0xC7000020u); break;
            case 2: RECOMP_ITAIL(0xC7000020u); break;
            case 3: g_eax=MEM32(0xA104F544u); break;
            case 4: g_eax=MEM32(0xA10E02B4u); break;
            case 5: MEM32(0xA104F540u)=19; break;
            case 6: MEM32(0xA10E02B0u)=19; break;
            case 7: g_eax=MEM32(0xB8000FFFu); break;
            case 8: g_eax=MEM32(0xB8001000u); break;
            default: g_eax=MEM32(0xA104F540u); break;
            }
        }'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root/'fixture.c'; binary = root/'fixture'
            (root/'recomp_types.h').write_text(
                '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n'
                'static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;\n')
            source.write_text(b.assemble(body))
            compiler = shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
            self.assertIsNotNone(compiler, 'C compiler required for transport regression')
            subprocess.run([compiler, '-std=c11', str(source), '-o', str(binary)],
                           check=True, capture_output=True, timeout=120)
            stack = bytearray(4096); struct.pack_into('<I', stack, 0x804, 0)
            data = b''.join(struct.pack('<11I', n, 2, 3, 4, 5, 6, 7, 0xB8000800, 17, 23, 0)+stack
                            for n in range(9))
            p = subprocess.run([str(binary)], input=data, capture_output=True, check=True, timeout=30)
            rows = [json.loads(line) for line in p.stdout.splitlines()]
            self.assertEqual(rows[0]['registers'][0], 17)
            self.assertEqual(rows[1:], [dict(case=n, rejected=True) for n in range(1, 9)])
            # Every rejection must leave the next case independently initialized.
            p = subprocess.run([str(binary)], input=data+data[:4140], capture_output=True, check=True, timeout=30)
            self.assertEqual(json.loads(p.stdout.splitlines()[-1])['registers'][0], 17)
            for truncated in (b'X', data[:43], data[:4140-1]):
                self.assertNotEqual(subprocess.run([str(binary)], input=truncated,
                                    capture_output=True, timeout=30).returncode, 0)

    def test_private_output_exclusive_and_failed_lift_not_verification(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'ROOT', Path(tmp)):
            root = Path(tmp); private = root/'work/recomp-bench'; private.mkdir(parents=True)
            outside = root/'outside'; outside.mkdir(); (private/'link').symlink_to(outside)
            for output in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError): b.run(output, root/'missing')
            output = private/'out'
            with patch.object(b.subprocess, 'run', side_effect=OSError('secret')), self.assertRaises(OSError):
                b.run(output, root/'missing')
            row = json.loads((output/'metrics.jsonl').read_text())
            self.assertEqual(row['failed_stage'], 'lift')
            for key in ('success','lifted','compiled_for_aarch64','matched_x86_reference',
                        'executed_under_qemu','android_executed'):
                self.assertFalse(row[key])
            with self.assertRaises(FileExistsError): b.run(output, root/'missing')

    def test_cli_sanitized_and_bounded_success_label(self):
        out, err = io.StringIO(), io.StringIO()
        with patch('sys.argv', ['execute','--index','secret','--output','private']), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with patch.object(b, 'run', side_effect=ValueError('secret')): self.assertEqual(b.main(), 1)
            self.assertNotIn('secret', err.getvalue())
            with patch.object(b, 'run', return_value={}): self.assertEqual(b.main(), 0)
        self.assertIn('NOT cold/Windows/Android/startup', out.getvalue())


if __name__ == '__main__': unittest.main()
