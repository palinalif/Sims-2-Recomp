"""Public oracle/transport controls only; never opens original game inputs."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_storage_selector.py'
spec = importlib.util.spec_from_file_location('execute_selector', PATH)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


class ExecuteSelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs, cls.expected = b.reference()

    def test_existing_sweep_packs_all_frames_without_self_authored_reference(self):
        self.assertEqual(len(self.inputs), 256*(44+4096))
        self.assertEqual(len(self.expected), 256)
        for n, (q, target, result, index, salt, clobber) in enumerate(b.cases()):
            block = self.inputs[n*4140:(n+1)*4140]
            words = struct.unpack('<11I', block[:44])
            regs, stack = q.free.inputs(index, salt)
            self.assertEqual(words, (*regs, target, result, int(clobber)))
            self.assertEqual(block[44:], stack)
            self.assertEqual([e[0] for e in self.expected[n]['events']],
                             ['resolve', 'guard', 'fls'] if target else ['resolve', 'tls'])

    def test_exact_comparison_and_all_gprs(self):
        text = '\n'.join(map(json.dumps, self.expected))
        self.assertEqual(b.compare(text, self.expected), dict(cases=256, matched=256))
        for k in range(8):
            rows = copy.deepcopy(self.expected); rows[0]['registers'][k] ^= 1
            with self.assertRaises(ValueError): b.compare('\n'.join(map(json.dumps, rows)), self.expected)

    def test_full_stack_order_and_each_frame_component_mutation_reject(self):
        mutations = [('stack', None), ('event-order', None)]
        mutations += [('event', i) for i in range(5)]
        for kind, k in mutations:
            rows = copy.deepcopy(self.expected)
            if kind == 'stack': rows[0]['stack'] = 'ff'+rows[0]['stack'][2:]
            elif kind == 'event-order': rows[0]['events'].reverse()
            elif k == 0: rows[0]['events'][0][k] = 'unknown'
            elif k == 1: rows[0]['events'][0][k][0] ^= 1
            else: rows[0]['events'][0][k] ^= 1
            with self.subTest(kind=kind, k=k), self.assertRaises(ValueError):
                b.compare('\n'.join(map(json.dumps, rows)), self.expected)

    def test_partial_duplicate_extra_rejected_and_boolean_integer_reject(self):
        for rows in (self.expected[:-1], self.expected+[self.expected[0]],
                     [self.expected[0]]*256):
            with self.assertRaises(ValueError): b.compare('\n'.join(map(json.dumps, rows)), self.expected)
        for key, value in (('case', False), ('registers', [False]*8), ('events', []),
                           ('rejected', True), ('stack', 'bad')):
            rows = copy.deepcopy(self.expected); rows[0][key] = value
            with self.assertRaises(ValueError): b.compare('\n'.join(map(json.dumps, rows)), self.expected)
        rows = copy.deepcopy(self.expected); rows[0]['events'][0][2] = False
        with self.assertRaises(ValueError): b.compare('\n'.join(map(json.dumps, rows)), self.expected)
        with self.assertRaises(ValueError): b.compare('invalid json', self.expected)

    def test_duplicate_json_fields_reject(self):
        rows = list(map(json.dumps, self.expected))
        rows[0] = rows[0].replace('"case": 0', '"case": 123, "case": 0')
        with self.assertRaises(ValueError): b.compare('\n'.join(rows), self.expected)

    def test_body_verbatim_and_fail_closed_macro_contract(self):
        body = 'void storage_selector(void) { /* authored control only */ }'
        source = b.assemble(body)
        self.assertEqual(source.count(body), 1)
        self.assertNotIn('@BODY@', source)
        self.assertIn('#undef RECOMP_ICALL', source)
        self.assertIn('#undef RECOMP_ITAIL', source)
        self.assertIn('call_return(v)', source)
        self.assertIn('endpoint(v,1)', source)
        self.assertIn('memcmp(slots,original_slots', source)
        for bad in ('', ' ', None):
            with self.assertRaises(ValueError): b.assemble(bad)

    def test_private_paths_exclusive_and_failed_lift_not_verification(self):
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

    def test_cli_failure_sanitized_and_success_label_bounded(self):
        out, err = io.StringIO(), io.StringIO()
        with patch('sys.argv', ['execute','--index','secret','--output','private']), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with patch.object(b, 'run', side_effect=ValueError('secret')):
                self.assertEqual(b.main(), 1)
            self.assertNotIn('secret', err.getvalue())
            with patch.object(b, 'run', return_value={}): self.assertEqual(b.main(), 0)
        self.assertIn('NOT Windows/Android/startup', out.getvalue())


if __name__ == '__main__': unittest.main()
