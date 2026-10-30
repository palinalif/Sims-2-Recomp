"""Public controls for newly allocated inputs; no private game data required."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts/recomp'))
spec = importlib.util.spec_from_file_location('image_leaf', ROOT/'scripts/recomp/verify_image_leaf.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def transport(states):
    return ''.join(f'CASE {i}\nR ' + ' '.join(f'{s["regs"][r]:08x}' for r in bench.REGS)
                   + f'\nF {s["eflags"]:08x}\nT 0\nENDCASE\n'
                   for i, s in enumerate(states))


class ImageLeafTests(unittest.TestCase):
    def test_explicit_new_inputs_and_both_branches(self):
        cases = bench.cases()
        self.assertEqual(cases, bench.cases())
        self.assertEqual(len(cases), 32)
        self.assertEqual(sum(c['fields'][2] == 0 for c in cases), 16)
        for case in cases:
            self.assertEqual(case['regs']['esp'], bench.STACK)
            self.assertEqual(int.from_bytes(case['stack'][4:], 'little'), bench.OBJECT)
            self.assertGreater(bench.OBJECT, 0xb0000000)
            self.assertEqual(len(case['obj']), 0x108)

    def test_independent_arithmetic_flags(self):
        case = bench.cases()[0]
        zero = bench.oracle(case)
        self.assertEqual(zero['regs']['eax'], 0xffffffff)
        self.assertEqual(zero['eflags'], 0x286)
        # ADD overflow, carry, zero, auxiliary carry and parity boundaries.
        for fields, value, flags in (
                ((0x7fffffff, 0, 1), 0x80000000, 0xa96),
                ((0xffffffff, 0, 1), 0, 0x257),
                ((15, 0, 1), 16, 0x212),
                ((0, 1, 2), 1, 0x213)):
            result = bench.oracle(dict(case, fields=fields))
            self.assertEqual(result['regs']['eax'], value)
            self.assertEqual(result['eflags'], flags)
            self.assertEqual(result['regs']['esp'], bench.STACK+4)
            self.assertEqual(result['regs']['ecx'], bench.OBJECT)

    def test_bounded_reference_ret_and_faults(self):
        case = bench.cases()[0]
        expected = dict(regs=dict(case['regs'], esp=bench.STACK+4),
                        eflags=0x202, mem={}, fp_depth=0, st=[])
        with patch.object(bench, 'oracle', return_value=expected):
            self.assertEqual(bench.reference(b'\xc3', [case]), [expected])
            for code in (b'\xeb\xfe',  # instruction budget exhausted
                         b'\xa1\x00\x00\x00\x00\xc3',  # null read
                         b'\x89\x04\x24\xc3',  # stack store
                         b'\x8b\x44\x24\x08\xc3'):  # committed page gap
                with self.subTest(code=code), self.assertRaises(Exception):
                    bench.reference(code, [case])

    def test_unchanged_body_and_one_entry(self):
        # Authored placeholder body only. No original bytes/body in Git.
        body = 'void object_query_1250(void) { /* authored placeholder */ }\n'
        text = ('#define MEM32(addr) ts2_checked_read32(&query_view, (uint32_t)(addr))\n'
                'void object_query_1240(void) {}\n' + body +
                'void object_query_1270(void) {}\n')
        source, _ = bench.assemble(text, bench.cases())
        self.assertEqual(source.count(body), 1)
        self.assertNotIn('void object_query_1240', source)
        self.assertNotIn('void object_query_1270', source)
        self.assertEqual(source.count('ts2_image_dispatch('), 32)
        self.assertNotIn('ts2_checked_read32(', source)
        self.assertIn('before[68]', source)
        self.assertIn('if(before[j]!=ts2_image_read32(', source)
        with self.assertRaises(ValueError):
            bench.assemble(text.replace('#define MEM32(addr)', '#define OTHER(addr)'), bench.cases())

    def test_every_observable_and_transport_required(self):
        states = [bench.oracle(c) for c in bench.cases()]
        text = transport(states)
        self.assertEqual(bench.check(states, text), 32)
        for field in bench.REGS:
            changed = copy.deepcopy(states)
            changed[0]['regs'][field] ^= 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.check(changed, text)
        for field, value in (('eflags', 0), ('mem', {'1': 2}), ('fp_depth', 1), ('st', [1])):
            changed = copy.deepcopy(states)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.check(changed, text)
        for bad in ('', text[:-9], text+text, transport(states[:-1]), text.replace('T 0', 'T 1', 1)):
            with self.assertRaises(ValueError):
                bench.check(states, bad)

    def test_missing_inputs_fail_and_preserve_output(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bench, 'ROOT', Path(tmp)):
            output = Path(tmp)/'work/recomp-bench/new'
            with self.assertRaises(OSError):
                bench.run(output)
            before = (output/'result.json').read_bytes()
            row = json.loads(before)
            self.assertFalse(row['success'])
            self.assertFalse(row['fresh_x86_reference'])
            self.assertFalse(row['arm64_executed'])
            with self.assertRaises(FileExistsError):
                bench.run(output)
            self.assertEqual((output/'result.json').read_bytes(), before)
            outside = Path(tmp)/'outside'
            outside.mkdir()
            (output.parent/'alias').symlink_to(outside)
            for path in (outside/'new', output.parent/'alias/new'):
                with self.assertRaises(ValueError):
                    bench.run(path)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
