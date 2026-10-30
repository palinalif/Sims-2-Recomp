"""Public negative controls for fresh-lift claims; no owner fixtures required."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/measure_leaf.py'
spec = importlib.util.spec_from_file_location('measure_leaf', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def output(count=32):
    return ''.join(f'CASE {i}\nR' + ' 00000000' * 8 +
                   '\nF 00000202\nT 0\nENDCASE\n' for i in range(count))


class FreshLeafTests(unittest.TestCase):
    def test_bounded_block_construction(self):
        # Authored JMP-to-RET fixture; no original bytes.
        code = bytes.fromhex('eb0090c3')
        function = bench.decode_function(code, ((0, 2), (2, 4)), 0xA0000000, lambda i: i)
        self.assertEqual(len(function.blocks), 2)
        for bad_code, ranges in (
                (code, ((0, 1), (1, 4))),  # mid-instruction boundary
                (code, ((0, 2), (3, 4))),  # gap
                (code, ((0, 3), (2, 4))),  # overlap
                (code, ((0, 2),)),  # truncated range
                (bytes.fromhex('eb7fc3'), ((0, 2), (2, 3))),  # escaping jump
                (bytes.fromhex('e800000000c3'), ((0, 6),)),  # call
                (bytes.fromhex('90'), ((0, 1),)),  # no return
                (bytes.fromhex('c30f'), ((0, 2),))):  # partial decode
            with self.subTest(code=bad_code, ranges=ranges), self.assertRaises(ValueError):
                bench.decode_function(bad_code, ranges, 0xA0000000, lambda i: i)

    def test_every_observable_and_count_required(self):
        text = output()
        expected = bench.parse_output(text)
        self.assertEqual(bench.check_states(expected, text), 32)
        for field in ('regs', 'eflags', 'mem', 'fp_depth', 'st'):
            changed = copy.deepcopy(expected)
            if field == 'regs':
                changed[0][field]['eax'] = 1
            elif field == 'mem':
                changed[0][field]['2684354560'] = 42
            elif field == 'st':
                changed[0][field] = [1]
            else:
                changed[0][field] += 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                bench.check_states(changed, text)
        for bad in (output(31), output(33), text[:-9], text + text, ''):
            with self.assertRaises(ValueError):
                bench.check_states(expected, bad)
        with self.assertRaises(ValueError):
            bench.check_states(expected[:31], output(31))

    def test_full_pipeline_required(self):
        row = {'lifted': True, 'runs': {isa: dict(compiled=True, executed=True,
                matched=32, stdout_sha256='same') for isa in ('host', 'arm64')}}
        bench.complete(row)
        changed = copy.deepcopy(row)
        changed['lifted'] = False
        with self.assertRaises(ValueError):
            bench.complete(changed)
        for isa in row['runs']:
            missing = copy.deepcopy(row)
            del missing['runs'][isa]
            with self.assertRaises(ValueError):
                bench.complete(missing)
            for key, value in (('compiled', False), ('executed', False),
                               ('matched', 31), ('stdout_sha256', 'other')):
                changed = copy.deepcopy(row)
                changed['runs'][isa][key] = value
                with self.subTest(isa=isa, key=key), self.assertRaises(ValueError):
                    bench.complete(changed)

    def test_missing_inputs_record_failure_and_refuse_clobber(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            out = Path(temp) / 'work/recomp-bench/leaf'
            with self.assertRaises(OSError):
                bench.measure(out)
            data = (out / 'metrics.jsonl').read_bytes()
            row = json.loads(data)
            self.assertFalse(row['success'])
            self.assertFalse(row['attempted'])
            self.assertFalse(row['lifted'])
            self.assertEqual(row['failed_stage'], 'preflight')
            with self.assertRaises(FileExistsError):
                bench.measure(out)
            self.assertEqual((out / 'metrics.jsonl').read_bytes(), data)

    def test_output_policy_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            outside = root / 'outside'
            outside.mkdir()
            private = root / 'work/recomp-bench'
            private.mkdir(parents=True)
            (private / 'link').symlink_to(outside)
            for out in (outside / 'result', private / 'link/result'):
                with self.assertRaises(ValueError):
                    bench.measure(out)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
