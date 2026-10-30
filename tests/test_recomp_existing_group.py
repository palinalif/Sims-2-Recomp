"""Public claim-gate tests; actual private execution is a separate experiment."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/verify_existing_group.py'
spec = importlib.util.spec_from_file_location('existing_group', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class ExistingGroupTests(unittest.TestCase):
    def test_complete_pair_required(self):
        pair = {isa: {'executed': True, 'exit_code': 0, 'matched': 96,
                      'stdout_sha256': 'same'} for isa in ('host', 'arm64')}
        bench.require_complete(pair)
        for isa in pair:
            missing = copy.deepcopy(pair)
            del missing[isa]
            with self.assertRaises(ValueError):
                bench.require_complete(missing)
            for key, value in (('executed', False), ('exit_code', 1),
                               ('matched', 95), ('stdout_sha256', 'different')):
                changed = copy.deepcopy(pair)
                changed[isa][key] = value
                with self.subTest(isa=isa, key=key), self.assertRaises(ValueError):
                    bench.require_complete(changed)

    def test_output_outside_private_tree_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'not-private'
            with self.assertRaises(ValueError):
                bench.run(output)
            self.assertFalse(output.exists())

    def test_missing_inputs_fail_closed_and_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / 'work/recomp-bench/missing'
            old = bench.ROOT
            try:
                bench.ROOT = root
                with self.assertRaises(OSError):
                    bench.run(output)
                report = (output / 'result.json').read_bytes()
                state = json.loads(report)
                self.assertFalse(state['success'])
                self.assertFalse(state['arm64_executed'])
                self.assertEqual(state['runs'], {})
                with self.assertRaises(FileExistsError):
                    bench.run(output)
                self.assertEqual((output / 'result.json').read_bytes(), report)
            finally:
                bench.ROOT = old

    def test_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'work/recomp-bench').mkdir(parents=True)
            (root / 'outside').mkdir()
            (root / 'work/recomp-bench/escape').symlink_to(root / 'outside')
            old = bench.ROOT
            try:
                bench.ROOT = root
                with self.assertRaises(ValueError):
                    bench.run(root / 'work/recomp-bench/escape/result')
                self.assertEqual(list((root / 'outside').iterdir()), [])
            finally:
                bench.ROOT = old


if __name__ == '__main__':
    unittest.main()
