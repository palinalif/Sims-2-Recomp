"""Authored x86 only: continuation scope and conservative first-call dataflow."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/inspect_continuation_scope.py'
spec = importlib.util.spec_from_file_location('continuation_scope', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def analyze(code):
    _, nodes, edges, _ = bench.decode_flow(bytes.fromhex(code), bench.BASE+0x20d0, lambda i:i)
    return nodes, edges


def prefix(code, **kwargs):
    nodes, edges = analyze(code)
    return bench.first_call_constants(nodes, edges, bench.BASE+0x20d0, **kwargs)


class ContinuationScopeTests(unittest.TestCase):
    def test_branch_possibilities_and_edi_are_not_path_proof(self):
        # MOV EAX,high VA; TEST ECX,ECX; JZ call; MOV EAX,other VA; CALL EAX; RET.
        rows = prefix('b8001000a0 85c9 7405 b8002000a0 ffd0 c3')
        self.assertEqual({r['target_rva'] for r in rows}, {'0x1000','0x2000'})
        self.assertTrue(all(r['edi_constant'] is None for r in rows))
        rows = prefix('31ff b8001000a0 ffd0 c3')
        self.assertEqual(rows[0]['edi_constant'], '0x0')

    def test_unknown_memory_partial_and_arithmetic_writes_kill_constants(self):
        for clobber in ('8b00', 'b001', '83c001', '40', 'f7e1'):
            with self.subTest(clobber=clobber):
                self.assertIsNone(prefix('b8001000a0 '+clobber+' ffd0 c3')[0]['target_rva'])
        self.assertEqual(prefix('b8001000a0 89c2 ffd2 c3')[0]['target_rva'], '0x1000')
        self.assertIsNone(prefix('ff10 c3')[0]['target_rva'])

    def test_stops_at_first_call_without_inventing_return_or_callee_state(self):
        rows = prefix('b8001000a0 ffd0 b8002000a0 ffd0 c3')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['target_rva'], '0x1000')
        with self.assertRaises(ValueError):
            prefix('90 c3', budget=1)

    def test_unknown_scope_never_inferred_from_queue_or_constant_target(self):
        nodes, edges = analyze('b8001000a0 ffd0 c3')
        result = bench.scope(nodes, edges, bench.BASE+0x20d0)
        self.assertTrue(result['needs_scoped_decision'])
        self.assertFalse(result['whole_caller_comparison_ready'])
        # Direct CALL to independently authored, unlisted RVA 0x20d6.
        nodes, edges = analyze('e801000000 c3')
        result = bench.scope(nodes, edges, bench.BASE+0x20d0)
        self.assertEqual(result['not_in_verified_inventory'], ['0x20d6'])
        self.assertIn(0x1070, bench.KNOWN)  # Historical verified setter is retained.
        # A known body is inventory only, not a composed comparison or new scope.
        delta = (0x1070-0x20d0-5) & 0xffffffff
        nodes, edges = analyze('e8'+delta.to_bytes(4, 'little').hex()+'c3')
        result = bench.scope(nodes, edges, bench.BASE+0x20d0)
        self.assertEqual(result['not_in_verified_inventory'], [])
        self.assertFalse(result['whole_caller_comparison_ready'])

    def test_private_exclusive_failure_receipt_and_no_extra_root(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            for rva, path in ((0x21d0, root/'work/recomp-bench/wrong'),
                              (0x20d0, root/'public')):
                with self.assertRaises(ValueError):
                    bench.inspect(rva, root/'index', path)
                self.assertFalse(path.exists())
            out = root/'work/recomp-bench/new'
            with self.assertRaises(OSError):
                bench.inspect(0x20d0, root/'index', out)
            saved = (out/'result.json').read_bytes()
            receipt = json.loads(saved)
            self.assertFalse(receipt['inspection_complete'])
            self.assertFalse(receipt['host_executed'])
            self.assertFalse(receipt['dependencies_decoded'])
            with self.assertRaises(FileExistsError):
                bench.inspect(0x20d0, root/'index', out)
            self.assertEqual((out/'result.json').read_bytes(), saved)
            outside = root/'outside'
            outside.mkdir()
            (out.parent/'link').symlink_to(outside)
            with self.assertRaises(ValueError):
                bench.inspect(0x20d0, root/'index', out.parent/'link/new')

    def test_inspection_reads_only_named_root_and_requires_index_and_pin(self):
        reads = []
        def get_data(rva, bound):
            reads.append((rva, bound))
            return b'\xff\xd0\xc3'+bytes(bound-3)
        pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(ImageBase=bench.BASE),
            FILE_HEADER=SimpleNamespace(Machine=0x14c), get_data=get_data)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)), \
                patch.object(bench, 'digest', return_value=bench.IMAGE_SHA), \
                patch.object(bench, 'crosscheck_index', return_value={}) as check, \
                patch('pefile.PE', return_value=pe):
            root = Path(temp)
            image = root/'work/interop-legacy-002/analysis-image.bin'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'authored placeholder')
            index = root/'index'
            index.write_text('{}')
            row = bench.inspect(0x20d0, index, root/'work/recomp-bench/new')
            self.assertEqual(reads, [(0x20d0, bench.BOUND)])
            self.assertTrue(row['inspection_complete'])
            self.assertFalse(row['dependencies_decoded'])
            check.assert_called_once()
            check.side_effect = ValueError('authored bad index')
            with self.assertRaises(ValueError):
                bench.inspect(0x20d0, index, root/'work/recomp-bench/bad-index')
            self.assertFalse(json.loads((root/'work/recomp-bench/bad-index/result.json').read_text())['inspection_complete'])
            with patch.object(bench, 'digest', return_value='wrong'):
                with self.assertRaises(ValueError):
                    bench.inspect(0x20d0, index, root/'work/recomp-bench/bad-pin')
            self.assertEqual(len(reads), 2)  # Wrong pin rejects before reading a body.


if __name__ == '__main__':
    unittest.main()
