"""Authored x86 scope controls; no original game bytes or private inputs."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/inspect_cache_closure.py'
spec = importlib.util.spec_from_file_location('cache_closure', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def nodes(code, rva=0x1290):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return {i.address:i for i in md.disasm(code, bench.BASE+rva)}


def call(target, rva=0x1290):
    return b'\xe8'+((target-rva-5) & 0xffffffff).to_bytes(4, 'little')+b'\xc3'


class CacheClosureTests(unittest.TestCase):
    def test_only_explicit_closure_targets_are_permitted(self):
        for target in bench.CLOSURE:
            gate = bench.dependency_gate(nodes(call(target)))
            self.assertTrue(gate['ready_for_lift'])
            self.assertEqual(gate['dependencies'][0]['target_rva'], hex(target))
        for target in (0x1280, 0x12e0, 0x84601e):
            gate = bench.dependency_gate(nodes(call(target)))
            self.assertFalse(gate['ready_for_lift'])
            self.assertEqual(len(gate['unresolved_or_out_of_scope']), 1)

    def test_indirect_calls_and_tail_dispatch_never_assumed_in_scope(self):
        # Independently authored register/memory call and tail-jump fixtures.
        for code in ('ffd0c3', 'ff5108c3', 'ffe0', 'ff6108'):
            with self.subTest(code=code):
                gate = bench.dependency_gate(nodes(bytes.fromhex(code)))
                self.assertFalse(gate['ready_for_lift'])
                self.assertTrue(gate['dependencies'][0]['indirect'])
                self.assertIsNone(gate['dependencies'][0]['target_rva'])

    def test_local_branches_must_land_on_instruction_boundary(self):
        self.assertTrue(bench.dependency_gate(nodes(bytes.fromhex('740090c3')))['ready_for_lift'])
        # Jump into the middle of an instruction is not a local decoded target.
        self.assertFalse(bench.dependency_gate(nodes(bytes.fromhex('eb01b801000000c3')))['ready_for_lift'])
        self.assertTrue(bench.dependency_gate(nodes(b'\xc3'))['ready_for_lift'])

    def test_output_is_private_exclusive_and_missing_inputs_not_success(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            indexes = {r:root/'index' for r in bench.LEAVES}
            with self.assertRaises(ValueError):
                bench.inspect(root/'public', indexes)
            self.assertFalse((root/'public').exists())
            out = root/'work/recomp-bench/result'
            with self.assertRaises(OSError):
                bench.inspect(out, indexes)
            data = (out/'result.json').read_bytes()
            report = json.loads(data)
            self.assertFalse(report['inspection_complete'])
            self.assertFalse(report['ready_for_lift'])
            self.assertFalse(report['lifted'])
            self.assertFalse(report['arm64_executed'])
            with self.assertRaises(FileExistsError):
                bench.inspect(out, indexes)
            self.assertEqual((out/'result.json').read_bytes(), data)
            outside = root/'outside'
            outside.mkdir()
            (root/'work/recomp-bench/link').symlink_to(outside)
            with self.assertRaises(ValueError):
                bench.inspect(root/'work/recomp-bench/link/new', indexes)

    def test_first_indirect_dependency_stops_before_second_body(self):
        from types import SimpleNamespace
        # Authored x86 CALL EAX; RET, padded inside the bounded inspection window.
        pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(ImageBase=bench.BASE),
                             FILE_HEADER=SimpleNamespace(Machine=0x14c))
        reads = []
        def get_data(rva, size):
            reads.append((rva, size))
            return bytes.fromhex('ffd0c3')+bytes(size-3)
        pe.get_data = get_data
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)), \
                patch.object(bench, 'digest', return_value=bench.IMAGE_SHA), \
                patch.object(bench, 'crosscheck_index', return_value={'boundaries_agree':True}), \
                patch('pefile.PE', return_value=pe):
            root = Path(temp)
            image = root/'work/interop-legacy-002/analysis-image.bin'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'authored image placeholder')
            index = root/'index.json'
            index.write_text('{}')
            report = bench.inspect(root/'work/recomp-bench/result', {r:index for r in bench.LEAVES})
            self.assertEqual(reads, [(0x1290,64)])
            self.assertTrue(report['inspection_complete'])
            self.assertEqual(report['stop_rva'], '0x1290')
            self.assertEqual(set(report['functions']), {'0x1290'})
            self.assertFalse(report['ready_for_lift'])
            self.assertFalse(report['lifted'])
            self.assertEqual(report['blocked_stage'], 'closure-dependency-scope')

    def test_survey_not_widened(self):
        self.assertEqual(bench.LEAVES, (0x1290, 0x12d0))
        self.assertEqual(set(bench.CLOSURE), {0x1abd40,0x1240,0x1250,0x1270,0x1290,0x12d0})


if __name__ == '__main__':
    unittest.main()
