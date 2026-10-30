"""Whole-CFG gates with authored fixtures only; no original code in Git."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/measure_encoded_resolver.py'
spec = importlib.util.spec_from_file_location('resolver_measurement', PATH)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
ENTRY = b.BASE+0x2000


class EncodedResolverMeasurementTests(unittest.TestCase):
    def test_selection_retains_prior_candidates_and_rejections(self):
        old = b.prior_selection(); new = b.selection()
        self.assertEqual(new, b.selection())
        self.assertEqual(new['selected'][:-1], old['selected'])
        self.assertEqual(new['rejected'], old['rejected'])
        self.assertEqual(new['counts']['selected'], 24)
        self.assertEqual(new['selected'][-1]['rva'], '0x847E6C')
        for invalid in ('full', 'duplicate'):
            m = copy.deepcopy(old)
            if invalid == 'full': m['authorization_limit'] = 23
            else: m['selected'][0]['rva'] = '0x847e6c'
            with patch.object(b, 'prior_selection', return_value=m), self.assertRaises(ValueError):
                b.selection()

    def test_both_branches_and_cold_call_retained(self):
        # TEST/JZ chooses RET or external CALL then RET. Both belong to body.
        code = b'\x85\xc0\x74\x01\xc3\xe8\x00\x01\x00\x00\xc3'
        f, nodes, edges, a = b.characterize(code, ENTRY, lambda i: i)
        self.assertEqual(a['size_bytes'], len(code))
        self.assertEqual(a['reachable_bytes'], len(code))
        self.assertEqual(a['instructions'], 5)
        self.assertEqual(a['calls'], [ENTRY+10+256])
        self.assertEqual(edges[ENTRY+2], [ENTRY+5, ENTRY+4])
        self.assertIn(ENTRY+5, nodes)
        self.assertEqual(sum(len(x.instructions) for x in f.blocks.values()), 5)
        self.assertFalse(a['cold_paths_pruned'])

    def test_unreachable_suffix_gap_trap_and_external_jump_reject(self):
        for code in (b'\xc3\x90', b'\xeb\x01\x90\xc3', b'\xcc\xc3',
                     b'\xff\xe0', b'\xeb\x7f', b'\x85', b'', b'\x90'*257):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                b.characterize(code, ENTRY, lambda i: i)

    def test_body_inserted_once_without_instruction_replacement(self):
        body = 'void authored(void) { CALL_COLD(); }'
        self.assertEqual(b.assemble(body).count(body), 1)
        for bad in ('', '/* unimplemented */', '/* unhandled */', '/* unresolved */'):
            with self.assertRaises(ValueError): b.assemble(bad)

    def test_private_output_symlink_and_exclusive_guards(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'ROOT', Path(tmp)):
            root = Path(tmp); private = root/'work/recomp-bench'; private.mkdir(parents=True)
            outside = root/'outside'; outside.mkdir(); (private/'link').symlink_to(outside)
            for output in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError): b.measure(root/'index', output)
            output = private/'out'
            with patch.object(b, 'digest', return_value='bad'), self.assertRaises(ValueError):
                b.measure(root/'index', output)
            row = json.loads((output/'metrics.jsonl').read_text())
            self.assertEqual(row['failed_stage'], 'preflight')
            for k in ('attempted','lifted','compiled_for_aarch64','linked',
                      'matched_x86_reference','executed_under_qemu','android_executed'):
                self.assertFalse(row[k])
            with self.assertRaises(FileExistsError): b.measure(root/'index', output)

    def test_cli_incomplete_exit_and_sanitized_error(self):
        with patch('sys.argv', ['measure','--index','private','--output','private']):
            with patch.object(b, 'measure', return_value={}): self.assertEqual(b.main(), 2)
            with patch.object(b, 'measure', side_effect=ValueError('secret')): self.assertEqual(b.main(), 1)


if __name__ == '__main__': unittest.main()
