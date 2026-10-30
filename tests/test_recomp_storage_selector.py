"""Authored tail CFG fixtures only; no original bytes or recovered bodies."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/measure_storage_selector.py'
spec = importlib.util.spec_from_file_location('selector_measurement', PATH)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
ENTRY = b.BASE+0x2000
SLOT = b.BASE+0x9000


def authored():
    # One external CALL; two normal successors; RET vs absolute indirect tail.
    return b'\xe8'+struct.pack('<i', 0x100)+b'\x85\xc0\x74\x01\xc3\xff\x25'+struct.pack('<I', SLOT)


class StorageSelectorMeasurementTests(unittest.TestCase):
    def test_selection_preserves_all_prior_candidates_and_rejections(self):
        old = b.prior_selection(); new = b.selection()
        self.assertEqual(new, b.selection())
        self.assertEqual(new['selected'][:-1], old['selected'])
        self.assertEqual(new['rejected'], old['rejected'])
        self.assertEqual(new['counts']['selected'], 23)
        self.assertEqual(new['selected'][-1]['rva'], '0x8480BF')
        for invalid in ('full', 'duplicate'):
            m = copy.deepcopy(old)
            if invalid == 'full': m['authorization_limit'] = 22
            else: m['selected'][0]['rva'] = '0x8480BF'
            with patch.object(b, 'prior_selection', return_value=m), self.assertRaises(ValueError):
                b.selection()

    def test_external_tail_retained_not_a_return_or_internal_edge(self):
        f, nodes, a = b.decode_selector(authored(), ENTRY, SLOT, lambda i: i)
        self.assertEqual(a['instructions'], 5)
        self.assertEqual(a['edges'], 4)
        self.assertEqual(len(f.blocks), 3)
        self.assertEqual(a['external_tail_sites'], [hex(ENTRY+10-b.BASE)])
        self.assertFalse(a['external_tail_is_return'])
        self.assertFalse(a['call_effects_verified'])
        self.assertEqual(nodes[ENTRY+10].mnemonic, 'jmp')
        self.assertEqual(sum(i.mnemonic == 'ret' for i in nodes.values()), 1)
        d = b.dependencies(nodes, SimpleNamespace())
        self.assertEqual(d['direct_calls'], [hex(ENTRY+5+0x100-b.BASE)])
        self.assertIn(hex(SLOT), d['absolute_memory_va'])
        # Existing normal-return policy still rejects this body.
        from measure_startup import decode_flow
        with self.assertRaises(ValueError): decode_flow(authored(), ENTRY, lambda i: i)

    def test_wrong_tail_register_segment_slot_and_missing_tail_reject(self):
        prefix = authored()[:10]
        for code in (prefix+b'\xff\xe0', prefix+b'\x64\xff\x25'+struct.pack('<I', SLOT),
                     prefix+b'\xff\x25'+struct.pack('<I', SLOT+4), prefix+b'\xc3'):
            with self.subTest(code=code.hex()), self.assertRaises(ValueError):
                b.decode_selector(code, ENTRY, SLOT, lambda i: i)

    def test_escapes_interior_targets_unreachable_trap_and_truncation_reject(self):
        code = authored()
        for bad in (code[:8]+b'\x7f'+code[9:], code[:8]+b'\x02'+code[9:],
                    code+b'\x90', b'\xcc'+code[1:], code[:-1], b'', b'\x90'*129):
            with self.subTest(code=bad.hex()), self.assertRaises(ValueError):
                b.decode_selector(bad, ENTRY, SLOT, lambda i: i)
        with self.assertRaises(ValueError): b.decode_selector(code, ENTRY, SLOT+1, lambda i: i)

    def test_body_is_verbatim_without_replacing_indirect_tail(self):
        body = 'void authored(void) { ITAIL(0x1234); }'
        self.assertEqual(b.assemble(body).count(body), 1)
        for bad in ('', '/* unimplemented */', '/* unhandled */', '/* unresolved */'):
            with self.assertRaises(ValueError): b.assemble(bad)

    def test_private_pin_symlink_and_exclusive_output(self):
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

    def test_cli_object_only_is_incomplete_and_errors_sanitized(self):
        with patch('sys.argv', ['measure','--index','private','--output','private']):
            with patch.object(b, 'measure', return_value={}): self.assertEqual(b.main(), 2)
            with patch.object(b, 'measure', side_effect=ValueError('secret')): self.assertEqual(b.main(), 1)


if __name__ == '__main__': unittest.main()
