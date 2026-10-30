"""Authored encoding fixtures; no original-game bytes or saved states."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('resource_call', Path(__file__).resolve().parents[1]/'scripts/recomp/reference_resource_call.py')
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class ResourceCallTests(unittest.TestCase):
    ENTRY = 0xA0001100
    LEAF = 0xA0001200

    def frame(self):
        regs = {r: 0x12345678 for r in bench.REGS}
        regs['esp'] = bench.PAGES[0]+2048
        pages = {p: bytearray(4096) for p in bench.PAGES}
        pages[bench.PAGES[0]][:] = bytes([0xEA])*4096
        return regs, pages

    def prefix(self, head):
        return head+b'\xe8'+struct.pack('<i', self.LEAF-(self.ENTRY+len(head)+5))

    def test_raw_plan_and_continuous_x86_nested_return(self):
        regs, pages = self.frame()
        # Authored frame, local address passed by PUSH, leaf writes through it.
        prefix = self.prefix(bytes.fromhex('5589e583ec108d45f050'))
        plan = bench.prefix_plan(prefix, self.ENTRY, regs, pages[bench.PAGES[0]])
        self.assertEqual(plan[-1]['next_pc'], self.LEAF)
        self.assertEqual(plan[-1]['regs']['esp'], regs['esp']-28)
        self.assertEqual(struct.unpack_from('<I', plan[-1]['stack'], 2020)[0], self.ENTRY+len(prefix))
        leaf = bytes.fromhex('8b442404c6005ac20400')
        result, seen = bench.reference_case(leaf, self.LEAF, regs, pages, prefix=(prefix, self.ENTRY))
        self.assertEqual(len(seen), 3)
        self.assertEqual(result['regs'][-1], regs['esp']-20)
        self.assertEqual(bytes.fromhex(result['pages'])[2028], 0x5A)
        self.assertEqual(pages[bench.PAGES[0]][2028], 0xEA)

    def test_immediates_mov_direction_and_sub_flags_match_x86(self):
        regs, pages = self.frame()
        for head in ('558bec81ec200000006aff', '89c08bc083ec046878563412', '83ec0054'):
            with self.subTest(head=head):
                prefix = self.prefix(bytes.fromhex(head))
                result, _ = bench.reference_case(bytes.fromhex('c20400'), self.LEAF, regs, pages,
                                                prefix=(prefix, self.ENTRY))
                plan = bench.prefix_plan(prefix, self.ENTRY, regs, pages[bench.PAGES[0]])
                self.assertEqual(result['regs'][-1], plan[-1]['regs']['esp']+8)

    def test_rejects_branch_segment_memory_move_and_truncated_prefix(self):
        regs, pages = self.frame()
        for head in ('eb00', '6489c0', '8b00', '89c4', '83c404', '8d0424', '83ec01', 'e800'):
            with self.subTest(head=head), self.assertRaises(ValueError):
                bench.prefix_plan(self.prefix(bytes.fromhex(head)), self.ENTRY, regs, pages[bench.PAGES[0]])
        for code in (b'', b'\x50', b'\x68\x01', b'\xe8\x01'):
            with self.assertRaises(ValueError):
                bench.prefix_plan(code, self.ENTRY, regs, pages[bench.PAGES[0]])

    def test_wrong_call_target_bad_stack_and_wrong_cleanup_reject(self):
        regs, pages = self.frame()
        prefix = self.prefix(bytes.fromhex('6a00'))
        with self.assertRaises(ValueError):
            bench.reference_case(bytes.fromhex('c20400'), self.LEAF+16, regs, pages, prefix=(prefix, self.ENTRY))
        regs['esp'] = bench.PAGES[0]
        with self.assertRaises(ValueError):
            bench.prefix_plan(prefix, self.ENTRY, regs, pages[bench.PAGES[0]])
        regs, pages = self.frame()
        # A leaf that corrupts its return address must not count as a return.
        with self.assertRaises(ValueError):
            bench.reference_case(bytes.fromhex('c7042400000000c20400'), self.LEAF, regs, pages,
                                 prefix=(prefix, self.ENTRY))

    def test_corrupt_prefix_prediction_cannot_pass_x86(self):
        import reference_resource_call as oracle
        regs, pages = self.frame()
        prefix = self.prefix(bytes.fromhex('6a00'))
        original = oracle.prefix_plan
        for component in ('register', 'flags', 'stack', 'pc'):
            def corrupt(*args):
                plan = original(*args)
                if component == 'register':
                    plan[0]['regs']['eax'] ^= 1
                elif component == 'flags':
                    plan[0]['flags'] ^= 1
                elif component == 'stack':
                    plan[0]['stack'] = bytes(4096)
                else:
                    plan[0]['next_pc'] ^= 1
                return plan
            with self.subTest(component=component), patch.object(oracle, 'prefix_plan', corrupt):
                with self.assertRaises(ValueError):
                    bench.reference_case(bytes.fromhex('c20400'), self.LEAF, regs, pages,
                                         prefix=(prefix, self.ENTRY))

    def test_prefix_code_overlap_and_cross_page_reject(self):
        regs, pages = self.frame()
        prefix = self.prefix(bytes.fromhex('6a00'))
        for address in (self.LEAF, 0xA0002000, 0xA0001FFC):
            with self.subTest(address=address), self.assertRaises(ValueError):
                bench.reference_case(bytes.fromhex('c20400'), self.LEAF, regs, pages, prefix=(prefix, address))

    def test_output_private_exclusive_and_wrong_pin_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bench, 'ROOT', Path(tmp)):
            root = Path(tmp)
            with self.assertRaises(ValueError):
                bench.run(root/'missing', root/'missing', root/'outside')
            image = root/'work/interop-legacy-002/analysis-image.bin'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'wrong pin authored fixture')
            output = root/'work/recomp-bench/rejected'
            with self.assertRaises(ValueError):
                bench.run(root/'missing', root/'missing', output)
            row = json.loads((output/'metrics.json').read_text())
            self.assertFalse(row['success'])
            self.assertEqual(row['completed_cases'], 0)
            self.assertFalse(row['native_executed'])
            with self.assertRaises(FileExistsError):
                bench.run(root/'missing', root/'missing', output)
            self.assertEqual(image.read_bytes(), b'wrong pin authored fixture')


if __name__ == '__main__':
    unittest.main()
