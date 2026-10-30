"""Public authored encodings only; no original function bytes or states."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/reference_resource_boundary.py'
spec = importlib.util.spec_from_file_location('resource_boundary', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
ENTRY = bench.BASE+0x2000
TARGET = bench.BASE+0x4000


def authored():
    # Self-MOV ECX; save EAX; clear EAX; push two zeros; CALL external.
    prefix = bytes.fromhex('89c95031c05050')
    return prefix+b'\xe8'+struct.pack('<i', TARGET-ENTRY-len(prefix)-5)


class ResourceBoundaryTests(unittest.TestCase):
    def inputs(self):
        regs = {r: 0x87654321+n for n, r in enumerate(bench.REGS)}
        regs['esp'] = bench.STACK+1024
        return regs, bytes([0xA5])*4096, 0xED7

    def test_raw_plan_checks_frame_without_following_callee(self):
        regs, stack, flags = self.inputs()
        result = bench.prefix_plan(authored(), ENTRY, regs, stack, flags)[-1]
        self.assertEqual(result['next_pc'], TARGET)
        self.assertEqual(result['regs']['esp'], regs['esp']-16)
        self.assertEqual(result['regs']['eax'], 0)
        sp = result['regs']['esp']-bench.STACK
        self.assertEqual(struct.unpack_from('<4I', result['stack'], sp),
                         (ENTRY+len(authored()), 0, 0, regs['eax']))
        self.assertEqual(result['stack'][:sp], stack[:sp])
        self.assertEqual(result['stack'][1024:], stack[1024:])
        self.assertEqual(result['flag_mask'], 0xCC5)
        self.assertEqual(result['flags'] & 0xCC5, (flags & ~0x8C5 | 0x44) & 0xCC5)

    def test_hook_free_x86_matches_independent_encoding_oracle(self):
        regs, stack, flags = self.inputs()
        result = bench.exercise(authored(), ENTRY, regs, stack, flags)
        self.assertEqual(result, bench.prefix_plan(authored(), ENTRY, regs, stack, flags)[-1])

    def test_push_esp_reads_old_value(self):
        regs, stack, flags = self.inputs()
        code = b'\x54\xe8'+struct.pack('<i', TARGET-ENTRY-6)
        result = bench.exercise(code, ENTRY, regs, stack, flags)
        self.assertEqual(struct.unpack_from('<I', result['stack'], 1020)[0], regs['esp'])
        self.assertEqual(result['flag_mask'], 0xCD5)

    def test_unknown_control_flow_memory_partial_and_sp_write_reject(self):
        regs, stack, flags = self.inputs()
        for code in (b'', b'\xc3', b'\xcc', b'\xff\xd0', b'\xeb\x00',
                     b'\x89\xc8', b'\x89\x00', b'\x31\xe4', b'\xe8\x00',
                     authored()+b'\x90', b'\x50', b'\x89'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                bench.prefix_plan(code, ENTRY, regs, stack, flags)
        internal = b'\xe8'+struct.pack('<i', -5)
        with self.assertRaises(ValueError):
            bench.prefix_plan(internal, ENTRY, regs, stack, flags)

    def test_bounds_and_budget_reject_before_execution(self):
        regs, stack, flags = self.inputs()
        for sp in (bench.STACK, bench.STACK+3, bench.STACK+4100):
            with self.subTest(sp=sp), self.assertRaises(ValueError):
                bench.exercise(authored(), ENTRY, dict(regs, esp=sp), stack, flags)
        with self.assertRaises(ValueError):
            bench.exercise(authored(), ENTRY, regs, stack, flags, budget=2)
        with self.assertRaises(ValueError):
            bench.prefix_plan(authored(), ENTRY, regs, stack[:-1], flags)

    def test_corrupted_oracle_is_not_accepted_as_x86(self):
        regs, stack, flags = self.inputs()
        for field in ('regs', 'stack', 'flags', 'next_pc'):
            plan = bench.prefix_plan(authored(), ENTRY, regs, stack, flags)
            if field == 'regs':
                plan[0]['regs']['edx'] ^= 1
            elif field == 'stack':
                plan[0]['stack'] = bytes(4096)
            else:
                plan[0][field] ^= 1
            with self.subTest(field=field), patch.object(bench, 'prefix_plan', return_value=plan):
                with self.assertRaises(ValueError):
                    bench.exercise(authored(), ENTRY, regs, stack, flags)

    def test_private_exclusive_and_missing_pin_guards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            (private/'link').symlink_to(outside)
            for output in (outside/'out.json', private/'link/out.json'):
                with self.assertRaisesRegex(ValueError, 'Private'):
                    bench.run(root/'index.json', output)
            output = private/'out.json'
            with patch.object(bench, 'digest', return_value='bad'):
                with self.assertRaises(ValueError):
                    bench.run(root/'index.json', output)
            self.assertFalse(output.exists())
            output.write_text('preserved')
            with self.assertRaises(FileExistsError):
                bench.run(root/'index.json', output)
            self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
