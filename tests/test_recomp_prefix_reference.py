"""Authored caller/helper encodings only; no original-game bytes or states."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/reference_startup_prefix.py'
spec = importlib.util.spec_from_file_location('prefix_reference', PATH)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
import reference_startup_dependency as h

PREFIX_ENTRY = 0x72000000


def prefix(target=h.ENTRY, entry=PREFIX_ENTRY):
    return bytes.fromhex('6aff6878563412e8') + struct.pack('<i', target-(entry+12))


class PrefixReferenceTests(unittest.TestCase):
    def fixture(self):
        regs = {r: 0x100+n for n, r in enumerate(h.GPRS)}
        regs['esp'] = h.STACK+0x800
        stack = bytearray([0xA5]*4096)
        struct.pack_into('<I', stack, 0x800, h.RETURN)
        return regs, stack

    def test_independent_raw_caller_plan_and_known_frame(self):
        regs, stack = self.fixture()
        plan = h.caller_plan(prefix(), PREFIX_ENTRY, h.ENTRY, regs, stack)
        self.assertEqual([(p[0], p[1], p[3]) for p in plan],
            [(PREFIX_ENTRY, 2, PREFIX_ENTRY+2),
             (PREFIX_ENTRY+2, 5, PREFIX_ENTRY+7),
             (PREFIX_ENTRY+7, 5, h.ENTRY)])
        expected = bytearray(stack)
        for offset, value in ((0x7FC, h.MASK), (0x7F8, 0x12345678), (0x7F4, PREFIX_ENTRY+12)):
            struct.pack_into('<I', expected, offset, value)
        self.assertEqual(plan[-1][4], expected)
        self.assertEqual(plan[-1][2], dict(regs, esp=regs['esp']-12))
        self.assertEqual(stack[0x7F4:0x800], bytes([0xA5])*12)

    def test_signed_immediates_and_negative_rel32(self):
        regs, stack = self.fixture()
        code = bytes.fromhex('6a7f6800000080e8') + struct.pack('<i', -0x100C)
        plan = h.caller_plan(code, PREFIX_ENTRY, PREFIX_ENTRY-0x1000, regs, stack)
        self.assertEqual(struct.unpack_from('<III', plan[-1][4], 0x7F4),
                         (PREFIX_ENTRY+12, 0x80000000, 127))
        self.assertEqual(plan[-1][3], PREFIX_ENTRY-0x1000)

    def test_actual_call_fs_helper_and_stop_before_trapping_continuation(self):
        # Separately authored frame/FS fixture. Continuation's zero-filled page
        # would fault if executed; only the helper's RET reaches its address.
        code = bytes.fromhex('64a1000000005589e55064892d0000000089ec8b2c248d642404c3')
        for fs in (0x74000000, 0x75000000):
            regs, stack = self.fixture()
            state = h.exercise(code, regs, stack, fs, h.MASK, 2,
                prefix=prefix(), prefix_entry=PREFIX_ENTRY)
            self.assertEqual(state.pc, PREFIX_ENTRY+12)
            self.assertEqual(state.regs, dict(regs, eax=h.MASK, esp=regs['esp']-8))
            self.assertEqual(state.read(regs['esp']), h.RETURN)
            self.assertEqual(state.read(fs), regs['esp']-16)
            expected = bytearray(stack)
            for offset, value in ((0x7FC, h.MASK), (0x7F8, 0x12345678),
                    (0x7F4, PREFIX_ENTRY+12), (0x7F0, regs['ebp']), (0x7EC, h.MASK)):
                struct.pack_into('<I', expected, offset, value)
            self.assertEqual(state.pages[h.STACK], expected)

    def test_wrong_call_target_truncation_and_unadmitted_prefix_reject(self):
        regs, stack = self.fixture()
        invalid = [b'', b'\x90'+prefix(), prefix(h.ENTRY+1), prefix()[:-1],
                   prefix()+b'\x90', b'\xe8\x00\x00\x00\x00', b'\x50'+prefix(),
                   b'\x6a\x01'*5+prefix()[7:]]
        for code in invalid:
            with self.subTest(code=code), self.assertRaises(ValueError):
                h.caller_plan(code, PREFIX_ENTRY, h.ENTRY, regs, stack)
        regs['esp'] = h.STACK+4
        with self.assertRaises(ValueError):
            h.caller_plan(prefix(), PREFIX_ENTRY, h.ENTRY, regs, stack)

    def test_wrong_oracle_gpr_pc_or_full_stack_cannot_match(self):
        regs, stack = self.fixture()
        original = h.caller_plan
        for kind in ('gpr', 'pc', 'memory'):
            def corrupt(*args):
                plan = original(*args)
                pc, size, state, next_pc, page = plan[0]
                if kind == 'gpr':
                    state['edi'] ^= 1
                elif kind == 'pc':
                    next_pc ^= 1
                else:
                    page = bytes([page[0] ^ 1])+page[1:]
                plan[0] = pc, size, state, next_pc, page
                return plan
            with self.subTest(kind=kind), patch.object(h, 'caller_plan', corrupt), self.assertRaises(ValueError):
                h.exercise(b'\xc3', regs, stack, 0x74000000, 1, 2,
                    prefix=prefix(), prefix_entry=PREFIX_ENTRY)

    def test_wrong_helper_return_budget_and_code_overlap_reject(self):
        regs, stack = self.fixture()
        for code, kwargs in ((bytes.fromhex('b800000071890424c3'), {}),
                             (b'\xc3', {'budget': 3}),
                             (b'\xc3', {'prefix_entry': h.ENTRY, 'prefix': prefix(entry=h.ENTRY)})):
            options = dict(prefix=prefix(), prefix_entry=PREFIX_ENTRY)
            options.update(kwargs)
            with self.subTest(code=code, kwargs=kwargs), self.assertRaises(ValueError):
                h.exercise(code, regs, stack, 0x74000000, 1, 2, **options)

    def test_private_path_pin_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(b, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root/'outside'
            outside.mkdir()
            (private/'link').symlink_to(outside)
            for output in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError):
                    b.run(output, root/'index')
            output = private/'out'
            with patch.object(b, 'digest', return_value='wrong'), self.assertRaises(ValueError):
                b.run(output, root/'index')
            self.assertFalse(output.exists())
            output.write_text('preserved')
            with self.assertRaises(FileExistsError):
                b.run(output, root/'index')
            self.assertEqual(output.read_text(), 'preserved')


if __name__ == '__main__':
    unittest.main()
