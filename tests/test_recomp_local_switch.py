"""Authored switch metadata only; no game code or derived bodies."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/measure_local_switch.py'
spec = importlib.util.spec_from_file_location('local_switch',PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class LocalSwitchTests(unittest.TestCase):
    BASE = 0xa0001000
    TABLE = 0xa0002000
    # Authored JMP [EAX*4+TABLE]; two independent MOV/RET arms.
    CODE = bytes.fromhex('ff2485002000a0 b801000000c3 b802000000c3')

    def decode(self,code=None,targets=None,table=None):
        return bench.decode_switch(self.CODE if code is None else code,self.BASE,
            self.TABLE if table is None else table,
            (self.BASE+7,self.BASE+13) if targets is None else targets,lambda i:i)

    def test_explicit_local_arms_and_blocks(self):
        f,n,e = self.decode()
        self.assertEqual(f.jump_targets,{self.BASE+7,self.BASE+13})
        self.assertEqual(set(f.blocks),{self.BASE,self.BASE+7,self.BASE+13})
        self.assertEqual(len(n),5)
        self.assertEqual(e[self.BASE],[self.BASE+7,self.BASE+13])
        self.assertEqual(e[self.BASE+12],[])

    def test_rejects_wrong_table_and_operand_forms(self):
        with self.assertRaises(ValueError):
            self.decode(table=self.TABLE+4)
        for prefix in ('ffe0','ff20','ff648500','ff2445002000a0'):
            with self.subTest(prefix=prefix),self.assertRaises(ValueError):
                self.decode(code=bytes.fromhex(prefix)+self.CODE[7:])

    def test_rejects_external_mid_instruction_and_empty_targets(self):
        for targets in ((),(self.BASE+8,),(self.BASE-1,),(self.BASE+19,),tuple([self.BASE+7]*17)):
            with self.subTest(targets=targets),self.assertRaises(ValueError):
                self.decode(targets=targets)

    def test_rejects_calls_traps_and_escaping_branch(self):
        for arm in (bytes.fromhex('e800000000c3'),bytes.fromhex('cc90909090c3'),
                    bytes.fromhex('e9ffffff7fc3')):
            with self.subTest(arm=arm.hex()),self.assertRaises(ValueError):
                self.decode(code=self.CODE[:7]+arm+self.CODE[13:])

    def test_rejects_segments_and_undefined_instructions(self):
        for arm in (bytes.fromhex('64a100000000c3'),bytes.fromhex('0f0b909090c3')):
            with self.subTest(arm=arm.hex()),self.assertRaises(ValueError):
                self.decode(code=self.CODE[:7]+arm,targets=(self.BASE+7,))

    def test_duplicate_table_entries_preserve_unique_arms(self):
        f,n,e = self.decode(targets=(self.BASE+7,self.BASE+13,self.BASE+7))
        self.assertEqual(len(f.jump_targets),2)
        self.assertEqual(len(e[self.BASE]),2)

    def test_private_failure_is_recorded_without_fake_success(self):
        import json
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp,patch.object(bench,'ROOT',Path(tmp)), \
                patch('execute_cache_skip.ROOT',Path(tmp)):
            out = Path(tmp)/'work/recomp-bench/new'
            # Missing original input is a failure, never recreated or skipped.
            with self.assertRaises(FileNotFoundError):
                bench.measure(out,Path(tmp)/'missing-index')
            row = json.loads((out/'result.json').read_text())
            self.assertFalse(row['success'])
            self.assertFalse(row['arm64_executed'])
            self.assertFalse(row['m1_complete'])
            self.assertEqual(row['commands'],[])
            with self.assertRaises(FileExistsError):
                bench.measure(out,Path(tmp)/'missing-index')

    def test_missing_switch_and_no_return_reject(self):
        with self.assertRaises(ValueError):
            self.decode(code=b'\xc3',targets=(self.BASE,))
        with self.assertRaises(ValueError):
            self.decode(code=bytes.fromhex('ff2485002000a0 ebfe'),targets=(self.BASE+7,))


if __name__ == '__main__':
    unittest.main()
