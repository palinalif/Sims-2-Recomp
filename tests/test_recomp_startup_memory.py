"""Authored access-journal and independent startup writable-scope controls."""
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/recomp'))
import assess_startup_memory as assessment
import reference_startup as ref


class StartupMemoryTests(unittest.TestCase):
    def journal(self, case):
        sp = case['sp']
        used = case['cookie'] == ref.DEFAULT or case['cookie'] < 0x10000
        result = [('write',sp-4,4),('write',sp-8,4),('write',ref.COMPLEMENT,4)]
        if used:
            result += [('write',ref.COOKIE,4),('write',sp-44,4),
                       ('endpoint-write',sp-28,8),('endpoint-write',sp-36,8)]
        return result

    def test_independent_footprints_both_paths(self):
        for case in ref.cases():
            result = assessment.check_accesses(case,self.journal(case))
            self.assertIn(result['global_write_bytes'],(4,8))
            self.assertLessEqual(result['stack_write_bytes'],44)

    def test_permission_and_range_mutations_reject(self):
        used, bypass = ref.cases()[0], ref.cases()[4]
        bad = [('write',ref.BASE+ref.SLOTS[0],4),
               ('write',ref.INIT,4),('write',ref.DATA,4),
               ('write',used['sp']-48,4),('write',used['sp'],4),
               ('endpoint-write',ref.COOKIE,4),('endpoint-write',used['sp']-32,8),
               ('read',ref.COOKIE+4,4),('read',0xfffffffc,8),
               ('other',used['sp']-4,4),('write',-4,4)]
        for mutation in bad:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                assessment.check_accesses(used,self.journal(used)+[mutation])
        with self.assertRaises(ValueError):
            assessment.check_accesses(bypass,self.journal(bypass)+[('write',ref.COOKIE,4)])
        with self.assertRaises(ValueError):
            assessment.check_accesses(used,self.journal(used)[1:])

    def test_actual_reference_journals_same_value_and_implicit_stores(self):
        case = ref.cases()[0]
        # Authored x86, no proprietary bytes. mov [cookie],eax; push eax;
        # pop eax; call helper; ret. Helper: push ebp; mov ebp,esp; leave; ret.
        import struct
        body = b'\xa3'+struct.pack('<I',ref.COOKIE)+b'\x50\x58\xe8'
        body += struct.pack('<i',ref.HELPER-(ref.INIT+len(body)+4))+b'\xc3'
        codes = {ref.INIT:body, ref.HELPER:b'\x55\x89\xe5\xc9\xc3'}
        journal = []
        actual = ref.exercise(codes,case,accesses=journal)
        self.assertEqual(actual['sp'],case['sp']+4)
        self.assertIn(('write',ref.COOKIE,4),journal)
        self.assertEqual(journal.count(('write',case['sp']-4,4)),2)
        self.assertIn(('write',case['sp']-8,4),journal)
        self.assertIn(('read',case['sp']-8,4),journal)  # LEAVE
        self.assertIn(('read',case['sp'],4),journal)    # RET
        # Journal includes a same-value store on a second invocation as well.
        repeated = dict(case,cookie=0x13579bdf)
        other = []
        ref.exercise(codes,repeated,accesses=other)
        self.assertEqual(journal,other)

    def test_default_reference_is_unchanged_without_journal(self):
        codes = {ref.INIT:b'\xc3',ref.HELPER:b'\xc3'}
        case = ref.cases()[0]
        observed=[]
        self.assertEqual(ref.exercise(codes,case),ref.exercise(codes,case,accesses=observed))
        self.assertEqual(observed,[('read',case['sp'],4)])


if __name__ == '__main__':
    unittest.main()
