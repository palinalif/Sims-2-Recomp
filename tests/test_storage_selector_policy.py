import os
from pathlib import Path
import shlex
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_storage_selector_policy as p


class StorageSelectorPolicyTests(unittest.TestCase):
    def test_native_resolution_selection_and_hot_reentry(self):
        command=[*shlex.split(os.environ.get('TS2_GUEST_STORAGE_SELECTOR_RUNNER','')),
            os.environ.get('TS2_GUEST_STORAGE_SELECTOR_PROBE','build/host/ts2_guest_storage_selector_probe')]
        self.assertEqual(p.check(command,list(p.cases())),2464)

    def test_every_result_cache_and_event_component_is_required(self):
        for target in (0,p.q.FLS):
            wanted=p.expected((31,0,0,p.r.H1,target,p.r.NEG,0))
            for i in range(len(wanted)):
                changed=wanted.copy(); changed[i]^=1
                with self.assertRaises(ValueError): p.compare(changed,wanted)
            events=[wanted[i] for i in range(5,len(wanted),4)]
            self.assertEqual(events,[1,3,5,6,5,6] if target else [1,3,7,7])

    def test_strict_transport(self):
        line='0 0 31 0 0'
        self.assertEqual(p.parse(line,1),[[0,0,31,0,0]])
        for text,count in (('',1),(line+'\n'+line,1),(line,2),
                (line+' 7',1),('0 0 31 0 1',1),('0 0 -1 0 0',1),
                ('0 0 4294967296 0 0',1),('0 0 0x1f 0 0',1)):
            with self.assertRaises(ValueError): p.parse(text,count)


if __name__=='__main__': unittest.main()
