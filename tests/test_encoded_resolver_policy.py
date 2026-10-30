import copy
import os
from pathlib import Path
import shlex
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_encoded_resolver_policy as p


class EncodedResolverPolicyTests(unittest.TestCase):
    def test_native_requests_publication_and_reentry_against_oracle(self):
        binary = os.environ.get('TS2_GUEST_ENCODED_RESOLVER_PROBE',
                                'build/host/ts2_guest_encoded_resolver_probe')
        command = [*shlex.split(os.environ.get('TS2_GUEST_ENCODED_RESOLVER_RUNNER','')),binary]
        self.assertEqual(p.check(command,list(p.cases())),5464)

    def test_transport_rejects_partial_duplicate_extra_and_malformed(self):
        line = '0 31 0 0 0 0'
        self.assertEqual(p.parse(line,1),[[0,31,0,0,0,0]])
        for text,count in (('',1),(line+'\n'+line,1),(line,2),
                (line+' 7',1),('0 31 0 0 0 1',1),('0 -1 0 0 0 0',1),
                ('0 4294967296 0 0 0 0',1),('0 31 0 0 0 0x0',1)):
            with self.assertRaises(ValueError): p.parse(text,count)

    def test_every_observed_value_and_event_is_required(self):
        case = (31,(0,0),((0,87,1,1,p.r.H1),(0,5,0,0,0)),0,2)
        expected = p.expected(case)
        for i in range(len(expected)):
            changed = copy.deepcopy(expected); changed[i] ^= 1
            with self.assertRaises(ValueError): p.compare(changed,expected)
        self.assertEqual(expected[0],0)
        self.assertEqual(expected[1],p.c.encode(p.r.NEG,31))
        self.assertEqual(expected[3],0)  # Export failure must leave candidate2 alone.


if __name__ == '__main__': unittest.main()
