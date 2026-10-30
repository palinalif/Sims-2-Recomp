"""Public full-state hot ABI checks; no private inputs required."""
import contextlib
import copy
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_encoded_hot_abi as p

class EncodedHotAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native=os.environ.get('TS2_GUEST_ENCODED_HOT_ABI_PROBE','build/host/ts2_guest_encoded_hot_abi_probe')
        cls.runner=os.environ.get('TS2_GUEST_ENCODED_HOT_ABI_RUNNER')
        cls.cases=p.cases(); cls.states=p.run(cls.cases,cls.native,cls.runner)

    def test_full_state_and_immutable_pages(self):
        for case,state in zip(self.cases,self.states):
            with self.subTest(case=case): p.verify(state,case)

    def test_cold_bounds_unmapped_and_overlap_reject_before_mutation(self):
        for case,mode,sp in [((31,0,33,7),0,None),((0,1,64,0),0,None),
                ((0,1,p.r.NEG,0),0,None),*((self.cases[0],i,None) for i in (1,2,3)),
                *((self.cases[0],0,s) for s in (0,8,0xfffffffc,0x80000000))]:
            with self.subTest(case=case,mode=mode,sp=sp):
                failure,state,_=p.run([case],self.native,self.runner,mode,sp)[0]
                self.assertEqual(failure,1)
                regs,stack=p.p.inputs(case[2],case[3]) if case[2]<64 else self._invalid_inputs(case)
                if sp is not None: regs[7]=sp
                self.assertEqual(state,dict(registers=regs,flags=0x602&p.p.MASK,stack=bytes(stack)))

    @staticmethod
    def _invalid_inputs(case):
        regs,stack=p.p.inputs(0,case[3]); struct.pack_into('<I',stack,2052,case[2])
        return regs,stack

    def test_every_observed_component_mutation_rejects(self):
        case=self.cases[0]; state=self.states[0]
        for i in range(8):
            wrong=copy.deepcopy(state); wrong[1]['registers'][i]^=1
            with self.assertRaises(ValueError): p.verify(wrong,case)
        for bit in (1,4,64,128,1024,2048):
            wrong=copy.deepcopy(state); wrong[1]['flags']^=bit
            with self.assertRaises(ValueError): p.verify(wrong,case)
        for i in (0,2036,2048,4095):
            wrong=copy.deepcopy(state); stack=bytearray(wrong[1]['stack']); stack[i]^=1; wrong[1]['stack']=bytes(stack)
            with self.assertRaises(ValueError): p.verify(wrong,case)
        for i in (0,336,1024,2047):
            wrong=copy.deepcopy(state); wrong[2][i]^=1
            with self.assertRaises(ValueError): p.verify(wrong,case)
        with self.assertRaises(ValueError): p.verify((1,state[1],state[2]),case)

    def test_strict_parser(self):
        failure,state,pages=self.states[0]
        valid=' '.join(map(str,[failure,*state['registers'],state['flags'],
                        *struct.unpack('<1024I',state['stack']),*pages]))
        self.assertEqual(p.parse(valid,1),[self.states[0]])
        for text in (valid+' 0',valid+'\n'+valid,' '.join(valid.split()[:-1]),
                     valid+'\n\n',valid.replace(' ',' x ',1),'','-1','4294967296','x'):
            with self.assertRaises(ValueError): p.parse(text,1)

    def test_private_wrong_pin_is_readonly_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/'private.bin'; image.write_bytes(b'private fixture')
            out,err=io.StringIO(),io.StringIO()
            args=['--private-x86','--native',self.native]
            if self.runner: args.extend(['--runner',self.runner])
            with patch.object(p.r,'IMAGE',image),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(p.main(args),2)
            self.assertEqual(out.getvalue(),''); self.assertNotIn(str(image),err.getvalue())
            self.assertEqual(image.read_bytes(),b'private fixture')

if __name__=='__main__': unittest.main()
