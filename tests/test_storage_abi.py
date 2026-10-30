"""Public native integer ABI model controls; private PE not needed."""
import contextlib
import copy
import io
import os
import struct
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_storage_abi as p

class StorageAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native=os.environ.get('TS2_GUEST_STORAGE_ABI_PROBE','build/host/ts2_guest_storage_abi_probe')
        cls.runner=os.environ.get('TS2_GUEST_STORAGE_ABI_RUNNER')
        cls.cases=p.cases()
        cls.states=p.run(cls.cases,cls.native,cls.runner)

    def test_full_state_and_endpoint_frames_against_oracle(self):
        for case,state in zip(self.cases,self.states):
            with self.subTest(case=case): p.verify(state,case)

    def test_cleanup_and_missing_endpoints_fail_without_fallback(self):
        for wrong in (1,2,3):
            states=p.run(self.cases[:1]+self.cases[128:129],self.native,self.runner,wrong)
            for failure,state in states:
                self.assertEqual(failure,1)
                if wrong in (2,3):
                    self.assertLessEqual(len(state['events']),1)
        case=self.cases[128]
        failure,state=p.run([case],self.native,self.runner,4)[0]
        self.assertEqual(failure,1)
        self.assertEqual([e[0] for e in state['events']],['resolve'])
        for wrong,case,events in ((5,self.cases[128],['resolve','guard']),
                                  (6,self.cases[0],['resolve']),
                                  (7,self.cases[128],['resolve','guard']),
                                  (8,self.cases[128],['resolve','guard','fls'])):
            failure,state=p.run([case],self.native,self.runner,wrong)[0]
            self.assertEqual(failure,1)
            self.assertEqual([e[0] for e in state['events']],events)
        for sp in (0,24,0xfffffffc,0x80000000):
            failure,state=p.run([self.cases[0]],self.native,self.runner,sp=sp)[0]
            self.assertEqual(failure,1)
            self.assertEqual(state['events'],[])

    def test_every_observed_component_mutation_rejects(self):
        case=self.cases[128]; failure,state=self.states[128]
        for i in range(8):
            wrong=copy.deepcopy(state); wrong['registers'][i]^=1
            with self.assertRaises(ValueError): p.verify((failure,wrong),case)
        for bit in (1,4,64,128,1024,2048):
            wrong=copy.deepcopy(state); wrong['flags']^=bit
            with self.assertRaises(ValueError): p.verify((failure,wrong),case)
        for i in (0,2048-28,2048,4095):
            wrong=copy.deepcopy(state); b=bytearray(wrong['stack']); b[i]^=1; wrong['stack']=bytes(b)
            with self.assertRaises(ValueError): p.verify((failure,wrong),case)
        for i,e in enumerate(state['events']):
            for j in range(len(e)):
                wrong=copy.deepcopy(state); event=list(wrong['events'][i])
                event[j]=([v^1 for v in event[j]] or [1]) if j==1 else ('bad' if j==0 else event[j]^1)
                wrong['events'][i]=tuple(event)
                with self.assertRaises(ValueError): p.verify((failure,wrong),case)
        with self.assertRaises(ValueError): p.verify((1,state),case)

    def test_private_pin_failure_is_readonly_and_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            image=Path(tmp)/'private.bin'; image.write_bytes(b'private fixture')
            out,err=io.StringIO(),io.StringIO()
            args=['--private-x86','--native',self.native]
            if self.runner: args.extend(['--runner',self.runner])
            with patch.object(p.r,'IMAGE',image),contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
                self.assertEqual(p.main(args),2)
            self.assertEqual(out.getvalue(),'')
            self.assertNotIn(str(image),err.getvalue())
            self.assertNotIn('private fixture',err.getvalue())
            self.assertEqual(image.read_bytes(),b'private fixture')

    def test_strict_transport(self):
        _,s=self.states[128]
        v=[0,*s['registers'],s['flags'],*struct.unpack('<1024I',s['stack']),len(s['events'])]
        for kind,args,ret,sp,ecx in s['events']:
            e=[{'resolve':1,'guard':2,'fls':3,'tls':4}[kind],ret,sp,ecx,*args]
            v.extend([len(e),*e])
        valid=' '.join(map(str,v))
        self.assertEqual(p.parse(valid,1),[self.states[128]])
        malformed=[valid+' 0',valid+'\n'+valid,' '.join(valid.split()[:-1]),
                   valid.replace(' ', ' x ',1),valid+'\n\n']
        for text,count in [(x,1) for x in malformed]+[('',1),('0',1),('0\n0',1),('-1',1),('4294967296',1),('x',1)]:
            with self.subTest(length=len(text)),self.assertRaises(ValueError): p.parse(text,count)

if __name__=='__main__': unittest.main()
