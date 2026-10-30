"""Public oracle-sensitivity controls; no original bodies or private fixtures."""
import importlib.util
import json
from pathlib import Path
import random
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('cache_faults',ROOT/'scripts/recomp/check_cache_caller_faults.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
b=f.caller


class CacheCallerFaultTests(unittest.TestCase):
    def fixture(self):
        inputs=bytearray();expected=[]
        for n in range(64):
            regs,pages=b.caller_state(n,random.Random(n),{p:bytes(4096) for p in b.IMAGE_PAGES})
            inputs.extend(struct.pack('<8I',*(regs[r] for r in b.REGS)))
            inputs.extend(b''.join(bytes(pages[p]) for p in b.PAGES))
            final=bytearray(b''.join(bytes(pages[p]) for p in b.PAGES))
            def before(off):return struct.unpack_from('<I',pages[b.DATA_PAGES[1]],128+off)[0]
            def put(p,off,v):struct.pack_into('<I',final,b.PAGES.index(p)*4096+128+off,v)
            end=before(0x100)
            put(b.DATA_PAGES[1],0x1c8,17);put(b.DATA_PAGES[1],0x1cc,23)
            put(b.DATA_PAGES[1],0x108,end if end else before(0x108))
            values=[before(0xfc),18,23,(before(0x18)-before(0x1c)+end)&0xffffffff if end else 0xffffffff,
                    (before(0x104)-end)&0xffffffff if end and before(0x104) else 0]
            for off,v in zip(range(0x80,0x94,4),values):put(b.DATA_PAGES[3],off,v)
            out=[regs[r] for r in b.REGS];out[-1]+=4;out[0]=(values[-1]&0xffffff00)|int(values[0]!=0)
            expected.append(dict(case=n,regs=out,pages=final.hex()))
        return expected,bytes(inputs)

    def test_baseline_and_actual_observed_faults(self):
        expected,inputs=self.fixture()
        self.assertTrue(f.assess('\n'.join(map(json.dumps,expected)),expected,inputs,'valid')['strict_reference_match'])
        for mode in ('cleanup','slot-order'):
            rows=json.loads(json.dumps(expected))
            for row in rows:
                if mode=='cleanup':row['regs'][-1]-=4
                else:
                    data=bytearray.fromhex(row['pages']);i=b.PAGES.index(b.DATA_PAGES[3])*4096+256
                    data[i:i+4],data[i+4:i+8]=data[i+4:i+8],data[i:i+4]
                    row['pages']=data.hex()
            result=f.assess('\n'.join(map(json.dumps,rows)),expected,inputs,mode)
            self.assertEqual(result['differing_cases'],64)
            self.assertEqual(result['poststate_rejections'],64)

    def test_no_fault_or_failed_execution_cannot_count_as_kill(self):
        expected,inputs=self.fixture();text='\n'.join(map(json.dumps,expected))
        with self.assertRaises(ValueError):f.assess(text,expected,inputs,'cleanup')
        with self.assertRaises(ValueError):f.assess(text,expected,inputs[:-1],'valid')
        for bad in ('', '\n'.join(json.dumps(dict(case=n,rejected=True)) for n in range(64)),
                    text.replace('"case": 0','"case": 0, "case": 0',1)):
            with self.subTest(bad=bad[:40]),self.assertRaises(ValueError):f.assess(bad,expected,inputs,'cleanup')

    def test_bridge_faults_are_exact_and_bounded(self):
        text=b.BRIDGE.read_text()
        self.assertEqual(f.bridge_source(text,'valid'),text)
        for mode in ('slot-order','cleanup'):
            self.assertNotEqual(f.bridge_source(text,mode),text)
            with self.assertRaises(ValueError):f.bridge_source('',mode)
            with self.assertRaises(ValueError):f.bridge_source(text+text,mode)
        with self.assertRaises(ValueError):f.bridge_source(text,'unknown')


if __name__=='__main__':unittest.main()
