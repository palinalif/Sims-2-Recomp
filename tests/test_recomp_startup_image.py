"""Scoped startup image controls; authored inputs only, no private fixtures needed."""
import copy
import hashlib
from unittest.mock import patch
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from test_analysis import synthetic_pe
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/recomp'))
import verify_startup_image as bench


class StartupImageTests(unittest.TestCase):
    def test_missing_private_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=bench.ROOT
            try:
                bench.ROOT=Path(tmp)
                out=bench.ROOT/'work/recomp-bench/missing'
                with self.assertRaises(OSError): bench.run(out)
                row=json.loads((out/'result.json').read_text())
                self.assertFalse(row['success'])
                self.assertFalse(row['arm64_executed'])
            finally: bench.ROOT=old

    def test_body_pin_and_candidate_scope(self):
        for bodies in ({}, {0x8258A9:'authored',0x82585C:'authored'}):
            with self.assertRaises(ValueError): bench.assemble(bodies,[])

    def test_entry_assembly_preserves_bodies_and_nonlocal_stop(self):
        bodies={r:'void public_%x(void) {}'%r for r in (*bench.BODY_SHA,0x8248A3)}
        pins={r:hashlib.sha256(body.encode()).hexdigest() for r,body in bodies.items()}
        rows=[dict(caller=0xA08248A3,target=0xA08258A9,
                   return_va=0xA08248A8,slot=False)]
        # Test-only authored pins; production pins are never changed on disk.
        with patch.dict(bench.BODY_SHA,{r:pins[r] for r in bench.BODY_SHA}), \
             patch.object(bench,'ENTRY_SHA',pins[0x8248A3]):
            text=bench.assemble(bodies,rows,entry=True)
            for body in bodies.values(): self.assertEqual(text.count(body),1)
            self.assertTrue(text.startswith('#define ENTRY_BOUNDARY 1'))
            self.assertIn('ts2_startup_stop(0xA0824727u,s);',text)
            self.assertNotIn('longjmp(',text)
            self.assertIn('\\\"eip\\\":%u',text)
            self.assertIn('const uint32_t stop=ts2_startup_observe_entry(s);',text)
            self.assertIn('static void initial_dispatch(void);',text)
            self.assertEqual(text.count('ts2_startup_observe_entry(s)'),2)
            with self.assertRaises(ValueError): bench.assemble(bodies,rows)

    def test_comparison_requires_full_stack_globals_and_components(self):
        self.check_comparison(False)

    def test_entry_comparison_requires_stop_pc_and_full_state(self):
        self.check_comparison(True)

    def check_comparison(self,entry):
        from reference_startup import cases,oracle,entry_oracle
        refs=[]; rows=[]
        for n,case in enumerate(cases()):
            state=(entry_oracle if entry else oracle)(case)
            saved=dict(state)
            for key in ('stack','data'): saved[key]=saved[key].hex()
            refs.append(dict(case=case,state=saved))
            expected=dict(saved)
            data=state['data']
            expected.pop('data')
            expected['globals']=[struct.unpack_from('<I',data,o)[0] for o in (0x540,0x580)]
            rows.append(dict(case=n,state=expected))
        stream=lambda data:'\n'.join(json.dumps(r) for r in data)
        compare=lambda text:bench.compare_stream(text,refs,entry=entry)
        self.assertEqual(compare(stream(rows)),320)
        for component in rows[0]['state']:
            bad=copy.deepcopy(rows)
            value=bad[0]['state'][component]
            if isinstance(value,list):
                if value: value[0]^=1
                else: value.append(0)
            elif isinstance(value,str):
                bad[0]['state'][component]=('00' if value[:2]!='00' else '01')+value[2:]
            else: bad[0]['state'][component]^=1
            with self.assertRaises(ValueError): compare(stream(bad))
        for bad in (rows[:-1], rows+[rows[-1]], [dict(case=0,rejected='unmapped')]+rows[1:]):
            with self.assertRaises(ValueError): compare(stream(bad))
        for value in (False, 0.0):
            bad=copy.deepcopy(rows); bad[0]['case']=value
            with self.assertRaises(ValueError): compare(stream(bad))
        duplicate=stream(rows).replace('"case": 0,','"case": 0, "case": 0,',1)
        with self.assertRaises(ValueError): compare(duplicate)

    def test_actual_adapter_authored_memory_dispatch_and_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp); exe=directory/'probe'
            opts=os.environ.get('TS2_IMAGE_TEST_TARGET','').split()
            compiler=('zig-cxx' if opts else os.environ.get('CXX') or
                      shutil.which('c++') or shutil.which('clang++') or 'g++')
            argv=[compiler,*opts,'-std=c++20','-O0','-I'+str(ROOT/'native/include'),
                  '-I'+str(ROOT/'scripts/recomp'),str(ROOT/'scripts/recomp/startup_image.cpp'),
                  str(ROOT/'tests/fixtures/startup_image_authored.cpp'),
                  *[str(ROOT/'native/src'/name) for name in
                    ('guest_image.cpp','guest_memory.cpp','guest_dispatch.cpp')],'-o',str(exe)]
            built=subprocess.run(argv,capture_output=True,timeout=120)
            self.assertEqual(built.returncode,0,built.stderr.decode())
            data=bytearray(synthetic_pe())
            struct.pack_into('<I',data,0x98+28,0xa0000000)
            struct.pack_into('<I',data,0x98+56,0x1050000)
            image=directory/'authored.bin'; image.write_bytes(data)
            runner=os.environ.get('TS2_IMAGE_TEST_RUNNER')
            prefix=[runner] if runner else []
            for args,expected in (([str(image)],0),([],1)):
                proc=subprocess.run([*prefix,str(exe),*args],capture_output=True,timeout=60)
                self.assertEqual(proc.returncode,expected,proc.stderr.decode())
            self.assertEqual(image.read_bytes(),data)


if __name__=='__main__': unittest.main()
