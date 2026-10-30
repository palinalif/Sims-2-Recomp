"""Public transport/comparator tests: no original game bytes or lifted bodies."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'scripts/recomp/execute_module_acquisition.py'
spec=importlib.util.spec_from_file_location('execute_module',PATH)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


class ExecuteModuleTests(unittest.TestCase):
    def test_reference_matches_existing_oracle_inputs(self):
        data,expected=b.reference()
        self.assertEqual(len(data),1944*92)
        self.assertEqual(len(expected),1944)
        for n,row in enumerate(expected):
            words=struct.unpack_from('<23I',data,n*92)
            wanted=b.oracle.oracle(words[8:10],(words[10:15],words[15:20]),words[20])
            self.assertEqual(row['eax'],wanted['eax'])
            self.assertEqual(row['modules'],wanted['modules'])
            self.assertEqual(row['events'],[list(e) for e in wanted['events']])
        self.assertEqual(b.compare('\n'.join(map(json.dumps,expected)),expected)['matched'],1944)

    def test_every_observed_component_mutation_rejects(self):
        _,expected=b.reference()
        event_case=next(n for n,e in enumerate(expected) if e['events'])
        for key in ('case','eax','esp','modules','events'):
            rows=copy.deepcopy(expected);r=rows[event_case]
            if key=='modules':r[key][0]^=1
            elif key=='events':r[key][0][2]^=1
            else:r[key]^=1
            with self.subTest(key=key),self.assertRaises(ValueError):
                b.compare('\n'.join(map(json.dumps,rows)),expected)
        for index in (0,1,3):
            rows=copy.deepcopy(expected);e=rows[event_case]['events'][0]
            if index==0:e[0]='error'
            elif index==1:e[1][0]^=1
            else:e[3]^=1
            with self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)

    def test_strict_transport(self):
        _,expected=b.reference();text='\n'.join(map(json.dumps,expected))
        for bad in ('',text+'\n'+json.dumps(expected[-1]),'\n'.join(text.splitlines()[1:]),
                    text.replace('"eax": 0','"eax": false',1),
                    text.replace('"case": 0','"case": 0, "case": 0',1),
                    text.replace('"esp": 3087009796','"esp": -1',1)):
            if bad==text:continue
            with self.assertRaises((ValueError,json.JSONDecodeError)):b.compare(bad,expected)

    def test_verbatim_once_private_output_and_cli(self):
        body='void authored(void) { /* independent fixture */ }'
        self.assertEqual(b.assemble(body).count(body),1)
        for bad in ('','@BODY@'):
            with self.assertRaises(ValueError):b.assemble(bad)
        with tempfile.TemporaryDirectory() as tmp,patch.object(b,'ROOT',Path(tmp)):
            root=Path(tmp);private=root/'work/recomp-bench';private.mkdir(parents=True)
            outside=root/'outside';outside.mkdir();(private/'link').symlink_to(outside)
            for p in (outside/'out',private/'link/out'):
                with self.assertRaises(ValueError):b.run(p,root/'index')
        import contextlib,io
        with patch('sys.argv',['run','--index','private','--output','private']),patch.object(b,'run',side_effect=ValueError('secret')):
            with contextlib.redirect_stderr(io.StringIO()) as out:self.assertEqual(b.main(),1)
            self.assertNotIn('secret',out.getvalue())

    def test_authored_native_guard_recovery_and_endpoints(self):
        cc=shutil.which('cc');self.assertIsNotNone(cc,'real compiler required')
        # Public minimal header models ONLY macros needed by the authored fixture.
        header='''#include <stdint.h>
#include <stdio.h>
#include <string.h>
uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
#define esp g_esp
#define PUSH32(sp,v) do { (sp)-=4;MEM32(sp)=(v); } while(0)
#define RECOMP_FLAGS_OUT() ((void)0)
#define RECOMP_REGS_OUT() ((void)0)
#define RECOMP_REGS_IN() ((void)0)
'''
        body='''static void startup_847DA1(void) {
    if(g_eax==1) { MEM32(0xB80007DCu)=99;g_eax=0;g_esp+=4;return; }
    if(g_eax==2) { MEM32(0xB80007D8u)=99;g_eax=0;g_esp+=4;return; }
    if(g_eax==3) { MEM32(0xA10E0000u)=99;g_eax=0;g_esp+=4;return; }
    if(g_eax==4) { MEM32(0xA0E09964u)=99;g_eax=0;g_esp+=4;return; }
    if(g_eax==5) { g_ebx++;g_eax=0;g_esp+=4;return; }
    if(g_eax==6) { RECOMP_ICALL(0xC7000004u);return; }
    if(g_eax==7) { RECOMP_ITAIL(0xC7000000u);return; }
    if(g_eax==8) { (void)MEM32(0xB8001000u);return; }
    if(g_eax==9) {
        PUSH32(esp,0x800);PUSH32(esp,0);PUSH32(esp,0xC1234567u);
        RECOMP_ICALL(0xC7000000u);g_esp+=4;return;
    }
    g_eax=0;g_esp+=4;
}'''
        data,_=b.reference();base=list(struct.unpack_from('<23I',data));base[10]=123
        queries=[]
        for kind in range(10):
            words=base.copy();words[0]=kind;queries.append(struct.pack('<23I',*words))
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'recomp_types.h').write_text(header);(d/'test.c').write_text(b.assemble(body))
            p=subprocess.run([cc,'-std=c11','-I'+tmp,d/'test.c','-o',d/'test'],capture_output=True,timeout=60)
            self.assertEqual(p.returncode,0,p.stderr.decode())
            p=subprocess.run([d/'test'],input=b''.join(queries)+queries[0],capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0)
            rows=[json.loads(s) for s in p.stdout.splitlines()];self.assertEqual(len(rows),11)
            for n in range(2,9):self.assertEqual(rows[n],dict(case=n,rejected=True))
            for n in (0,1,10):self.assertEqual(rows[n]['eax'],0)
            self.assertEqual(rows[9]['eax'],123)
            self.assertEqual(rows[9]['events'],[['load',[0xC1234567,0,0x800],0x847DE5,b.oracle.r.SP-16]])


if __name__=='__main__':unittest.main()
