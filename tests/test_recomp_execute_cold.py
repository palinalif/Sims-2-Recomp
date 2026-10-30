"""Public cold transport tests: authored fixtures only, never original bodies."""
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

PATH=Path(__file__).resolve().parents[1]/'scripts/recomp/execute_cold_composed.py'
spec=importlib.util.spec_from_file_location('execute_cold',PATH)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


class ExecuteColdTests(unittest.TestCase):
    def test_reference_inputs_and_existing_oracle(self):
        data,expected=b.reference()
        self.assertEqual(len(data),b.COUNT*b.RECORD)
        for n,row in enumerate(expected):
            w=struct.unpack_from('<27I',data,n*b.RECORD)
            wanted=b.oracle.oracle(w[22],w[8:10],(w[10:15],w[15:20]),w[23],w[20])
            self.assertEqual({k:v for k,v in row.items() if k!='hot'},dict(case=n,eax=wanted['eax'],esp=wanted['esp'],modules=wanted['modules'],cache=wanted['cache'],events=[list(e) for e in wanted['events']]))
            self.assertEqual(struct.unpack_from('<I',data,n*b.RECORD+108+0x810)[0],b.oracle.r.ARRAY+4*w[20])
        self.assertEqual(b.compare('\n'.join(map(json.dumps,expected)),expected)['matched'],b.COUNT)
        self.assertEqual({c[0]&31 for c in b.cases()},set(range(32)))

    def test_every_observation_mutation_rejects(self):
        _,expected=b.reference();event_case=next(n for n,e in enumerate(expected) if e['events'])
        for key in ('case','eax','esp','modules','cache','events'):
            rows=copy.deepcopy(expected);r=rows[event_case]
            if key=='modules':r[key][0]^=1
            elif key=='events':r[key][0][2]^=1
            else:r[key]^=1
            with self.subTest(key=key),self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        for component in (0,1,3):
            rows=copy.deepcopy(expected);e=rows[event_case]['events'][0]
            if component==0:e[0]='unknown'
            elif component==1:e[1][0]^=1
            else:e[3]^=1
            with self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)

    def test_hot_oracle_and_every_observation_mutation(self):
        data,expected=b.reference()
        for n,row in enumerate(expected):
            w=struct.unpack_from('<27I',data,n*b.RECORD)
            hot=b.oracle.c.oracle(row['eax'] or b.oracle.r.NEG,w[22],w[24],0 if n<1080 else (7 if (n-1080)//2%2 else 0))
            stack=bytearray(hot['stack'])
            struct.pack_into('<I',stack,0x810,b.oracle.r.ARRAY+4*w[20])
            self.assertEqual(row['hot'],dict(registers=hot['registers'],stack=stack.hex()))
        for register in range(8):
            rows=copy.deepcopy(expected);rows[0]['hot']['registers'][register]^=1
            with self.subTest(register=register),self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        for offset in (0,0x7f4,0x800,0xfff):
            rows=copy.deepcopy(expected);s=bytearray.fromhex(rows[0]['hot']['stack']);s[offset]^=1
            rows[0]['hot']['stack']=s.hex()
            with self.subTest(offset=offset),self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        for hot in ({},dict(registers=[0]*7,stack='00'*4096),dict(registers=[0]*8,stack='GG'*4096)):
            rows=copy.deepcopy(expected);rows[0]['hot']=hot
            with self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)

    def test_strict_transport_and_verbatim_assembly(self):
        _,expected=b.reference();text='\n'.join(map(json.dumps,expected))
        for bad in ('',text+'\n'+json.dumps(expected[-1]),'\n'.join(text.splitlines()[1:]),
                    text.replace('"case": 0','"case": false',1),text.replace('"case": 0','"case": 0, "case": 0',1)):
            with self.assertRaises((ValueError,json.JSONDecodeError)):b.compare(bad,expected)
        rows=copy.deepcopy(expected);rows[0]['hot']['registers'][0]=False
        with self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        a='void authored_module(void) {}';c='void authored_resolver(void) {}'
        source=b.assemble(a,c);self.assertEqual(source.count(a),1);self.assertEqual(source.count(c),1)
        for x,y in (('',c),(a,''),('@MODULE@',c),(a,'@RESOLVER@')):
            with self.assertRaises(ValueError):b.assemble(x,y)

    def test_private_output_and_sanitized_cli(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(b,'ROOT',Path(tmp)):
            root=Path(tmp);private=root/'work/recomp-bench';private.mkdir(parents=True)
            outside=root/'outside';outside.mkdir();(private/'link').symlink_to(outside)
            for p in (outside/'out',private/'link/out'):
                with self.assertRaises(ValueError):b.run(p,root/'a',root/'b')
        import contextlib,io
        with patch('sys.argv',['run','--module-index','private','--resolver-index','private','--output','private']),patch.object(b,'run',side_effect=ValueError('secret')):
            with contextlib.redirect_stderr(io.StringIO()) as out:self.assertEqual(b.main(),1)
            self.assertNotIn('secret',out.getvalue())

    def test_authored_native_endpoints_guards_and_recovery(self):
        cc=shutil.which('cc');self.assertIsNotNone(cc,'real compiler required')
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
        module='''static void startup_847DA1(void) {
    PUSH32(esp,0x800);PUSH32(esp,0);PUSH32(esp,0xC1234567u);
    RECOMP_ICALL(0xC7000000u);g_esp+=4;
}'''
        resolver='''static void startup_847E6C(void) {
    uint32_t mode=g_eax;
    if(hot_active) {
        if(mode==10) MEM32(0xC2345000u);
        if(mode==11) MEM32(0xA0E09964u);
        if(mode==12) MEM32(0xA0D9A2D4u);
        if(mode==13) RECOMP_ICALL(0xA0847DA1u);
        if(mode==14) RECOMP_ICALL(0xA082F3ECu);
        if(mode==15) MEM32(0xA10E025Cu);
        if(mode==16) MEM32(0xA10E02B0u+4*index_word)^=1;
        if(mode==17) MEM32(0xA104F540u)^=1;
        g_esp+=4;return;
    }
    if(mode==1) MEM32(0xA104F540u)^=1;
    if(mode==2) MEM32(0xA10E0000u)^=1;
    if(mode==3) MEM32(0xB80007BCu)^=1;
    if(mode==4) g_ebx++;
    if(mode==5) RECOMP_ICALL(0xC7000004u);
    if(mode==6) RECOMP_ITAIL(0xC7000000u);
    if(mode==7) RECOMP_ICALL(0xA0847DA1u);
    if(mode==8) {
        PUSH32(esp,0xC3456000u);PUSH32(esp,0x80000000u);
        RECOMP_ICALL(0xC7000020u);
    }
    if(mode==9) {
        PUSH32(esp,0x80000000u);RECOMP_ICALL(0xA082F3ECu);g_esp+=4;
    }
    g_esp+=4;
}'''
        data,_=b.reference();base=bytearray(data[:b.RECORD]);struct.pack_into('<I',base,23*4,0x81234567)
        queries=[]
        for mode in range(18):
            q=base.copy();struct.pack_into('<I',q,0,mode);queries.append(bytes(q))
        for word,value in ((7,b.oracle.r.SP-1),(20,3),(24,64),(24,11),(23,0xFFFFFFFF),(26,2)):
            q=base.copy();struct.pack_into('<I',q,0,0);struct.pack_into('<I',q,word*4,value);queries.append(bytes(q))
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'recomp_types.h').write_text(header);(d/'test.c').write_text(b.assemble(module,resolver))
            p=subprocess.run([cc,'-std=c11','-I'+tmp,d/'test.c','-o',d/'test'],capture_output=True,timeout=60)
            self.assertEqual(p.returncode,0,p.stderr.decode())
            p=subprocess.run([d/'test'],input=b''.join(queries)+queries[0],capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0)
            rows=[json.loads(s) for s in p.stdout.splitlines()];self.assertEqual(len(rows),25)
            for n in range(1,7):self.assertEqual(rows[n],dict(case=n,rejected=True))
            for n in range(10,24):self.assertEqual(rows[n],dict(case=n,rejected=True))
            for n in (0,24):self.assertEqual(rows[n]['eax'],0)
            self.assertEqual(rows[7]['events'][0][0],'load')
            self.assertEqual(rows[8]['eax'],0x81234567)
            self.assertEqual(rows[8]['events'][0][0],'export')
            self.assertEqual(rows[9]['eax'],b.oracle.c.encode(0x80000000,struct.unpack_from('<I',base,22*4)[0]))
            self.assertEqual(rows[9]['events'],[])


if __name__=='__main__':unittest.main()
