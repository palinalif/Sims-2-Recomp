"""Public transport tests use authored bodies only; never original game code."""
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

PATH=Path(__file__).resolve().parents[1]/'scripts/recomp/execute_storage_cold.py'
spec=importlib.util.spec_from_file_location('execute_storage_cold',PATH)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


class StorageColdTests(unittest.TestCase):
    def test_reference_protocol_and_independent_oracle(self):
        data,rows=b.reference()
        self.assertEqual(len(data),b.COUNT*b.RECORD)
        for n,(case,clobber) in enumerate(b.cases()):
            cookie,modules,responses,export,result,index,salt=case
            words=struct.unpack_from('<28I',data,n*b.RECORD)
            regs,stack=b.oracle.query.free.inputs(index,salt)
            self.assertEqual(words[:8],tuple(regs))
            self.assertEqual(words[8:],(*modules,*responses[0],*responses[1],result,b.oracle.LOAD,cookie,export,0,b.oracle.EXPORT,4,int(clobber)))
            self.assertEqual(data[n*b.RECORD+112:(n+1)*b.RECORD],bytes(stack))
            wanted=b.oracle.oracle(cookie,modules,responses,export,result,index)
            self.assertEqual({k:v for k,v in rows[n].items() if k!='hot'},dict(case=n,**{k:([list(e) for e in v] if k=='events' else v) for k,v in wanted.items()}))
        self.assertEqual(b.compare('\n'.join(map(json.dumps,rows)),rows)['matched'],2528)
        self.assertEqual({case[0]&31 for case in b.oracle.cases()},set(range(32)))
        self.assertEqual({e['hot']['events'][-1]['kind'] for e in rows},{'fls','tls'})
        for row,(case,clobber) in zip(rows,b.cases()):
            cookie,_,_,_,result,index,salt=case
            value=b.hot.hot.rotate(row['cache']^cookie,cookie&31)
            wanted=b.hot.oracle(value,cookie,result,index,salt,clobber=clobber)
            self.assertEqual(row['hot']['registers'],wanted['registers'])
            self.assertEqual(row['hot']['stack'],wanted['stack'].hex())

    def test_all_count_storage_clobber_cross_product(self):
        sweep=list(b.cases());self.assertEqual(len(sweep),b.COUNT)
        self.assertEqual([c for c,clobber in sweep[:1504]],list(b.oracle.cases()))
        seen={(c[0]&31,c[3],c[4],c[5],clobber) for c,clobber in sweep[1504:]}
        import itertools
        self.assertEqual(seen,set(itertools.product(range(32),(0,b.oracle.query.FLS),
            (0,1,0x80000000,b.oracle.r.NEG),(0,b.oracle.r.NEG),(False,True))))
        self.assertEqual(len(seen),1024)

    def test_every_observed_field_and_event_rejects(self):
        _,expected=b.reference()
        for key in ('case','eax','esp','cache','modules'):
            rows=copy.deepcopy(expected)
            if key=='modules':rows[0][key][0]^=1
            else:rows[0][key]^=1
            with self.subTest(key=key),self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        for kind in ('resolve','load','error','compare','export','guard','fls','tls'):
            n=next(n for n,r in enumerate(expected) if any(e[0]==kind for e in r['events']))
            for component in range(4):
                rows=copy.deepcopy(expected);e=next(e for e in rows[n]['events'] if e[0]==kind)
                if component==0:e[0]='unknown'
                elif component==1:
                    if e[1]:e[1][0]^=1
                    else:e[1].append(1)
                else:e[component]^=1
                with self.subTest(kind=kind,component=component),self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)

    def test_hot_observation_and_transport_mutations_reject(self):
        _,expected=b.reference()
        def reject(rows):
            with self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        for component in range(8):
            rows=copy.deepcopy(expected);rows[0]['hot']['registers'][component]^=1;reject(rows)
        for position in (0,4094,4096,8190):
            rows=copy.deepcopy(expected);s=rows[0]['hot']['stack']
            rows[0]['hot']['stack']=s[:position]+('00' if s[position:position+2]!='00' else 'ff')+s[position+2:];reject(rows)
        for kind in ('resolve','guard','fls','tls'):
            n=next(n for n,r in enumerate(expected) if any(e['kind']==kind for e in r['hot']['events']))
            for field in ('kind','args','returnRva','registers'):
                rows=copy.deepcopy(expected);e=next(e for e in rows[n]['hot']['events'] if e['kind']==kind)
                if field=='kind':e[field]='unknown'
                elif field=='returnRva':e[field]^=1
                elif field=='args':e[field]=[False] if not e[field] else [False,*e[field][1:]]
                else:e[field][0]=False
                reject(rows)
        # An endpoint that silently ignores clobber mode must fail both branches.
        for kind in ('fls','tls'):
            n=next(n for n,(case,clobber) in enumerate(b.cases())
                if clobber and expected[n]['hot']['events'][-1]['kind']==kind)
            rows=copy.deepcopy(expected)
            rows[n]['hot']['registers'][2:4]=expected[n-1]['hot']['registers'][2:4]
            reject(rows)
        for field,value in (('registers',[False]*8),('stack','g'*8192),('events',[])):
            rows=copy.deepcopy(expected);rows[0]['hot'][field]=value;reject(rows)

    def test_strict_transport_and_verbatim_assembly(self):
        _,expected=b.reference();text='\n'.join(map(json.dumps,expected))
        for bad in ('',text+'\n'+json.dumps(expected[0]),'\n'.join(text.splitlines()[1:]),text.replace('"case": 0','"case": false',1),text.replace('"case": 0','"case": 0, "case": 0',1)):
            with self.assertRaises(ValueError):b.compare(bad,expected)
        for value in (False,-1,2**32):
            rows=copy.deepcopy(expected);rows[0]['events'][0][1][0]=value
            with self.assertRaises(ValueError):b.compare('\n'.join(map(json.dumps,rows)),expected)
        bodies=('void authored_module(void) {}','void authored_resolver(void) {}','void authored_selector(void) {}')
        source=b.assemble(*bodies)
        for body in bodies:self.assertEqual(source.count(body),1)
        for bad in ('','@MODULE@','@SELECTOR@','@RESOLVER@'):
            with self.assertRaises(ValueError):b.assemble(bad,*bodies[1:])

    def test_private_output_and_sanitized_failure(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(b,'ROOT',Path(tmp)):
            root=Path(tmp);private=root/'work/recomp-bench';private.mkdir(parents=True)
            outside=root/'outside';outside.mkdir();(private/'link').symlink_to(outside)
            for p in (outside/'out',private/'link/out'):
                with self.assertRaises(ValueError):b.run(p,root/'a',root/'b',root/'c')
        import contextlib,io
        argv=['run','--module-index','private','--resolver-index','private','--selector-index','private','--output','private']
        with patch('sys.argv',argv),patch.object(b,'run',side_effect=ValueError('secret')):
            with contextlib.redirect_stderr(io.StringIO()) as out:self.assertEqual(b.main(),1)
            self.assertNotIn('secret',out.getvalue())

    def test_authored_native_nested_endpoints_rejection_and_recovery(self):
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
    if(g_eax==1) MEM32(0xA104F540u)^=1;
    if(g_eax==2) MEM32(0xA10E0000u)^=1;
    if(g_eax==3) MEM32(0xB80007A0u)^=1;
    if(g_eax==4) g_ebx++;
    if(g_eax==5) RECOMP_ICALL(0xC7000084u);
    if(g_eax==6) RECOMP_ITAIL(0xC7000010u);
    g_esp+=4;
}'''
        resolver='''static void startup_847E6C(void) {
    if(hot_active) {
        require_contract(MEM32(0xA10E0334u)!=cookie_page[0x540/4]);
        if(g_eax==7) (void)MEM32(0xA0E09964u);
        if(g_eax==8) RECOMP_ICALL(0xC7000080u);
        if(g_eax==9) (void)MEM32(0xA10E025Cu);
        if(g_eax==10) MEM32(0xA104F540u)^=1;
        if(g_eax==11) (void)MEM32(0xA0E0A05Cu);
    } else {
        RECOMP_ICALL(0xA0847DA1u);MEM32(0xA10E0334u)^=1;
    }
    g_eax=export_value;g_esp+=4;
}'''
        selector='''static void storage_selector(void) {
    uint32_t index=MEM32(g_esp+4);
    PUSH32(esp,0xA0E0A064u);PUSH32(esp,0xA0E0A05Cu);PUSH32(esp,0xA0E06E5Cu);PUSH32(esp,33);
    RECOMP_ICALL(0xA0847E6Cu);g_esp+=16;
    if(g_eax) {
        g_ecx=g_eax;RECOMP_ICALL(0xC7000000u);
        PUSH32(esp,index);RECOMP_ICALL(0xC7000020u);g_esp+=8;
    } else RECOMP_ITAIL(0xC7000010u);
}'''
        data,_=b.reference();base=bytearray(data[:b.RECORD]);queries=[]
        for mode in range(7):
            q=base.copy();struct.pack_into('<I',q,0,mode);queries.append(bytes(q))
        for word,value in ((7,b.oracle.r.SP-1),(23,b.oracle.query.FLS+4),(26,0)):
            q=base.copy();struct.pack_into('<I',q,0,0);struct.pack_into('<I',q,word*4,value);queries.append(bytes(q))
        q=bytearray(queries[0]);struct.pack_into('<I',q,23*4,b.oracle.query.FLS);queries.append(bytes(q))
        # A valid record after each rejection proves per-record hot-state recovery.
        for mode in range(7,12):
            q=base.copy();struct.pack_into('<I',q,0,mode);queries.extend((bytes(q),bytes(base)))
        q=base.copy();struct.pack_into('<I',q,24*4,1);queries.extend((bytes(q),bytes(base)))
        # Both branch endpoints must clobber only after their observed entry.
        for export in (0,b.oracle.query.FLS):
            q=base.copy();struct.pack_into('<I',q,23*4,export);struct.pack_into('<I',q,27*4,1)
            queries.append(bytes(q))
        q=base.copy();struct.pack_into('<I',q,27*4,2);queries.extend((bytes(q),bytes(base)))
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp);(d/'recomp_types.h').write_text(header);(d/'test.c').write_text(b.assemble(module,resolver,selector))
            p=subprocess.run([cc,'-std=c11','-I'+tmp,d/'test.c','-o',d/'test'],capture_output=True,timeout=60)
            self.assertEqual(p.returncode,0,p.stderr.decode())
            p=subprocess.run([d/'test'],input=b''.join(queries)+queries[0],capture_output=True,timeout=10)
            self.assertEqual(p.returncode,0)
            rows=[json.loads(s) for s in p.stdout.splitlines()];self.assertEqual(len(rows),28)
            for n in range(1,10):self.assertEqual(rows[n],dict(case=n,rejected=True))
            for n in range(11,23,2):self.assertEqual(rows[n],dict(case=n,rejected=True))
            self.assertEqual(rows[25],dict(case=25,rejected=True))
            for n in (23,24):
                self.assertEqual(rows[n]['hot']['registers'][2:4],[0xFEEDFACE,0xDEADBEEF])
                self.assertNotEqual(rows[n]['hot']['events'][-1]['registers'][2:4],[0xFEEDFACE,0xDEADBEEF])
            for n in (0,10,*range(12,24,2),23,24,26,27):
                self.assertEqual(rows[n]['eax'],0)
                self.assertEqual(rows[n]['esp'],b.oracle.r.SP+8)
            self.assertEqual([e['kind'] for e in rows[0]['hot']['events']],['resolve','tls'])
            self.assertEqual(rows[0]['hot']['events'][0]['registers'][7],b.oracle.r.SP-20)
            self.assertEqual([e[0] for e in rows[0]['events']],['resolve','tls'])
            self.assertEqual([e[0] for e in rows[10]['events']],['resolve','guard','fls'])
            self.assertEqual(rows[0]['events'][-1][3],b.oracle.r.SP)
            self.assertLess(rows[10]['events'][-1][3],b.oracle.r.SP)


if __name__=='__main__':unittest.main()
