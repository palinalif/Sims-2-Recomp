"""Public transport controls only; no private originals or generated bodies."""
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

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_storage_composed.py'
spec = importlib.util.spec_from_file_location('execute_composed',PATH)
b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)


class ExecuteComposedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs,cls.expected = b.reference()
        cls.lines = list(map(json.dumps,cls.expected))

    def test_packing_reuses_unchanged_composed_oracle(self):
        self.assertEqual(len(self.inputs),3456*4144)
        self.assertEqual({c[1]&31 for c in b.oracle.cases()},set(range(32)))
        for n,(value,cookie,result,index,salt,clobber) in enumerate(b.oracle.cases()):
            block = self.inputs[n*4144:(n+1)*4144]
            regs,stack = b.oracle.query.free.inputs(index,salt)
            self.assertEqual(struct.unpack('<12I',block[:48]),
                             (*regs,cookie,b.oracle.hot.encode(value,cookie),result,clobber))
            self.assertEqual(block[48:],stack)
        self.assertEqual(b.compare('\n'.join(self.lines),self.expected),dict(cases=3456,matched=3456))

    def test_each_observed_component_and_strict_stream(self):
        changes = [('registers',k) for k in range(8)]+[('stack',0),('case',0),('extra',0)]
        changes += [('event',k) for k in range(5)]
        for field,k in changes:
            row = copy.deepcopy(self.expected[0])
            if field=='registers': row[field][k] ^= 1
            elif field=='stack': row[field] = 'ff'+row[field][2:]
            elif field=='event':
                row['events'][0][k] = ['bad', [False]*4, False, False, False][k]
            else: row[field] = False
            lines = self.lines.copy(); lines[0] = json.dumps(row)
            with self.assertRaises(ValueError): b.compare('\n'.join(lines),self.expected)
        for lines in (self.lines[:-1],self.lines+[self.lines[0]],[self.lines[0]]*3456):
            with self.assertRaises(ValueError): b.compare('\n'.join(lines),self.expected)
        lines = self.lines.copy();lines[0] = lines[0].replace('"case": 0','"case": 123, "case": 0')
        with self.assertRaises(ValueError): b.compare('\n'.join(lines),self.expected)
        with self.assertRaises(ValueError): b.compare('bad',self.expected)

    def test_bodies_inserted_verbatim_once(self):
        selector = 'void storage_selector(void) { /* authored only */ }'
        resolver = 'void startup_847E6C(void) { /* authored only */ }'
        source = b.assemble(selector,resolver)
        self.assertEqual(source.count(selector),1);self.assertEqual(source.count(resolver),1)
        self.assertNotIn('@SELECTOR@',source);self.assertNotIn('@RESOLVER@',source)
        self.assertIn('require_contract(!resolver_active)',source)
        for bad in ('',' ',None):
            with self.assertRaises(ValueError): b.assemble(selector,bad)

    def test_native_nested_dispatch_rejection_immutability_recovery_and_truncation(self):
        # Authored adapter exercise, NOT a selector/resolver reconstruction.
        resolver = '''void startup_847E6C(void) {
            switch(g_eax) {
            case 1: RECOMP_ICALL(0xC7000020u); break;
            case 2: RECOMP_ITAIL(0xC7000010u); break;
            case 3: g_eax=MEM32(0xA104F544u); break;
            case 4: MEM32(0xA104F540u)=99; break;
            case 5: MEM32(0xA10E0334u)=99; break;
            case 6: MEM32(0xA0D9A71Cu)=99; break;
            case 7: g_eax=MEM32(0xA10E0338u); break;
            default: g_eax=MEM32(0xA104F540u); break;
            }
            g_esp+=4;
        }'''
        selector = '''void storage_selector(void) {
            RECOMP_ICALL(0xA0847E6Cu);
            RECOMP_ITAIL(0xC7000010u);
        }'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);source=root/'fixture.c';binary=root/'fixture'
            (root/'recomp_types.h').write_text(
                '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n'
                'static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;\n'
                '#define RECOMP_FLAGS_OUT() ((void)0)\n#define RECOMP_REGS_OUT() ((void)0)\n'
                '#define RECOMP_REGS_IN() ((void)0)\n#define esp g_esp\n'
                '#define PUSH32(sp,v) do { (sp)-=4; MEM32(sp)=(v); } while(0)\n')
            source.write_text(b.assemble(selector,resolver))
            compiler=shutil.which('cc') or shutil.which('clang') or shutil.which('gcc')
            self.assertIsNotNone(compiler,'C compiler required for transport regression')
            subprocess.run([compiler,'-std=c11',str(source),'-o',str(binary)],
                           check=True,capture_output=True,timeout=120)
            stack=bytearray(4096);struct.pack_into('<I',stack,0x800,33)
            def case(n):
                return struct.pack('<12I',n,2,3,4,5,6,7,0xB8000800,17,23,41,0)+stack
            data=b''.join(case(n) for n in range(8))
            p=subprocess.run([str(binary)],input=data+case(0),capture_output=True,check=True,timeout=30)
            rows=[json.loads(line) for line in p.stdout.splitlines()]
            self.assertEqual(rows[0]['registers'][0],41)
            self.assertEqual([e[0] for e in rows[0]['events']],['resolve','tls'])
            self.assertEqual(rows[1:8],[dict(case=n,rejected=True) for n in range(1,8)])
            self.assertEqual(rows[8]['registers'],rows[0]['registers'])
            for truncated in (b'X',data[:47],data[:4143]):
                self.assertNotEqual(subprocess.run([str(binary)],input=truncated,
                    capture_output=True,timeout=30).returncode,0)

    def test_private_output_and_failed_lift_not_a_match(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(b,'ROOT',Path(tmp)):
            root=Path(tmp);private=root/'work/recomp-bench';private.mkdir(parents=True)
            outside=root/'outside';outside.mkdir();(private/'link').symlink_to(outside)
            for output in (outside/'out',private/'link/out'):
                with self.assertRaises(ValueError): b.run(output,root/'missing',root/'missing')
            output=private/'out'
            with patch.object(b.subprocess,'run',side_effect=OSError('private')),self.assertRaises(OSError):
                b.run(output,root/'missing',root/'missing')
            row=json.loads((output/'metrics.jsonl').read_text())
            self.assertEqual(row['failed_stage'],'lift')
            for key in ('success','lifted','compiled_for_aarch64','matched_x86_reference',
                        'executed_under_qemu','android_executed'):
                self.assertFalse(row[key])
            with self.assertRaises(FileExistsError): b.run(output,root/'missing',root/'missing')


if __name__ == '__main__': unittest.main()
