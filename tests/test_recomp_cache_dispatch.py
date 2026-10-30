"""Authored controls only; no original code, tables, derived bodies or fixtures."""
import importlib.util
import json
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_cache_dispatch.py'
spec = importlib.util.spec_from_file_location('cache_dispatch',PATH)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class CacheDispatchTests(unittest.TestCase):
    def state(self,n=8):
        return b.entry_state(n,0x1290,random.Random(17),{p:bytes(4096) for p in b.IMAGE_PAGES})

    def test_producer_fields_and_range_profiles(self):
        for n in range(64):
            regs,pages = self.state(n)
            h = b.DATA_PAGES[1]+128
            def word(off):
                return struct.unpack_from('<I',pages[b.DATA_PAGES[1]],128+off)[0]
            self.assertEqual(word(0x78),h+0x7c)
            self.assertEqual(word(0xb0),b.BASE+0xfcf0)
            self.assertEqual(word(0xc8),h+0x78)
            self.assertEqual(pages[b.DATA_PAGES[1]][128+0xc5],6)
            self.assertEqual(word(0x100)==0,n<4)
            if n>=4:
                self.assertEqual(word(0x100)-word(0x108),0 if n<8 else 1+n%16)
            self.assertIn(regs['esp'],(b.DATA_PAGES[0]+0x800,b.DATA_PAGES[0]+0xc00))
            self.assertEqual(set(pages),set(b.PAGES))

    def test_whole_samples_is_explicit_distinct_domain(self):
        image = {p:bytes(4096) for p in b.IMAGE_PAGES}
        rng = random.Random(17)
        for n in range(64):
            _,pages = b.entry_state(n,0x1290,rng,image,complete_units=True)
            if n >= 8:
                lo,hi = (struct.unpack_from('<I',pages[b.DATA_PAGES[1]],128+off)[0]
                         for off in (0x108,0x100))
                unit = (1,1,1,1,2,3,4,16)[n%8]
                self.assertEqual((hi-lo)%unit,0)
                self.assertTrue(0 < hi-lo <= 16)

    def test_comparison_rejects_mutations_and_ambiguous_json(self):
        expected = [dict(case=n,regs=[0]*8,pages='00'*(len(b.PAGES)*4096)) for n in range(64)]
        text = '\n'.join(json.dumps(r) for r in expected)
        self.assertEqual(b.compare(text,expected),dict(cases=64,matched=64))
        for key,value in (('case',True),('regs',[True]+[0]*7),('pages','ff'+expected[0]['pages'][2:])):
            rows = [dict(r) for r in expected]
            rows[0][key] = value
            with self.subTest(key=key),self.assertRaises(ValueError):
                b.compare('\n'.join(json.dumps(r) for r in rows),expected)
        for bad in (text+'\n'+json.dumps(expected[-1]),'\n'.join(text.splitlines()[1:]),
                    text.replace('"case": 0','"case": 0, "case": 0',1)):
            with self.assertRaises(ValueError):
                b.compare(bad,expected)

    def ref(self,code,budget=4096):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        entry = b.BASE+0x1100
        md = Cs(CS_ARCH_X86,CS_MODE_32)
        md.detail = True
        nodes = {i.address:i for i in md.disasm(code,entry)}
        regs,pages = self.state()
        data = bytearray(4096)
        data[0x100:0x100+len(code)] = code
        return b.reference(nodes,{b.BASE+0x1000:data},entry,regs,pages,budget)

    def test_reference_executes_original_instructions_no_responses(self):
        result,visited = self.ref(bytes.fromhex('b878563412c3'))
        self.assertEqual(result['regs'][0],0x12345678)
        self.assertEqual(len(visited),2)
        self.assertEqual(result['regs'][-1],self.state()[0]['esp']+4)

    def test_reference_rejects_unknown_pc_reads_writes_and_budget(self):
        for code in (bytes.fromhex('ffe0'), # random EAX target
                     bytes.fromhex('a100000050c3'), # unowned read
                     bytes.fromhex('c705009000a001000000c3'), # image write
                     bytes.fromhex('ebfe')): # finite budget exhaustion
            with self.subTest(code=code.hex()),self.assertRaises(Exception):
                self.ref(code,budget=16)

    def test_thunk_contract_rejects_authored_wrong_edges(self):
        # Authored deliberately long disp32 encoding, not original thunk bytes.
        # The contract validator must accept equivalent instruction encodings.
        base = b.BASE+0xfcf0
        mov = bytes.fromhex('c7842404000000b07ae1a0')
        code = mov+b'\xe9'+struct.pack('<i',b.BASE+0x9550-(base+len(mov)+5))
        f,nodes = b.thunk_function(code,lambda i:i)
        self.assertEqual(len(nodes),2)
        self.assertEqual(f.address,base)
        for offset in (3,4,9):
            wrong = bytearray(code)
            wrong[offset] ^= 1
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                b.thunk_function(bytes(wrong),lambda i:i)

    def test_failure_is_private_and_not_counted(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(b,'ROOT',Path(tmp)), \
                patch('execute_cache_skip.ROOT',Path(tmp)):
            out = Path(tmp)/'work/recomp-bench/missing'
            with self.assertRaises(ValueError):
                b.run(out,0,Path('x'),Path('y'),Path('z'))
            row = json.loads((out/'result.json').read_text())
            self.assertFalse(row['success'])
            self.assertFalse(row['arm64_executed'])
            self.assertFalse(row['android_executed'])
            with self.assertRaises(FileExistsError):
                b.run(out,0,Path('x'),Path('y'),Path('z'))

    def test_native_exact_dispatch_rejects_wrong_target_and_immutable_write(self):
        cc = shutil.which('zig-cc') or shutil.which('cc')
        self.assertIsNotNone(cc,'A real C compiler is required')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Authored declarations for transport-only control bodies. No private
            # fixture/upstream fetch is needed; real lifts use pinned real headers.
            (root/'recomp_types.h').write_text(
                '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#include <string.h>\n'
                'static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;\n')
            for mode in ('valid','target','image','tail-target','tail-caller'):
                thunk = 'g_cur_func=0xA000FCF0u;tail_dispatch(0xA0009550u);'
                if mode == 'tail-target':
                    thunk = thunk.replace('0xA0009550u','0xA0009551u')
                if mode == 'tail-caller':
                    thunk = thunk.replace('0xA000FCF0u','0xA0009550u')
                bodies = {0x9550:'void startup_009550(void) {g_eax=42;}',
                          0xfcf0:'void startup_00FCF0(void) {'+thunk+'}',
                          0x1290:'void startup_001290(void) {'+(
                              'MEM32(0xA0009000u)=1;' if mode=='image' else
                              'dispatch(0xA000FCF1u);' if mode=='target' else 'dispatch(0xA000FCF0u);')+'}'}
                source = root/(mode+'.c')
                source.write_text(b.assemble(bodies,0x1290,b.BASE+0x1200))
                binary = root/mode
                p = subprocess.run([cc,'-std=c11','-D_POSIX_C_SOURCE=200809L','-I'+str(root),str(source),'-lm','-o',str(binary)],capture_output=True,timeout=90)
                self.assertEqual(p.returncode,0,p.stderr.decode())
                data = bytearray()
                for n in range(64):
                    regs,pages = self.state(n)
                    data.extend(struct.pack('<8I',*(regs[r] for r in b.REGS)))
                    data.extend(b''.join(bytes(pages[p]) for p in b.PAGES))
                p = subprocess.run([str(binary)],input=data,capture_output=True,timeout=10)
                self.assertEqual(p.returncode,0)
                rows = [json.loads(s) for s in p.stdout.splitlines()]
                self.assertEqual(len(rows),64)
                if mode == 'valid':
                    self.assertTrue(all(r['regs'][0]==42 for r in rows))
                else:
                    self.assertTrue(all(r == dict(case=n,rejected=True) for n,r in enumerate(rows)))


if __name__ == '__main__':
    unittest.main()
