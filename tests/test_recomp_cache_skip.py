"""Authored reference/transport controls; no private image required."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_cache_skip.py'
spec = importlib.util.spec_from_file_location('cache_skip',PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class CacheSkipTests(unittest.TestCase):
    def state(self):
        pages = {p:bytearray(4096) for p in bench.PAGES}
        regs = {r:0 for r in bench.REGS}
        regs['esp'] = bench.PAGES[0]+0x800
        struct.pack_into('<I',pages[bench.PAGES[0]],0x800,bench.RETURN)
        return regs,pages

    def test_reference_value_cleanup_and_all_pages(self):
        regs,pages = self.state()
        # Authored MOV EAX, 7; RET.
        state,visited = bench.reference(bytes.fromhex('b807000000c3'),bench.BASE+0x1290,regs,pages)
        self.assertEqual(state['regs'][0],7)
        self.assertEqual(state['regs'][-1],regs['esp']+4)
        self.assertEqual(state['pages'],b''.join(bytes(pages[p]) for p in bench.PAGES).hex())
        self.assertEqual(len(visited),2)

    def test_reference_rejects_calls_before_execution(self):
        regs,pages = self.state()
        for code in ('ffd0c3','e800000000c3'):
            with self.subTest(code=code),self.assertRaises(ValueError):
                bench.reference(bytes.fromhex(code),bench.BASE+0x1290,regs,pages)

    def test_reference_rejects_unmapped_read_and_wrong_return(self):
        regs,pages = self.state()
        with self.assertRaises(ValueError):
            bench.reference(bytes.fromhex('a100000000c3'),bench.BASE+0x1290,regs,pages)
        struct.pack_into('<I',pages[bench.PAGES[0]],0x800,bench.RETURN+4)
        with self.assertRaises(ValueError):
            bench.reference(b'\xc3',bench.BASE+0x1290,regs,pages)

    def test_native_calls_reject_without_behavior_response(self):
        text = bench.assemble('void startup_001290(void) {}',0x1290)
        self.assertIn('#undef RECOMP_ICALL',text)
        self.assertIn('rejected=1; longjmp(escape,1)',text)
        self.assertIn('startup_001290();',text)
        self.assertNotIn('@BODY@',text)
        with self.assertRaises(ValueError):
            bench.assemble('UNIMPLEMENTED',0x1290)
        with self.assertRaises(ValueError):
            bench.assemble('void f(void) {}',0x1280)

    def test_native_reached_call_rejects_even_authorized_target(self):
        # Compile the actual transport with authored code, not just a text check.
        # This iteration implements NO dispatch path, including the approved VA.
        body = 'void startup_001290(void) { RECOMP_ICALL(0xA000FCF0u); g_eax=7; }'
        regs,pages = self.state()
        payload = struct.pack('<8I',*(regs[r] for r in bench.REGS))
        payload += b''.join(bytes(pages[p]) for p in bench.PAGES)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'transport.c'
            binary = Path(tmp)/'probe'
            source.write_text(bench.assemble(body,0x1290))
            # Minimal authored declarations for this transport-only test, not a
            # substitute lifter/runtime. Real experiment uses the verified header.
            (Path(tmp)/'recomp_types.h').write_text(
                '#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n'
                'static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;\n')
            built = subprocess.run(['cc','-D_POSIX_C_SOURCE=200809L','-std=c11',
                '-I'+tmp,str(source),'-lm','-o',str(binary)],
                capture_output=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr.decode())
            result = subprocess.run([str(binary)],input=payload*64,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0)
            import json
            self.assertEqual([json.loads(line) for line in result.stdout.splitlines()],
                             [dict(case=n,rejected=True) for n in range(64)])

    def test_output_private_exclusive_and_symlink_checked(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(bench,'ROOT',Path(tmp)):
            root = Path(tmp)
            with self.assertRaises(ValueError):
                bench.private_output(root/'public')
            out = root/'work/recomp-bench/new'
            bench.private_output(out)
            with self.assertRaises(FileExistsError):
                bench.private_output(out)
            (root/'outside').mkdir()
            (out.parent/'link').symlink_to(root/'outside')
            with self.assertRaises(ValueError):
                bench.private_output(out.parent/'link/new')

    def test_comparator_rejects_mutation_and_partial_output(self):
        import json
        state = dict(regs=[0]*8,pages='00'*16384)
        expected = [dict(case=n,**state) for n in range(64)]
        text = '\n'.join(json.dumps(r) for r in expected)
        self.assertEqual(bench.compare(text,expected)['matched'],64)
        with self.assertRaises(ValueError):
            bench.compare('\n'.join(text.splitlines()[:-1]),expected)
        changed = [dict(r) for r in expected]
        changed[0]['regs'] = [1]+[0]*7
        with self.assertRaises(ValueError):
            bench.compare('\n'.join(json.dumps(r) for r in changed),expected)

    def test_scope_keeps_survey_separate(self):
        self.assertEqual(bench.RVAS,(0x1290,0x12d0))
        self.assertEqual(set(bench.CLOSURE),{0x1abd40,0x1240,0x1250,0x1270,0x1290,0x12d0,0xfcf0,0x9550})


if __name__ == '__main__':
    unittest.main()
