"""Authored fixtures only; no original bytes, globals or saved game states."""
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('resource_leaf', Path(__file__).resolve().parents[1]/'scripts/recomp/execute_resource_leaf.py')
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class ResourceLeafTests(unittest.TestCase):
    def frame(self):
        regs = {r: 0x12345678 for r in bench.REGS}
        regs['esp'] = bench.PAGES[0]+2048
        pages = {p: bytearray(4096) for p in bench.PAGES}
        struct.pack_into('<II', pages[bench.PAGES[0]], 2048, bench.RETURN, 17)
        return regs, pages

    def test_original_reference_checks_return_cleanup_and_memory(self):
        regs, pages = self.frame()
        # Authored load argument; store into declared global page; RET 4.
        code = bytes.fromhex('8b442404a300f004a1c20400')
        result, seen = bench.reference_case(code, 0xA0001000, regs, pages)
        self.assertEqual(len(seen), 3)
        self.assertEqual(result['regs'][0], 17)
        self.assertEqual(result['regs'][-1], regs['esp']+8)
        memory = bytes.fromhex(result['pages'])
        self.assertEqual(struct.unpack_from('<I', memory, 8192)[0], 17)
        self.assertEqual(pages[bench.PAGES[2]], bytes(4096))

    def test_byte_mov_at_unaligned_page_end_is_checked_by_width(self):
        regs, pages = self.frame()
        pages[bench.PAGES[2]][4095] = 0xEA
        code = bytes.fromhex('a0ffff04a1a201000072c20400')
        result, _ = bench.reference_case(code, 0xA0001000, regs, pages)
        self.assertEqual(result['regs'][0] & 255, 0xEA)
        self.assertEqual(bytes.fromhex(result['pages'])[4097], 0xEA)

    def test_branch_paths_are_bounded_not_linear_execution(self):
        regs, pages = self.frame()
        code = bytes.fromhex('85c0740531c0c20400b801000000c20400')
        result, seen = bench.reference_case(code, 0xA0001000, regs, pages)
        self.assertEqual(result['regs'][0], 0)
        regs['eax'] = 0
        other, second = bench.reference_case(code, 0xA0001000, regs, pages)
        self.assertEqual(other['regs'][0], 1)
        self.assertNotEqual(seen, second)
        self.assertEqual(len(seen | second), 6)

    def test_calls_segments_bad_memory_bad_return_and_budget_reject(self):
        regs, pages = self.frame()
        for code in ('ffd0c3', '64a100000000c3', 'a100000000c3',
                     'a101f004a1c3', 'c3'):
            with self.subTest(code=code):
                if code == 'c3':
                    bad = {p: bytearray(v) for p, v in pages.items()}
                    struct.pack_into('<I', bad[bench.PAGES[0]], 2048, 0x71000004)
                else:
                    bad = pages
                with self.assertRaises(ValueError):
                    bench.reference_case(bytes.fromhex(code), 0xA0001000, regs, bad)
        with self.assertRaisesRegex(ValueError, 'budget'):
            bench.reference_case(bytes.fromhex('89c0c3'), 0xA0001000, regs, pages, budget=1)

    def records(self):
        return [dict(case=n, regs=[0]*8, pages='00'*16384) for n in range(64)]

    def test_strict_comparison_rejects_every_component_and_partial_outputs(self):
        expected = self.records()
        text = lambda rows: '\n'.join(json.dumps(r) for r in rows)
        self.assertEqual(bench.compare(text(expected), expected)['matched'], 64)
        mutations = [lambda r: r['regs'].__setitem__(2, 1),
                     lambda r: r.update(pages='01'+r['pages'][2:]),
                     lambda r: r.update(case=True), lambda r: r.update(extra=0),
                     lambda r: r.update(regs=[False]*8), lambda r: r.update(rejected=True)]
        for mutate in mutations:
            rows = json.loads(json.dumps(expected))
            mutate(rows[31])
            with self.assertRaises(ValueError):
                bench.compare(text(rows), expected)
        for rows in (expected[:-1], expected+[expected[0]], [expected[0]]*64):
            with self.assertRaises(ValueError):
                bench.compare(text(rows), expected)

    def test_private_exclusive_output_and_wrong_pin(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(bench, 'ROOT', Path(tmp)):
            root = Path(tmp)
            outside = root/'outside'
            outside.mkdir()
            private = root/'work/recomp-bench'
            private.mkdir(parents=True)
            (private/'link').symlink_to(outside)
            for output in (outside/'out', private/'link/out'):
                with self.assertRaises(ValueError):
                    bench.run(output, root/'missing-index')
            image = root/'work/interop-legacy-002/analysis-image.bin'
            image.parent.mkdir(parents=True)
            image.write_bytes(b'authored wrong-pin fixture')
            with self.assertRaises(ValueError):
                bench.run(private/'out', root/'missing-index')
            row = json.loads((private/'out/metrics.json').read_text())
            self.assertEqual(row, json.loads((private/'out/metrics.jsonl').read_text()))
            self.assertEqual(row['failed_stage'], 'reference')
            for key in ('attempted', 'lifted', 'compiled_for_aarch64', 'linked'):
                self.assertFalse(row[key])
            self.assertFalse(row['matched_x86_reference'])
            self.assertFalse(row['executed_under_qemu'])
            with self.assertRaises(FileExistsError):
                bench.run(private/'out', root/'missing-index')
            self.assertEqual(image.read_bytes(), b'authored wrong-pin fixture')

    def test_native_transport_byte_word_access_and_rejection(self):
        # Compile public authored C only: this exercises the actual adapter,
        # not pcrecomp or a hand-written substitute for the selected function.
        body = '''void startup_82A47B(void) {
            uint32_t a=MEM32(g_esp+4);MEM8(a+1)=0xEA;
            g_eax=MEM8(a+1);g_esp+=8;
        }'''
        inputs, expected = bytearray(), []
        for n in range(64):
            regs, pages = self.frame()
            struct.pack_into('<I', pages[bench.PAGES[0]], 2052, bench.PAGES[1])
            inputs.extend(struct.pack('<8I', *(regs[r] for r in bench.REGS)))
            inputs.extend(b''.join(pages[p] for p in bench.PAGES))
            regs.update(eax=0xEA, esp=regs['esp']+8)
            pages[bench.PAGES[1]][1] = 0xEA
            expected.append(dict(case=n, regs=[regs[r] for r in bench.REGS],
                pages=b''.join(pages[p] for p in bench.PAGES).hex()))
        # Public minimal header avoids any private fixture requirement.
        header = '''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'recomp_types.h').write_text(header)
            source, binary = root/'transport.c', root/'transport'
            source.write_text(bench.assemble(body))
            subprocess.run(['cc', '-std=c11', '-I'+str(root), str(source), '-o', str(binary)],
                check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(binary)], input=bytes(inputs), capture_output=True, check=True, timeout=10)
            self.assertEqual(bench.compare(result.stdout.decode(), expected)['matched'], 64)
            bad = bytearray(inputs)
            struct.pack_into('<I', bad, 32+2052, 0xFFFFFFFF)
            result = subprocess.run([str(binary)], input=bad, capture_output=True, check=True, timeout=10)
            with self.assertRaises(ValueError):
                bench.compare(result.stdout.decode(), expected)

    def test_native_transport_exact_configured_entry_stacks(self):
        body = 'void startup_82A47B(void) { g_esp+=8; }'
        header = '''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
static uint32_t g_flag_k,g_flag_a,g_flag_b,g_flag_cf;
'''
        inputs, expected = bytearray(), []
        for n in range(64):
            regs, pages = self.frame()
            regs['esp'] -= 28 if n % 2 else 32
            inputs.extend(struct.pack('<8I', *(regs[r] for r in bench.REGS)))
            inputs.extend(b''.join(pages[p] for p in bench.PAGES))
            regs['esp'] += 8
            expected.append(dict(case=n, regs=[regs[r] for r in bench.REGS],
                pages=b''.join(pages[p] for p in bench.PAGES).hex()))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'recomp_types.h').write_text(header)
            source, binary = root/'transport.c', root/'transport'
            source.write_text(bench.assemble(body))
            subprocess.run(['cc', '-std=c11', '-I'+str(root),
                '-DTS2_ENTRY_SP_A='+str(bench.PAGES[0]+2048-28)+'u',
                '-DTS2_ENTRY_SP_B='+str(bench.PAGES[0]+2048-32)+'u',
                str(source), '-o', str(binary)], check=True, capture_output=True, timeout=60)
            result = subprocess.run([str(binary)], input=bytes(inputs), capture_output=True, check=True, timeout=10)
            self.assertEqual(bench.compare(result.stdout.decode(), expected)['matched'], 64)
            bad = bytearray(inputs)
            struct.pack_into('<I', bad, 28, bench.PAGES[0]+2048)
            result = subprocess.run([str(binary)], input=bad, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 91)

    def test_global_hypotheses_are_complete_deterministic_and_bounded(self):
        combinations = set()
        for n in range(64):
            regs, pages = self.frame()
            before = {p: bytes(v) for p, v in pages.items()}
            state = bench.synthetic_global_state(n, pages)
            combinations.add((state['slot_mask'], state['pointed_byte'], n % 2))
            again = {p: bytearray(v) for p, v in before.items()}
            self.assertEqual(bench.synthetic_global_state(n, again), state)
            self.assertEqual(pages, again)
            self.assertEqual(bytes(pages[bench.PAGES[0]]), before[bench.PAGES[0]])
            allowed = {bench.PAGES[1]+1024+k*64 for k in range(3)}
            allowed |= {a+j for a in (0xA104F958, 0xA104F95C, 0xA10DFCAC) for j in range(4)}
            for p in bench.PAGES:
                self.assertTrue(all(p+i in allowed for i, (a, b) in
                    enumerate(zip(before[p], pages[p])) if a != b))
            for k, slot in enumerate((0xA104F958, 0xA104F95C, 0xA10DFCAC)):
                word = struct.unpack_from('<I', pages[slot & ~4095], slot & 4095)[0]
                self.assertEqual(word, bench.PAGES[1]+1024+k*64 if state['slot_mask'] & (1 << k) else 0)
        self.assertEqual(len(combinations), 64)
        for n in (-1, 64, True, 1.5):
            with self.assertRaises(ValueError):
                bench.synthetic_global_state(n, self.frame()[1])
        with self.assertRaises(ValueError):
            bench.synthetic_global_state(0, {})

    def test_global_alias_profiles_are_explicit_not_accidental(self):
        for n in range(64):
            _, pages = self.frame()
            state = bench.synthetic_global_state(n, pages, aliases=True)
            self.assertEqual(state['alias_profile'], n // 16)
            for k, slot in enumerate((0xA104F958, 0xA104F95C, 0xA10DFCAC)):
                pointer = bench.PAGES[1]+(1024+k*64, 128, 256, 512)[n // 16]
                word = struct.unpack_from('<I', pages[slot & ~4095], slot & 4095)[0]
                self.assertEqual(word, pointer if state['slot_mask'] & (1 << k) else 0)
                self.assertEqual(pages[bench.PAGES[1]][pointer-bench.PAGES[1]], state['pointed_byte'])

    def test_global_hypotheses_exercise_authored_pointer_branch(self):
        # Authored MOV global/TEST/JE/byte MOV/RET4. Not original game code.
        code = bytes.fromhex('a158f904a185c074028a00c20400')
        coverage = set()
        for n in range(64):
            regs, pages = self.frame()
            state = bench.synthetic_global_state(n, pages)
            accesses = []
            result, seen = bench.reference_case(code, 0xA0001000, regs, pages, accesses=accesses)
            self.assertIn((0xA104F958, 4), accesses)
            self.assertEqual((bench.PAGES[1]+1024, 1) in accesses, bool(state['slot_mask'] & 1))
            self.assertEqual(len(accesses), 1+bool(state['slot_mask'] & 1))
            coverage.update(seen)
            expected = ((bench.PAGES[1]+1024) & ~255) | state['pointed_byte'] if state['slot_mask'] & 1 else 0
            self.assertEqual(result['regs'][0], expected)
            self.assertEqual(bytes.fromhex(result['pages']), b''.join(pages[p] for p in bench.PAGES))
        self.assertEqual(len(coverage), 5)

    def test_body_is_inserted_verbatim_once(self):
        body = 'void startup_82A47B(void) { /* authored fixture */ }'
        result = bench.assemble(body)
        self.assertEqual(result.count(body), 1)
        self.assertNotIn('@BODY@', result)
        with self.assertRaises(ValueError):
            bench.assemble('')


if __name__ == '__main__':
    unittest.main()
