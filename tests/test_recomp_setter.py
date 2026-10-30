"""Public controls for selected setter measurement; no game bytes/fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/measure_setter.py'
spec = importlib.util.spec_from_file_location('setter_benchmark', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)
REGS = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
H = SimpleNamespace(REGS=REGS, Case=lambda name, code, **kw: SimpleNamespace(name=name, code=code, **kw))


class SetterBenchmarkTests(unittest.TestCase):
    def test_new_cases_are_deterministic_distinct_and_high_address(self):
        left, right = bench.cases(H, b'authored placeholder'), bench.cases(H, b'authored placeholder')
        self.assertEqual(len(left), 64)
        self.assertEqual([c.mem for c in left], [c.mem for c in right])
        self.assertEqual([c.regs for c in left], [c.regs for c in right])
        self.assertEqual(len({c.regs['esp'] for c in left}), 64)
        values = set()
        for c in left:
            sp = c.regs['esp']
            stop, obj, a, b = struct.unpack('<IIII', c.mem[sp])
            values.update((a, b))
            self.assertEqual(stop, bench.BASE+len(c.code))
            self.assertGreater(obj, 0x80000000)
            self.assertGreater(sp, 0x80000000)
            self.assertEqual(len(c.mem[obj]), 64)
            self.assertEqual(set(c.regs), set(REGS))
        self.assertTrue({0, 1, 0xffffffff, 0x80000000, 0x7fffffff}.issubset(values))

    def test_independent_oracle_preserves_caller_and_only_two_fields(self):
        obj, sp = 0xa0010000, 0xa0020000
        regs = dict.fromkeys(REGS, 0x12345678)
        regs['esp'] = sp
        c = SimpleNamespace(regs=regs, mem={obj: bytes(64), sp: struct.pack('<IIII', 1, obj, 0xffffffff, 0x80000000)})
        result = bench.oracle(c)
        self.assertEqual(result['regs'], dict(regs, eax=obj, ecx=0xffffffff, edx=0x80000000, esp=sp+4))
        self.assertEqual(result['eflags'], 0x202)
        self.assertEqual(result['mem'], {**{str(obj+0x28+i): 255 for i in range(4)}, str(obj+0x2f): 128})
        self.assertEqual(regs['eax'], 0x12345678)
        self.assertEqual(c.mem[obj], bytes(64))

    def test_every_observed_field_mutation_and_missing_case_rejects(self):
        states = [bench.oracle(c) for c in bench.cases(H, b'placeholder')]
        self.assertEqual(bench.require_match(states, copy.deepcopy(states)), 64)
        mutations = [('regs', 'eax', 123), ('regs', 'esp', 123), ('eflags', None, 0),
                     ('mem', '2684420136', 123), ('fp_depth', None, 1), ('st', None, [1.0])]
        for field, key, value in mutations:
            bad = copy.deepcopy(states)
            if key is None:
                bad[0][field] = value
            else:
                bad[0][field][key] = value
            with self.subTest(field=field, key=key), self.assertRaises(ValueError):
                bench.require_match(states, bad)
        with self.assertRaises(ValueError):
            bench.require_match(states[:-1], states[:-1])

    def test_no_pipeline_pass_without_both_isa_and_x86_oracle(self):
        good = dict(lifted=True, x86_oracle_matches=64, runs={isa: dict(compiled=True,
                    executed=True, matched=64, exit_code=0, stdout_sha256='same') for isa in ('host', 'arm64')})
        bench.complete(good)
        for field, value in (('lifted', False), ('x86_oracle_matches', 63)):
            bad = copy.deepcopy(good)
            bad[field] = value
            with self.assertRaises(ValueError):
                bench.complete(bad)
        for isa in good['runs']:
            for field, value in (('compiled', False), ('executed', False), ('matched', 63), ('exit_code', 1), ('stdout_sha256', 'different')):
                bad = copy.deepcopy(good)
                bad['runs'][isa][field] = value
                with self.subTest(isa=isa, field=field), self.assertRaises(ValueError):
                    bench.complete(bad)
            bad = copy.deepcopy(good)
            del bad['runs'][isa]
            with self.assertRaises(ValueError):
                bench.complete(bad)

    def test_private_outputs_exclusive_and_missing_inputs_record_failure(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            with self.assertRaises(ValueError):
                bench.measure(root/'outside', root/'index')
            self.assertFalse((root/'outside').exists())
            parent = root/'work/recomp-bench'
            parent.mkdir(parents=True)
            (root/'outside').mkdir()
            (parent/'link').symlink_to(root/'outside')
            with self.assertRaises(ValueError):
                bench.measure(parent/'link/result', root/'index')
            out = parent/'result'
            with self.assertRaises(OSError):
                bench.measure(out, root/'index')
            before = (out/'metrics.jsonl').read_bytes()
            row = json.loads(before)
            self.assertFalse(row['success'])
            self.assertFalse(row['attempted'])
            self.assertEqual(row['failed_stage'], 'preflight')
            self.assertEqual(row['runs'], {})
            with self.assertRaises(FileExistsError):
                bench.measure(out, root/'index')
            self.assertEqual((out/'metrics.jsonl').read_bytes(), before)

    def test_hook_free_access_checks_read_write_return_and_reject_escape(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        # Authored stack load / indirect store, NOT the original body.
        load, store, ret = list(md.disasm(bytes.fromhex('8b04248906c3'), 0x400000))
        sp, obj = 0xa0020000, 0xa0010000
        regs = dict(esp=sp, esi=obj+0x28)
        self.assertEqual(bench.checked_accesses(load, regs.__getitem__, sp, obj), [('read', sp, 4)])
        self.assertEqual(bench.checked_accesses(store, regs.__getitem__, sp, obj), [('write', obj+0x28, 4)])
        self.assertEqual(bench.checked_accesses(ret, regs.__getitem__, sp, obj), [('read', sp, 4)])
        for value in (obj, obj+0x30, 0xffffffff):
            regs['esi'] = value
            with self.assertRaises(ValueError):
                bench.checked_accesses(store, regs.__getitem__, sp, obj)
        regs['esp'] = sp+16
        with self.assertRaises(ValueError):
            bench.checked_accesses(load, regs.__getitem__, sp, obj)
        with self.assertRaises(ValueError):
            bench.checked_accesses(ret, regs.__getitem__, sp, obj)
        for code in ('90', '50', 'c20400', '648b0424', '8b0404'):
            insn = next(md.disasm(bytes.fromhex(code), 0x400000))
            with self.subTest(code=code), self.assertRaises(ValueError):
                bench.checked_accesses(insn, regs.__getitem__, sp, obj)

    def test_fixture_embeds_exact_body_once_and_calls_it_for_all_cases(self):
        h = SimpleNamespace(Case=H.Case, build_c=lambda _: 'prelude\nstatic void case_0(void){}\nint main(void){}')
        body = 'static void setter_1070(void) { /* authored test body */ }'
        text = bench.source(h, bench.cases(H, b'placeholder'), body)
        self.assertEqual(text.count(body), 1)
        self.assertEqual(text.count('    setter_1070();'), 64)
        self.assertIn('exit(91)', text)
        self.assertIn('(uint64_t)va + 4', text)
        self.assertIn('int main(void){}', text)
