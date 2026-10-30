"""Public transport/claim regression tests; no original bytes or lifted bodies."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_startup.py'
spec = importlib.util.spec_from_file_location('startup_native', PATH)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def saved_reference(*, entry=False):
    oracle = b.entry_oracle if entry else b.oracle
    return [dict(case=c, state={k:v.hex() if isinstance(v, bytes) else v
                               for k,v in oracle(c).items()}) for c in b.cases()]


def stream(reference):
    return '\n'.join(json.dumps(dict(case=n, state=r['state'])) for n,r in enumerate(reference))


class StartupNativeTests(unittest.TestCase):
    def test_complete_stream_and_every_observed_component(self):
        reference = saved_reference()
        self.assertTrue(b.compare_stream(stream(reference), reference)['verified'])
        for key in reference[0]['state']:
            records = [dict(case=n, state=copy.deepcopy(r['state'])) for n,r in enumerate(reference)]
            value = records[0]['state'][key]
            if isinstance(value, int):
                records[0]['state'][key] ^= 1
            elif isinstance(value, list):
                value[0] ^= 1
            else:
                records[0]['state'][key] = ('00' if value[:2]!='00' else '01')+value[2:]
            result = b.compare_stream('\n'.join(map(json.dumps, records)), reference)
            self.assertEqual(result['matched'],319,key)
            self.assertFalse(result['verified'],key)

    def test_rejection_is_execution_not_match(self):
        reference = saved_reference()
        records = [dict(case=n,rejected='endpoint-return-address') if r['state']['events']
                   else dict(case=n,state=r['state']) for n,r in enumerate(reference)]
        result = b.compare_stream('\n'.join(map(json.dumps,records)),reference)
        self.assertEqual(result['matched'],160)
        self.assertEqual(result['rejected'],{'endpoint-return-address':160})
        self.assertFalse(result['verified'])
        records[0]['rejected']='pretend-success'
        with self.assertRaises(ValueError):
            b.compare_stream('\n'.join(map(json.dumps,records)),reference)

    def test_malformed_duplicate_partial_and_lying_reference_reject(self):
        ref = saved_reference(); lines = stream(ref).splitlines()
        for bad in (lines[:-1], lines+[lines[0]], [lines[0]]+lines[:-1], ['{}']+lines[1:]):
            with self.assertRaises(ValueError):
                b.compare_stream('\n'.join(bad),ref)
        ref[0]['state']['eax'] ^= 1
        with self.assertRaises(ValueError):
            b.compare_stream(stream(ref),ref)

    def test_assembly_preserves_bodies_and_call_macros(self):
        # Authored sentinels only, not functions copied from a game.
        bodies={0x8258A9:'void public_fixture_a(void) { /* unchanged */ }',
                0x82585C:'void public_fixture_b(void) { /* unchanged too */ }'}
        text=b.assemble(bodies)
        for body in bodies.values():
            self.assertEqual(text.count(body),1)
        self.assertNotIn('#undef RECOMP_ICALL',text)
        self.assertNotIn('#undef RECOMP_CALL',text)
        self.assertNotIn('#define RECOMP_RETADDR',text)
        with self.assertRaises(ValueError):
            b.assemble({0x8258A9:'something'})

    def test_entry_oracle_scope_and_every_component(self):
        reference = saved_reference(entry=True)
        self.assertTrue(b.compare_stream(stream(reference), reference, entry=True)['verified'])
        for key in reference[0]['state']:
            records = [dict(case=n, state=copy.deepcopy(r['state'])) for n,r in enumerate(reference)]
            value = records[0]['state'][key]
            if isinstance(value, int):
                records[0]['state'][key] ^= 1
            elif isinstance(value, list):
                value[0] ^= 1
            else:
                records[0]['state'][key] = ('00' if value[:2]!='00' else '01')+value[2:]
            result = b.compare_stream('\n'.join(map(json.dumps, records)), reference, entry=True)
            self.assertEqual(result['matched'], 319, key)
            self.assertFalse(result['verified'], key)
        for ref, mode in ((reference, False), (saved_reference(), True)):
            with self.assertRaises(ValueError):
                b.compare_stream(stream(ref), ref, entry=mode)
        reference[0]['state']['eip'] ^= 1
        with self.assertRaises(ValueError):
            b.compare_stream(stream(reference), reference, entry=True)

    def test_entry_assembly_is_explicit_and_preserves_all_bodies(self):
        pair = {0x8258A9:'void public_pair_a(void) {}',
                0x82585C:'void public_pair_b(void) {}'}
        bodies = dict(pair)
        bodies[0x8248A3] = 'void public_entry(void) {}'
        rows = [dict(caller=0xA08248A3, target=0xA08258A9,
                     return_va=0xA08248A8, slot=False)]
        text = b.assemble(bodies, rows, entry=True)
        self.assertTrue(text.startswith('#define ENTRY_BOUNDARY 1\n'))
        for body in bodies.values():
            self.assertEqual(text.count(body), 1)
        self.assertNotIn('#undef RECOMP_ITAIL', text)
        self.assertIn('case 0xA0824727u: return tail_stop;', text)
        self.assertIn('startup_8248A3();\n            reject("tail-boundary")', text)
        for args in ((bodies, None, True), (pair, rows, True), (bodies, rows, False)):
            with self.assertRaises(ValueError):
                b.assemble(args[0], args[1], entry=args[2])
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp)/'not-created'
            with self.assertRaises(ValueError):
                b.run(out, entry=True)
            self.assertFalse(out.exists())

    def test_fixed_little_endian_input_and_case_order(self):
        data=b.input_bytes()
        self.assertEqual(len(data),320*14*4)
        for n,c in enumerate(b.cases()):
            words=struct.unpack_from('<14I',data,n*56)
            self.assertEqual(list(words),[c['stack'],c['sp'],c['cookie'],*c['values'],*c['saved'],c['qpc']])

    def test_missing_input_and_no_clobber_or_escape(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(b,'ROOT',Path(temp)):
            root=Path(temp); out=root/'work/recomp-bench/absent'
            with self.assertRaises(ValueError):
                b.run(out)
            row=json.loads((out/'result.json').read_text())
            self.assertEqual(row['failed_stage'],'reference')
            self.assertFalse(row['success']); self.assertEqual(row['runs'],{})
            before=(out/'result.json').read_bytes()
            with self.assertRaises(FileExistsError):
                b.run(out)
            self.assertEqual(before,(out/'result.json').read_bytes())
            outside=root/'outside';outside.mkdir()
            (out.parent/'link').symlink_to(outside)
            for path in (outside/'new',out.parent/'link/new'):
                with self.assertRaises(ValueError):
                    b.run(path)
            self.assertEqual(list(outside.iterdir()),[])


if __name__=='__main__':
    unittest.main()
