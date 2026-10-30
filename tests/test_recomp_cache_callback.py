"""Public authored prefix controls; no proprietary bytes, states or fixtures."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/trace_cache_callback.py'
spec = importlib.util.spec_from_file_location('cache_callback', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def nodes(code):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    return {i.address:i for i in md.disasm(bytes.fromhex(code), bench.BASE+0x1290)}


def trace(code, **kwargs):
    return bench.trace_prefix(nodes(code), bench.BASE+0x1290, **kwargs)


class CacheCallbackTests(unittest.TestCase):
    def test_pointer_chain_stack_and_address_not_value(self):
        # Authored: save EDI; arg0->EDI; field+20->ECX; address+24->EDX;
        # push address, push loaded field; call [EDI+28]. Deliberate differing
        # displacements detect field confusion and LEA-vs-MOV confusion.
        r = trace('57 8b7c2408 8b4f20 8d5724 52 51 ff5728 c3')
        sp = bench.SP
        arg = ('load32', bench.add(sp,4))
        call = r['calls'][0]
        self.assertEqual(call['target'], ('load32',bench.add(arg,0x28)))
        self.assertEqual(call['pre_call_esp'], bench.add(sp,-12))
        self.assertEqual(call['stack_words'], [('load32',bench.add(arg,0x20)),
            bench.add(arg,0x24), ('entry','edi'), ('load32',sp)])
        self.assertFalse(r['execution_performed'])
        self.assertFalse(r['target_resolved'])
        # Mutations must change the provenance, not silently retain a contract.
        for changed in ('ff5728','ff572c'):
            value = trace('8b7c2404 '+changed)['calls'][0]['target']
            self.assertEqual(value, ('load32',bench.add(arg,0x28 if changed=='ff5728' else 0x2c)))
        self.assertNotEqual(trace('8b7c2404 8b5724 52 ffd0')['calls'][0]['stack_words'][0],
                            trace('8b7c2404 8d5724 52 ffd0')['calls'][0]['stack_words'][0])

    def test_both_guard_edges_and_first_call_stop(self):
        r = trace('85c9 7403 ffd0 c3 c3')
        self.assertEqual(r['return_paths'],1)
        self.assertEqual(len(r['calls']),1)
        c = r['calls'][0]
        self.assertEqual(c['target'],('entry','eax'))
        self.assertEqual(c['conditions'][0]['predicate'],('test',('entry','ecx'),('entry','ecx')))
        self.assertFalse(c['conditions'][0]['taken'])
        # Unsupported post-call body must never be interpreted.
        self.assertEqual(trace('ffd0 0f0b')['steps'],1)
        self.assertEqual(trace('c3 0f0b')['return_paths'],1)

    def test_nested_service_is_not_handle_callback_slot(self):
        # Authored arg0->EDX; [EDX+40]->ECX; push service; call [ECX+14].
        c = trace('8b542404 8b4a40 51 ff5114')['calls'][0]
        handle = ('load32',bench.add(bench.SP,4))
        service = ('load32',bench.add(handle,0x40))
        self.assertEqual(c['target'],('load32',bench.add(service,0x14)))
        self.assertEqual(c['stack_words'][0],service)
        self.assertNotEqual(c['target'],('load32',bench.add(handle,0x14)))

    def test_stack_save_restore_push_esp_and_copy_normalization(self):
        r = trace('50 5b 54 ffd3')
        c = r['calls'][0]
        self.assertEqual(c['target'],('entry','eax'))
        self.assertEqual(c['stack_words'][0],bench.SP)
        self.assertEqual(bench.add(bench.add(bench.SP,-4),4),bench.SP)
        self.assertEqual(trace('90 ff510c')['calls'][0]['target'],
                         ('load32',bench.add(('entry','ecx'),12)))

    def test_bounded_stack_cleanup_and_increment_invalidate_predicate(self):
        c = trace('50 83c404 40 ffd0')['calls'][0]
        self.assertEqual(c['pre_call_esp'],bench.SP)
        self.assertEqual(c['target'],bench.add(('entry','eax'),1))
        for code in ('85c9 40 7400 ffd0', '85c9 83c404 7400 ffd0',
                     'ff00 ffd0', '83c4fc ffd0', '66ff5104'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                trace(code)

    def test_unknown_side_effects_boundaries_and_budgets_reject(self):
        for code in ('83c004 ffd0', # arithmetic not modelled
                     '8901 ffd0', # input-memory store
                     '88c3 ffd0', # partial register write
                     '648b01 ffd0', # segmented load
                     '8b0401 ffd0', # indexed load
                     '8be0 ffd0', # rewritten stack base
                     '7400 ffd0', # no known flag predicate
                     '85c9 e300 ffd0', # JECXZ is not a flag-based condition
                     'ffe0', # unresolved tail
                     'ebfe', # loop
                     'eb01 b801000000 c3', # branch into instruction
                     'b801000000'): # fallthrough hole
            with self.subTest(code=code), self.assertRaises(ValueError):
                trace(code)
        with self.assertRaises(ValueError):
            trace('90 90 ffd0',max_steps=2)
        with self.assertRaises(ValueError):
            trace('85c9 7402 ffd0 c3',max_paths=1)

    def test_private_exclusive_failure_record_never_success(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench,'ROOT',Path(temp)):
            root = Path(temp)
            with self.assertRaises(ValueError):
                bench.inspect(root/'public',root/'index')
            out = root/'work/recomp-bench/result'
            with self.assertRaises(OSError):
                bench.inspect(out,root/'index')
            original = (out/'result.json').read_bytes()
            r = json.loads(original)
            self.assertFalse(r['inspection_complete'])
            for flag in ('lifted','host_executed','arm64_executed','android_executed'):
                self.assertFalse(r[flag])
            self.assertEqual(r['inspected_rvas'],['0x1290'])
            with self.assertRaises(FileExistsError):
                bench.inspect(out,root/'index')
            self.assertEqual((out/'result.json').read_bytes(),original)
            outside = root/'outside'
            outside.mkdir()
            (out.parent/'link').symlink_to(outside)
            with self.assertRaises(ValueError):
                bench.inspect(out.parent/'link/new',root/'index')


if __name__ == '__main__':
    unittest.main()
