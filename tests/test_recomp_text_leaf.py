"""Named standalone text-leaf quantities; authored inputs only, no game fixture."""
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('text_leaf', ROOT/'scripts/recomp/execute_text_leaf.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class TextLeafTests(unittest.TestCase):
    def test_buffer_backing_nondecreasing_range_and_full_byte_domain(self):
        observed = set()
        for n in range(64):
            regs, pages = b.leaf_state(n, {p:bytes(4096) for p in b.IMAGE_PAGES})
            frame = struct.unpack_from('<5I', pages[b.DATA_PAGES[0]], regs['esp']-b.DATA_PAGES[0])
            ret, descriptor, cursor, end, out = frame
            self.assertEqual(ret, b.RETURN)
            self.assertEqual(descriptor, b.BASE+0xe17ab0)
            self.assertEqual(out, b.DATA_PAGES[1]+128+0x1c8)
            self.assertLessEqual(cursor, end)
            self.assertLessEqual(end-cursor, 64)
            self.assertEqual(cursor, b.DATA_PAGES[2]+128)
            observed.update(pages[b.DATA_PAGES[2]][128:128+end-cursor])
            self.assertEqual(set(pages), set(b.PAGES))
        self.assertEqual(observed, set(range(256)))
        for n in (-1, 64, True):
            with self.assertRaises(ValueError): b.leaf_state(n, {})

    def test_standalone_transport_contains_verbatim_body_and_exact_entry(self):
        body = 'static void startup_009550(void) {}'
        text = b.assemble(body)
        self.assertEqual(text.count(body), 1)
        self.assertIn('cache_invoke(0xA0009550u,in,adapter_009550)', text)
        self.assertNotIn('adapter_1ABD40', text)
        self.assertNotIn('@BODY@', text)
        with self.assertRaises(ValueError): b.assemble('')

    def test_two_distinct_bridge_perturbations_require_unique_sites(self):
        text = b.BRIDGE.read_text()
        self.assertEqual(b.bridge_source(text, 'valid'), text)
        self.assertIn('a^=4', b.bridge_source(text, 'counter-destinations'))
        self.assertIn('s[7]-=4', b.bridge_source(text, 'return-frame'))
        for mode in b.MODES[1:]:
            for bad in ('', text+text):
                with self.assertRaises(ValueError): b.bridge_source(bad, mode)
        with self.assertRaises(ValueError): b.bridge_source(text, 'unknown')

    def test_strict_comparison_and_complete_mutant_stream_required(self):
        expected = [dict(case=n, regs=[0]*8, pages='00'*(len(b.PAGES)*4096)) for n in range(64)]
        encode = lambda rows:'\n'.join(json.dumps(r) for r in rows)
        text = encode(expected)
        self.assertEqual(b.assess(text, expected, 'valid')['matched'], 64)
        with self.assertRaises(ValueError): b.assess(text, expected, 'return-frame')
        wrong = [dict(r, regs=[1]+r['regs'][1:]) for r in expected]
        for mode in b.MODES[1:]:
            self.assertEqual(b.assess(encode(wrong), expected, mode)['differing_cases'], 64)
        with self.assertRaises(ValueError): b.assess(encode(wrong), expected, 'valid')
        for malformed in (encode(wrong[:-1]), encode(wrong+[wrong[-1]]),
                          encode([dict(case=n, rejected=True) for n in range(64)]),
                          text.replace('"case": 0', '"case": 1', 1),
                          text.replace('"case": 0', '"case": 0, "case": 0', 1)):
            with self.assertRaises(ValueError): b.assess(malformed, expected, 'return-frame')

    def test_thunk_entry_has_service_pointer_and_same_owned_range(self):
        images = {p:bytes(4096) for p in b.IMAGE_PAGES}
        for n in range(64):
            regs, pages = b.thunk_state(n, images)
            leaf_regs, leaf_pages = b.leaf_state(n, images)
            self.assertEqual(regs, leaf_regs)
            offset = regs['esp']-b.DATA_PAGES[0]+4
            self.assertEqual(struct.unpack_from('<I', pages[b.DATA_PAGES[0]], offset)[0],
                             b.DATA_PAGES[1]+128+0x7c)
            self.assertNotEqual(pages, leaf_pages)
            struct.pack_into('<I', pages[b.DATA_PAGES[0]], offset, b.BASE+0xe17ab0)
            self.assertEqual(pages, leaf_pages)

    def test_thunk_transport_preserves_bodies_and_fail_closed_tail_guard(self):
        leaf = 'static void startup_009550(void) {}'
        thunk = 'static void startup_00FCF0(void) {}'
        text = b.assemble(leaf, thunk)
        self.assertEqual(text.count(leaf), 1)
        self.assertEqual(text.count(thunk), 1)
        self.assertIn('cache_invoke(0xA000FCF0u,in,adapter_00FCF0)', text)
        self.assertIn('g_cur_func!=0xA000FCF0u || target!=0xA0009550u', text)
        self.assertNotIn('cache_invoke(0xA0009550u,in,adapter_009550)', text)
        for bad in ('', 0):
            with self.assertRaises(ValueError): b.assemble(leaf, bad)

    def test_thunk_contract_rejects_argument_return_and_cleanup_corruption(self):
        regs, pages = b.thunk_state(0, {p:bytes(4096) for p in b.IMAGE_PAGES})
        final = bytearray(b''.join(bytes(pages[p]) for p in b.PAGES))
        offset = regs['esp']-b.DATA_PAGES[0]
        struct.pack_into('<I', final, offset+4, b.BASE+0xe17ab0)
        state = dict(regs=[regs[r] for r in b.REGS], pages=final.hex())
        state['regs'][-1] += 4
        b.assert_thunk_poststate(regs, pages, state)
        for off in (0, 4, 8, 12, 16):
            wrong = final.copy(); wrong[offset+off] ^= 1
            with self.assertRaises(ValueError):
                b.assert_thunk_poststate(regs, pages, dict(state, pages=wrong.hex()))
        for change in (-4, 4):
            wrong_regs = state['regs'].copy(); wrong_regs[-1] += change
            with self.assertRaises(ValueError):
                b.assert_thunk_poststate(regs, pages, dict(state, regs=wrong_regs))
        with self.assertRaises(ValueError):
            b.assert_thunk_poststate(regs, pages, dict(state, pages=''))

    def test_thunk_bad_index_rejects_before_lifter_or_image_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = Path(tmp)/'index.json'
            provenance = dict(sourceImageSha256=b.IMAGE_SHA, mode='readOnly',
                analysisPerformed=False, headlessExitCode=0, outputParseError=None)
            query = dict(query=dict(rva='0xfcf0'), program=dict(imageBaseVa=hex(b.BASE)))
            env = dict(schema='sims2-ghidra-query-envelope/1', provenance=provenance, result=query)
            mutations = [dict(env, schema='wrong')]
            for k, v in dict(sourceImageSha256='bad', mode='write', analysisPerformed=True,
                             headlessExitCode=1, outputParseError='bad').items():
                mutations.append(dict(env, provenance=dict(provenance, **{k:v})))
            mutations.append(dict(env, result=dict(query, query=dict(rva='0x9550'))))
            mutations.append(dict(env, result=dict(query, program=dict(imageBaseVa='0'))))
            for bad in mutations:
                index.write_text(json.dumps(bad))
                with self.assertRaises(ValueError): b.lift_thunk(None, Path(tmp), index)

    def test_missing_fresh_lift_records_failure_not_execution(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(b, 'ROOT', Path(tmp)), \
                patch('execute_cache_skip.ROOT', Path(tmp)), \
                patch.object(b.subprocess, 'run', side_effect=FileNotFoundError):
            out = Path(tmp)/'work/recomp-bench/absent'
            with self.assertRaises(FileNotFoundError): b.run(out, Path('missing'))
            receipt = json.loads((out/'result.json').read_text())
            self.assertFalse(receipt['success'])
            self.assertFalse(receipt['arm64_executed'])
            self.assertFalse(receipt['android_executed'])
            self.assertEqual(receipt['failed_stage'], 'fresh-switch-lift')
            with self.assertRaises(FileExistsError): b.run(out, Path('missing'))


if __name__ == '__main__': unittest.main()
