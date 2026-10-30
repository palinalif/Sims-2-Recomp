"""Authored endpoint/oracle controls; no original game bytes or states."""
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/reference_startup.py'
spec = importlib.util.spec_from_file_location('startup_reference', PATH)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class StartupReferenceTests(unittest.TestCase):
    def test_deterministic_case_coverage_and_cookie_branches(self):
        cases = b.cases()
        self.assertEqual(cases, b.cases())
        self.assertEqual(len(cases), 320)
        self.assertEqual(len({c['stack'] for c in cases}), 4)
        self.assertEqual(sum(bool(b.oracle(c)['events']) for c in cases), 160)
        for cookie, entropy, want in ((b.DEFAULT,b.DEFAULT,b.DEFAULT+1),
                (0,0,0x47110000),(1,1,0x47110001),(0,0xFFFF,0xFFFFFFFF),
                (0,0x10000,0x10000),(0x10000,0,0x10000),
                (b.M,0,b.M)):
            self.assertEqual(b.cookie_value(cookie, entropy)[0], want)

    def test_stdcall_output_pairs_and_cleanup(self):
        case = b.cases()[0]
        hs = case['sp']-12
        for k in range(4):
            writes = []
            pop = k in (0,3)
            arg = hs-(16 if k == 0 else 24) if pop else None
            result, after = b.endpoint(k, hs-(32 if pop else 28), b.RETURNS[k],
                arg, case, lambda a,n: bytes(n), lambda a,p: writes.append((a,p)))
            self.assertEqual(after, hs-24)
            self.assertEqual(len(writes), int(pop))
            if pop:
                self.assertEqual(writes[0][0], arg)
                self.assertEqual(len(writes[0][1]), 8)
            self.assertIsInstance(result, int)

    def test_endpoint_bad_order_frame_pointer_and_zeroing_reject(self):
        case = b.cases()[0]
        hs = case['sp']-12
        good = [0, hs-32, b.RETURNS[0], hs-16]
        for position, value in ((0,4),(0,-1),(1,hs-28),(2,b.RETURN),(3,hs-12)):
            args = good.copy(); args[position] = value
            with self.subTest(position=position), self.assertRaises(ValueError):
                b.endpoint(*args,case,lambda a,n: bytes(n),lambda a,p: None)
        with self.assertRaises(ValueError):
            b.endpoint(*good,case,lambda a,n: b'\xA5'*n,lambda a,p: None)
        # QPC cleanup can be masked by LEAVE; boundary check must still reject.
        for k in (0,3):
            for wrong in (0,8):
                with self.assertRaises(ValueError):
                    b.endpoint(k,hs-32,b.RETURNS[k],hs-(16 if k==0 else 24),case,
                        lambda a,n: bytes(n),lambda a,p: None,cleanup=wrong)

    def test_each_observed_component_and_page_byte_is_required(self):
        state = b.oracle(b.cases()[0])
        b.verify_state(state, copy.deepcopy(state))
        for key in state:
            changed = copy.deepcopy(state)
            if isinstance(changed[key], int):
                changed[key] ^= 1
            elif isinstance(changed[key], bytes):
                v = bytearray(changed[key]); v[-1] ^= 1; changed[key] = bytes(v)
            else:
                changed[key][0] ^= 1
            with self.subTest(key=key), self.assertRaises(ValueError):
                b.verify_state(changed, state)
        with self.assertRaises(ValueError):
            b.verify_state({**state,'unobserved':0},state)

    def test_helper_frame_address_and_qpc_bool_independence(self):
        case = b.cases()[0]
        changed = copy.deepcopy(case); changed['qpc'] ^= 1
        self.assertEqual(b.oracle(case), b.oracle(changed))
        changed = copy.deepcopy(case); changed['values'][5] ^= 4
        self.assertNotEqual(b.oracle(case), b.oracle(changed))
        state = b.oracle(case)
        self.assertEqual(state['sp'],case['sp']+4)
        self.assertEqual(state['saved'],case['saved'])
        self.assertEqual(state['events'],[0,1,2,3])

    def test_authored_x86_transport_and_read_bounds(self):
        # A separate public fixture: no original bytes. It bypasses the helper,
        # writes an explicit immediate complement through EDX, leaving EAX alone.
        case = next(c for c in b.cases() if c['cookie'] == 0x10000)
        code = (bytes.fromhex('5657ba') + struct.pack('<I', (~case['cookie'])&b.M) +
                bytes.fromhex('8915') + struct.pack('<I', b.COMPLEMENT) + bytes.fromhex('5f5ec3'))
        codes = {b.INIT:code, b.HELPER:b'\xc3'}
        b.verify_state(b.exercise(codes,case), b.oracle(case))
        with self.assertRaises(ValueError):
            b.exercise(codes,case,budget=1)
        # Unmapped-in-the-contract, but mapped-in-the-page reads still reject.
        bad = bytes.fromhex('a1') + struct.pack('<I', b.COOKIE+8) + b'\xc3'
        with self.assertRaises(ValueError):
            b.exercise({b.INIT:bad,b.HELPER:b'\xc3'},case)
        with self.assertRaises(ValueError):
            unknown = b'\xba'+struct.pack('<I',b.API+4)+b'\xff\xe2'
            b.exercise({b.INIT:unknown,b.HELPER:b'\xc3'},case)

    @staticmethod
    def entry_code(call=b.INIT, tail=b.TAIL, opcode=0xE9):
        # Authored relative-control-flow fixture, assembled from public metadata.
        return (b'\xe8' + struct.pack('<I', (call-b.ENTRY-5)&b.M) +
                bytes([opcode]) + struct.pack('<I', (tail-b.ENTRY-10)&b.M))

    def test_entry_flow_requires_exact_direct_call_and_external_tail(self):
        code = self.entry_code()
        self.assertEqual(len(b.entry_flow(code)), 2)
        for bad in (code[:-1], code+b'\x90', self.entry_code(call=b.HELPER),
                    self.entry_code(tail=b.RETURN), self.entry_code(opcode=0xE8),
                    b'\xff\xd0'+code[2:]):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                b.entry_flow(bad)
        # Do NOT widen normal-return CFG semantics to accept escaping tails.
        with self.assertRaisesRegex(ValueError, 'Escaping normal flow'):
            b.decode_flow(code, b.ENTRY, lambda i:i)

    def test_entry_tail_keeps_caller_return_and_does_not_execute_target(self):
        for case in (c for c in b.cases() if c['cookie'] == 0x10000):
            init = (bytes.fromhex('5657ba') + struct.pack('<I', (~case['cookie'])&b.M) +
                    bytes.fromhex('8915') + struct.pack('<I', b.COMPLEMENT) +
                    bytes.fromhex('5f5ec3'))
            codes = {b.ENTRY:self.entry_code(), b.INIT:init, b.HELPER:b'\xc3'}
            actual = b.exercise(codes,case,entry=True)
            b.verify_state(actual, b.entry_oracle(case))
            self.assertEqual(actual['sp'],case['sp'])
            self.assertEqual(actual['eip'],b.TAIL)
            offset = case['sp']-case['stack']
            self.assertEqual(struct.unpack_from('<I', actual['stack'], offset)[0],b.RETURN)
            self.assertEqual(struct.unpack_from('<I', actual['stack'], offset-4)[0],b.ENTRY+5)
            # Tail's mapped bytes are zero, and absent from the instruction set:
            # reaching them would reject, not simulate success or return.
            for key in ('sp','eip','stack','saved','data','eax','events'):
                changed = copy.deepcopy(actual)
                if isinstance(changed[key], int):
                    changed[key] ^= 4
                elif isinstance(changed[key], bytes):
                    v = bytearray(changed[key]); v[offset] ^= 1; changed[key] = bytes(v)
                else:
                    changed[key] = [99]
                with self.subTest(key=key), self.assertRaises(ValueError):
                    b.verify_state(changed,b.entry_oracle(case))
            with self.assertRaises(ValueError):
                b.exercise(codes,case,entry=True,budget=1)
            with self.assertRaises(ValueError):
                b.exercise(codes,case)  # explicit mode required

    def test_run_keeps_boolean_mode_separate_from_body_addresses(self):
        # Exercise orchestration/preflight with public metadata only. In particular,
        # walking body addresses must not overwrite the explicit mode boolean.
        import pefile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            image = root/'work/interop-legacy-002/analysis-image.bin'
            image.parent.mkdir(parents=True); image.write_bytes(b'authored PE input')
            pin = hashlib.sha256(image.read_bytes()).hexdigest()
            provenance = dict(sourceImageSha256=pin,mode='readOnly',
                              analysisPerformed=False,headlessExitCode=0)
            for name in ('work/recomp-bench/run5-005-logs/helper.json.env.json',
                         'work/phase1-run3-010/caller.json.env.json'):
                path = root/name; path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(json.dumps(dict(provenance=provenance)))
            def get_data(rva, size):
                return self.entry_code() if rva == b.ENTRY-b.BASE else b'\xc3'*size
            pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(ImageBase=b.BASE),
                FILE_HEADER=SimpleNamespace(Machine=0x14C),get_data=get_data)
            sites = [dict(slot_rva=hex(s),call_rva=hex(c),
                     import_metadata=dict(dll='KERNEL32.dll',name=n))
                     for s,c,n in zip(b.SLOTS,b.CALLS,b.IMPORTS)]
            case = next(c for c in b.cases() if c['cookie'] == 0x10000)
            def exercise(codes, case, *, entry, **options):
                self.assertIs(type(entry),bool)
                self.assertEqual(set(codes),{b.INIT,b.HELPER,b.ENTRY} if entry else
                                           {b.INIT,b.HELPER})
                if options:
                    raise ValueError('authored negative control')
                return (b.entry_oracle if entry else b.oracle)(case)
            with patch.object(b,'ROOT',root), patch.object(b,'IMAGE_SHA',pin), \
                 patch.object(pefile,'PE',return_value=pe), \
                 patch.object(b,'decode_flow',side_effect=lambda code,*args:
                     (None,{},None,dict(reachable_bytes=len(code)))), \
                 patch.object(b,'dependencies',return_value=dict(indirect_call_sites=sites)), \
                 patch.object(b,'cases',return_value=[case]), \
                 patch.object(b,'exercise',side_effect=exercise):
                for mode in (False,True):
                    row = b.run(root/f'work/recomp-bench/mode-{mode}',entry=mode)
                    self.assertTrue(row['success'])
                    self.assertIs(row['entry_boundary'],mode)
                    self.assertFalse(row['tail_target_executed'])
                    self.assertEqual(row['rejected_controls'],4)

    def test_missing_input_and_output_guards(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(b,'ROOT',Path(temp)):
            root = Path(temp); out = root/'work/recomp-bench/test'
            with self.assertRaises(OSError):
                b.run(out)
            row = json.loads((out/'result.json').read_text())
            self.assertEqual(row['failed_stage'],'preflight')
            for key in ('success','fresh_x86_reference','lifted','compiled_for_aarch64',
                        'executed_under_qemu','android_executed','startup_executed'):
                self.assertFalse(row[key])
            before = (out/'result.json').read_bytes()
            with self.assertRaises(FileExistsError):
                b.run(out)
            self.assertEqual(before,(out/'result.json').read_bytes())
            outside = root/'outside'; outside.mkdir()
            (out.parent/'link').symlink_to(outside)
            for path in (outside/'new',out.parent/'link/new'):
                with self.assertRaises(ValueError):
                    b.run(path)
            self.assertEqual(list(outside.iterdir()),[])


if __name__ == '__main__':
    unittest.main()
