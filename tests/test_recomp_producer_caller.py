"""Authored caller-composition contracts; no private code, tables or fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

from test_recomp_classifier_scan import images

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_producer_caller.py'
spec = importlib.util.spec_from_file_location('producer_caller_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ProducerCallerTests(unittest.TestCase):
    def expected(self, regs, pages, sample):
        handle, sp = regs['eax'], regs['esp']
        offset = handle-m.scan.PAGES[1]
        pointer, selector = struct.unpack_from('<2I', pages[m.scan.PAGES[1]], offset+0xd0)
        names = m.scan.names_from_pages({p:pages[p] for p in m.scan.IMAGES})
        hits = [i for i,name in enumerate(names) if name.lower() == sample.lower()]
        value = 6 if pointer == 0 else hits[0] if hits else 0xffffffff
        after = copy.deepcopy(pages)
        if value != 0xffffffff:
            obj, link = handle+0x7c, handle+0x78
            first, second = (0x10b00,0x10b30) if selector else (0x10970,0x109a0)
            for off,word in ((0,m.c.BASE+first),(4,m.c.BASE+second),
                             (0x34,m.c.BASE+0xfcf0),(0x4c,link)):
                struct.pack_into('<I', after[m.scan.PAGES[1]], obj-m.scan.PAGES[1]+off, word)
            after[m.scan.PAGES[1]][obj-m.scan.PAGES[1]+0x49] = value
            struct.pack_into('<I', after[m.scan.PAGES[1]], link-m.scan.PAGES[1], obj)
        else:
            struct.pack_into('<I', after[m.scan.PAGES[0]], sp-m.scan.PAGES[0]-8, pointer)
        out = dict(regs,eax=18 if value == 0xffffffff else 0,esp=sp+4)
        if value == 0xffffffff: out['edx'] = 0
        return selector,value,dict(regs=[out[r] for r in m.c.REGS],pages=b''.join(after[p] for p in m.scan.PAGES).hex())

    def test_both_selections_every_scan_outcome_and_deterministic_fixtures(self):
        data = images(); original = copy.deepcopy(data); outcomes = set()
        for n in range(128):
            regs,pages,sample = m.state(n,data)
            self.assertEqual((regs,pages,sample),m.state(n,data))
            selector,value,result = self.expected(regs,pages,sample)
            self.assertEqual(m.contract(regs,pages,sample,result),(selector,value))
            outcomes.add((selector,value))
        self.assertEqual(outcomes,{(s,v) for s in (0,1) for v in (*range(7),0xffffffff)})
        self.assertEqual(data,original)
        for n in (-1,128,True):
            with self.assertRaises(ValueError): m.state(n,data)

    def test_contract_rejects_return_cleanup_preservation_and_nonstack_writes(self):
        for n in (0,1,24,25,122,123):
            regs,pages,sample = m.state(n,images())
            _,_,result = self.expected(regs,pages,sample)
            for r in ('eax','ebx','ebp','esi','edi','esp'):
                bad = copy.deepcopy(result); bad['regs'][m.c.REGS.index(r)] ^= 4
                with self.assertRaises(ValueError): m.contract(regs,pages,sample,bad)
            for page in range(1,6):
                bad = copy.deepcopy(result); final = bytearray.fromhex(bad['pages'])
                final[page*4096] ^= 1; bad['pages'] = final.hex()
                with self.assertRaises(ValueError): m.contract(regs,pages,sample,bad)

    def test_failure_argument_binding_and_null_provider_are_required(self):
        regs,pages,sample = m.state(24,images())
        _,value,result = self.expected(regs,pages,sample)
        self.assertEqual(value,0xffffffff)
        bad = copy.deepcopy(result); final = bytearray.fromhex(bad['pages'])
        final[regs['esp']-m.scan.PAGES[0]-8] ^= 4; bad['pages'] = final.hex()
        with self.assertRaises(ValueError): m.contract(regs,pages,sample,bad)
        struct.pack_into('<I',pages[m.scan.PAGES[1]],regs['eax']-m.scan.PAGES[1]+0x74,1)
        with self.assertRaises(ValueError): m.contract(regs,pages,sample,result)

    def test_six_verbatim_bodies_exact_dispatch_and_unbound_services(self):
        bodies = {r:f'static void marker_{r:X}() {{}}' for r in m.TARGETS}
        text = m.assemble(bodies)
        for body in bodies.values(): self.assertEqual(text.count(body),1)
        self.assertIn('for(unsigned n=0;n<128;++n)',text)
        self.assertIn('cache_invoke(0xA00020D0u,in,adapter_20D0)',text)
        self.assertIn('target==0xA0010B60u)) return 0xA00020F8u;',text)
        self.assertIn('caller==0xA00020D0u && target==0xA0001460u) return 0xA000210Fu;',text)
        self.assertIn('default:reject();',text)
        self.assertNotIn('case 0xA0831A6Fu:',text)
        self.assertNotIn('case 0xA00102D0u:',text)
        with self.assertRaises(ValueError): m.assemble({m.RVA:bodies[m.RVA]})

    def test_controls_only_modify_authored_bridge(self):
        valid = m.bridge_source('valid')
        self.assertIn('targets{0xA00020D0u,0xA00109D0u,0xA0010B60u,0xA0010700u,0xA000FCB0u,0xA0001460u}',valid)
        for mode,fault in (('wrong-result','s[0]^=4;'),('wrong-cleanup','s[7]+=8;')):
            self.assertEqual(m.bridge_source(mode),valid.replace('    current(s.data());','    current(s.data());\n    if(depth==1) '+fault))
        self.assertIn('a+=4;',m.bridge_source('wrong-slot'))
        with self.assertRaises(ValueError): m.bridge_source('unknown')

    def test_transport_strictness_and_behavioral_negative_controls(self):
        row = dict(case=0,regs=[0]*8,pages='00'*(6*4096))
        expected = [dict(row,case=n) for n in range(128)]
        encode = lambda rows: '\n'.join(json.dumps(r) for r in rows)
        text = encode(expected)
        self.assertEqual(m.assess(text,expected,'valid')['matched'],128)
        bad = copy.deepcopy(expected)
        for r in bad: r['regs'] = [4]+[0]*7
        for mode in ('wrong-result','wrong-cleanup','wrong-slot'):
            self.assertTrue(m.assess(encode(bad),expected,mode)['negative_control_rejected'])
            with self.assertRaises(ValueError): m.assess(text,expected,mode)
        for rows in (expected[:-1],expected+[expected[-1]],list(reversed(expected))):
            with self.assertRaises(ValueError): m.assess(encode(rows),expected,'valid')
        for malformed in (dict(case=0,rejected=True),dict(row,case=False),dict(row,pages='g'*len(row['pages'])),
                          dict(row,regs=[True]*8),dict(row,extra=1)):
            with self.assertRaises(ValueError): m.assess(encode([malformed]+expected[1:]),expected,'wrong-result')


if __name__ == '__main__': unittest.main()
