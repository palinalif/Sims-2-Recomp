"""Public authored contracts only; no original instructions or states."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_setter.py'
spec = importlib.util.spec_from_file_location('member_init', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RVA = 0x122f0


class OpenerMemberInitTests(unittest.TestCase):
    def test_profile_is_complete_call_free_unit(self):
        _, pin, size, count, blocks = m.unit(RVA)
        self.assertEqual((size,count,blocks),(25,5,((0,25),)))
        self.assertEqual(len(pin),64)
        self.assertEqual(m.modes(RVA),m.DESCRIPTOR_MODES)
        self.assertEqual(m.body_name(RVA),'opener_member_122F0')

    def test_full_state_contract_preserves_uninitialized_member(self):
        objects,stacks = set(),set()
        for n in range(64):
            regs,pages = m.state(n,RVA)
            before = copy.deepcopy((regs,pages))
            self.assertEqual((regs,pages),m.state(n,RVA))
            sp = regs['esp']-m.DATA_PAGES[0]
            obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],sp+4)[0]
            off = obj-m.DATA_PAGES[1]
            result = m.oracle(regs,pages,RVA)
            after = copy.deepcopy(pages)
            struct.pack_into('<I',after[m.DATA_PAGES[1]],off,m.BASE+0x12220)
            struct.pack_into('<II',after[m.DATA_PAGES[1]],off+8,0,1)
            self.assertEqual(result['pages'],b''.join(after[p] for p in m.PAGES).hex())
            self.assertEqual(result['regs'],[dict(regs,eax=obj,esp=regs['esp']+4)[r] for r in m.REGS])
            self.assertNotEqual(struct.unpack_from('<I',pages[m.DATA_PAGES[1]],off+4)[0],0)
            self.assertEqual((regs,pages),before)
            objects.add(obj);stacks.add(regs['esp'])
        self.assertEqual(len(objects),4);self.assertEqual(len(stacks),2)
        self.assertIn(m.DATA_PAGES[1]+4096-16,objects)

    def test_invalid_corpus_and_bounds_rejected(self):
        for n in (-1,64,True,1.0):
            with self.assertRaises(ValueError):m.state(n,RVA)
        regs,pages = m.state(0,RVA)
        for obj in (m.DATA_PAGES[1]-4,m.DATA_PAGES[1]+4096-12,m.DATA_PAGES[1]+1):
            bad = copy.deepcopy(pages)
            struct.pack_into('<I',bad[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4,obj)
            with self.assertRaises(ValueError):m.oracle(regs,bad,RVA)
        for esp in (m.DATA_PAGES[0]-4,m.DATA_PAGES[0]+4092,m.DATA_PAGES[0]+1):
            with self.assertRaises(ValueError):m.oracle(dict(regs,esp=esp),pages,RVA)

    def test_wrong_return_and_page_shape_rejected(self):
        regs,pages = m.state(0,RVA)
        bad = copy.deepcopy(pages)
        struct.pack_into('<I',bad[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0],0)
        with self.assertRaises(ValueError):m.oracle(regs,bad,RVA)
        with self.assertRaises(ValueError):m.oracle(regs,{**pages,m.DATA_PAGES[1]:b''},RVA)

    def test_transport_keeps_body_and_only_exact_target(self):
        body = 'static void opener_member_122F0(void) { /* authored fixture */ }'
        text = m.assemble(body,RVA)
        self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA00122F0u,in,adapter_122F0)',text)
        good = m.bridge_source(m.BRIDGE.read_text(),'valid',RVA)
        self.assertIn('targets{0xA00122F0u}',good)
        self.assertIn('s[0]^=4;',m.bridge_source(m.BRIDGE.read_text(),'wrong-result',RVA))
        self.assertIn('s[7]+=8;',m.bridge_source(m.BRIDGE.read_text(),'wrong-cleanup',RVA))
        with self.assertRaises(ValueError):m.bridge_source(m.BRIDGE.read_text(),'stub',RVA)

    def test_preserved_member_mutation_and_false_controls_reject(self):
        expected = [dict(case=n,**m.oracle(*m.state(n,RVA),RVA)) for n in range(64)]
        good = '\n'.join(json.dumps(row) for row in expected)
        m.assess(good,expected,'valid')
        for mode in ('wrong-result','wrong-cleanup'):
            changed = copy.deepcopy(expected)
            for row in changed:row['regs'][0 if mode=='wrong-result' else 7]^=4
            text = '\n'.join(json.dumps(row) for row in changed)
            m.assess(text,expected,mode)
            with self.assertRaises(ValueError):m.assess(text,expected,'valid')
            with self.assertRaises(ValueError):m.assess(good,expected,mode)
        bad = copy.deepcopy(expected)
        regs,pages = m.state(0,RVA)
        obj = struct.unpack_from('<I',pages[m.DATA_PAGES[0]],regs['esp']-m.DATA_PAGES[0]+4)[0]
        raw = bytearray.fromhex(bad[0]['pages'])
        raw[4096+obj-m.DATA_PAGES[1]+4]^=1
        bad[0]['pages']=raw.hex()
        with self.assertRaises(ValueError):m.assess('\n'.join(json.dumps(row) for row in bad),expected,'valid')
        with self.assertRaises(ValueError):m.assess(good.rsplit('\n',1)[0],expected,'valid')


if __name__ == '__main__':unittest.main()
