"""Authored oracle and transport tests, not original-game fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_opener_init.py'
spec = importlib.util.spec_from_file_location('opener_init', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c
# Deliberately synthetic PCs: transport tests do not embed recovered code.
CALLS = [(c.BASE+c.ZERO_INIT,c.BASE+m.ROOT_RVA+8)]+[
    (c.BASE+c.BUFFER_INIT,c.BASE+m.ROOT_RVA+16+8*n) for n in range(5)]


class OpenerInitTests(unittest.TestCase):
    def test_corpus_exact_span_and_preservation(self):
        objects, stacks = set(), set()
        for n in range(64):
            regs, pages = m.state(n)
            before = copy.deepcopy((regs,pages))
            self.assertEqual((regs,pages),m.state(n))
            result = m.oracle(regs,pages,CALLS[-1][1])
            self.assertEqual((regs,pages),before)
            objects.add(regs['edx']); stacks.add(regs['esp'])
            off = regs['edx']-c.DATA_PAGES[1]
            raw = bytes.fromhex(result['pages'])
            page = raw[4096:8192]
            initialized = bytearray(m.SPAN)
            struct.pack_into('<I',initialized,84,1)
            self.assertEqual(page[off:off+m.SPAN],initialized)
            self.assertTrue(all(pages[c.DATA_PAGES[1]][off:off+m.SPAN]))
            self.assertEqual(page[:off],pages[c.DATA_PAGES[1]][:off])
            self.assertEqual(page[off+m.SPAN:],pages[c.DATA_PAGES[1]][off+m.SPAN:])
            self.assertEqual(result['regs'],[dict(regs,eax=1,ecx=0,esp=regs['esp']+4)[r] for r in c.REGS])
            self.assertEqual(struct.unpack_from('<I',raw,regs['esp']-c.DATA_PAGES[0]-4)[0],CALLS[-1][1])
        self.assertEqual(len(objects),4); self.assertEqual(len(stacks),2)
        self.assertIn(c.DATA_PAGES[1]+4096-m.SPAN,objects)

    def test_oracle_rejects_invalid_receiver_stack_and_return(self):
        regs,pages = m.state(0)
        for field,value in (('edx',c.DATA_PAGES[1]-4),('edx',c.DATA_PAGES[1]+4096-m.SPAN+4),
                            ('edx',c.DATA_PAGES[1]+1),('esp',c.DATA_PAGES[0])):
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                m.oracle(dict(regs,**{field:value}),pages,CALLS[-1][1])
        bad = copy.deepcopy(pages)
        struct.pack_into('<I',bad[c.DATA_PAGES[0]],regs['esp']-c.DATA_PAGES[0],0)
        with self.assertRaises(ValueError): m.oracle(regs,bad,CALLS[-1][1])
        with self.assertRaises(ValueError): m.oracle(regs,pages,0)

    def test_sequence_requires_all_six_ordered_edges(self):
        m.validate_calls(CALLS)
        bad = copy.deepcopy(CALLS);bad[0]=(c.BASE+c.BUFFER_INIT,bad[0][1])
        duplicate = copy.deepcopy(CALLS);duplicate[2]=duplicate[1]
        for calls in (CALLS[:-1],CALLS+[CALLS[-1]],list(reversed(CALLS)),bad,duplicate):
            with self.subTest(calls=calls),self.assertRaises(ValueError):m.validate_calls(calls)

    def test_transport_retains_bodies_and_resets_sequence(self):
        bodies = {r:f'static void opener_{r:X}(void) {{ /* authored */ }}' for r in m.UNITS}
        text = m.assemble(bodies,CALLS)
        for body in bodies.values():self.assertEqual(text.count(body),1)
        self.assertIn('cache_reset(pages);call_index=0;',text)
        self.assertIn('if(call_index!=6) reject();',text)
        self.assertIn('switch(call_index++)',text)
        self.assertIn('caller!=0xA0002570u',text)
        for n,(target,ret) in enumerate(CALLS):
            self.assertIn(f'case {n}: if(target!=0x{target:08X}u) reject(); return 0x{ret:08X}u;',text)
        with self.assertRaises(ValueError):m.assemble({m.ROOT_RVA:'body'},CALLS)

    def test_bridge_faults_root_scoped_and_exact_targets(self):
        good = m.bridge_source('valid')
        self.assertIn('targets{0xA0002570u,0xA0001A40u,0xA0001A00u}',good)
        self.assertNotIn('memory->write32(s[3]+112,1)',good)
        self.assertIn('if(depth==1) memory->write32(s[3]+112,1)',m.bridge_source('wrong-slot'))
        self.assertIn('if(depth==1) s[7]+=8',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('stub')

    def test_comparator_rejects_memory_register_truncation_and_false_controls(self):
        expected = [dict(case=n,**m.oracle(*m.state(n),CALLS[-1][1])) for n in range(64)]
        text = '\n'.join(json.dumps(r) for r in expected)
        c.assess(text,expected,'valid')
        for mode,field in (('wrong-slot','pages'),('wrong-cleanup','regs')):
            bad = copy.deepcopy(expected)
            for row in bad:
                if field == 'regs':row[field][7]+=8
                else:
                    raw = bytearray.fromhex(row[field]);raw[4096]^=1;row[field]=raw.hex()
            changed = '\n'.join(json.dumps(r) for r in bad)
            c.assess(changed,expected,mode)
            with self.assertRaises(ValueError):c.assess(changed,expected,'valid')
            with self.assertRaises(ValueError):c.assess(text,expected,mode)
        with self.assertRaises(ValueError):c.assess(text.rsplit('\n',1)[0],expected,'valid')

    def test_output_policy_before_private_input_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)/'result'
            with self.assertRaises(ValueError):m.run(Path(tmp),out)
            self.assertFalse(out.exists())

    def test_invalid_corpus_indices(self):
        for n in (-1,64,True,1.0):
            with self.subTest(n=n),self.assertRaises(ValueError):m.state(n)


if __name__ == '__main__':unittest.main()
