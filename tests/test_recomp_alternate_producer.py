"""Alternate producer contracts on authored state only; no proprietary fixtures."""
import copy
import json
import struct
import unittest

from test_recomp_classifier_scan import m, images


class AlternateProducerTests(unittest.TestCase):
    def expected(self, n):
        regs, pages, sample = m.producer_state(n, images())
        _, obj, link, pointer = struct.unpack_from('<4I', pages[m.PAGES[0]], regs['esp']-m.PAGES[0])
        names = m.names_from_pages(images())
        matches = [i for i, name in enumerate(names) if name.lower() == sample.lower()]
        value = 6 if pointer == 0 else matches[0] if matches else 0xffffffff
        final = copy.deepcopy(pages)
        if value != 0xffffffff:
            for offset, word in ((0, m.c.BASE+0x10b00), (4, m.c.BASE+0x10b30),
                                 (0x34, m.c.BASE+0xfcf0), (0x4c, link)):
                struct.pack_into('<I', final[m.PAGES[1]], obj-m.PAGES[1]+offset, word)
            final[m.PAGES[1]][obj-m.PAGES[1]+0x49] = value
            struct.pack_into('<I', final[m.PAGES[1]], link-m.PAGES[1], obj)
        out = dict(regs, eax=int(value != 0xffffffff), esp=regs['esp']+4)
        result = dict(regs=[out[r] for r in m.c.REGS], pages=b''.join(final[p] for p in m.PAGES).hex())
        return regs, pages, sample, result, value

    def test_success_failure_null_and_every_class_without_mutating_inputs(self):
        counts = {}
        for n in range(64):
            regs, pages, sample, result, value = self.expected(n)
            before = copy.deepcopy(pages)
            self.assertEqual(m.producer_contract(regs,pages,sample,result,m.ALTERNATE),value)
            self.assertEqual(pages,before)
            self.assertEqual(self.expected(n),(regs,pages,sample,result,value))
            counts[value] = counts.get(value,0)+1
            if value != 0xffffffff:
                with self.assertRaises(ValueError): m.producer_contract(regs,pages,sample,result)
        self.assertEqual(counts,{**{i:6 for i in range(6)}, 0xffffffff:27, 6:1})

    def test_wrong_callback_class_publication_and_retained_bytes_reject(self):
        for n in (0, 12, 61):  # success, miss, null
            regs,pages,sample,result,_ = self.expected(n)
            obj,link = struct.unpack_from('<II',pages[m.PAGES[0]],regs['esp']-m.PAGES[0]+4)
            for address in (obj,obj+4,obj+0x34,obj+0x49,obj+0x4c,link,obj+0x20):
                bad = copy.deepcopy(result)
                data = bytearray.fromhex(bad['pages'])
                data[4096+address-m.PAGES[1]] ^= 1
                bad['pages'] = data.hex()
                with self.assertRaises(ValueError): m.producer_contract(regs,pages,sample,bad,m.ALTERNATE)
            for r in ('eax','ebx','ebp','esi','edi','esp'):
                bad = copy.deepcopy(result); bad['regs'][m.c.REGS.index(r)] ^= 1
                with self.assertRaises(ValueError): m.producer_contract(regs,pages,sample,bad,m.ALTERNATE)

    def test_exact_alternate_dispatch_returns_and_verbatim_bodies(self):
        bodies = {r:'static void authored_'+str(r)+'() { /* A00109D0 A00109DA adapter_109D0 */ }'
                  for r in (m.RVA,m.c.MODULE_COMPARE,m.ALTERNATE)}
        text = m.assemble(bodies,True,m.ALTERNATE)
        for body in bodies.values(): self.assertEqual(text.count(body),1)
        self.assertIn('case 0xA0010B60u: initialization_producer_10B60();break;',text)
        self.assertIn('caller==0xA0010B60u && target==0xA0010700u) return 0xA0010B6Au;',text)
        self.assertIn('cache_invoke(0xA0010B60u,in,adapter_10B60)',text)
        self.assertIn('default:reject();',text)
        valid = m.bridge_source(m.c.BRIDGE.read_text(),'valid',True,m.ALTERNATE)
        self.assertIn('targets{0xA0010700u,0xA000FCB0u,0xA0010B60u}',valid)
        self.assertNotIn('0xA00109D0u',valid)
        for mode in m.MODES[1:]:
            bad = m.bridge_source(m.c.BRIDGE.read_text(),mode,True,m.ALTERNATE)
            self.assertNotEqual(bad,valid)
            self.assertIn('if(depth==1)',bad)
        with self.assertRaises(ValueError): m.assemble({m.ALTERNATE:'body'},True,m.ALTERNATE)

    def test_compared_components_and_complete_behavioral_controls(self):
        expected = [dict(case=n,**self.expected(n)[3]) for n in range(64)]
        self.assertEqual(m.c.assess('\n'.join(map(json.dumps,expected)),expected,'valid')['matched'],64)
        for mode,index,delta in (('wrong-result',0,4),('wrong-cleanup',7,8)):
            bad = copy.deepcopy(expected)
            for row in bad: row['regs'][index] ^= delta
            text = '\n'.join(map(json.dumps,bad))
            self.assertEqual(m.c.assess(text,expected,mode)['differing_cases'],64)
            with self.assertRaises(ValueError): m.c.assess(text,expected,'valid')
            with self.assertRaises(ValueError): m.c.assess('\n'.join(text.splitlines()[:-1]),expected,mode)
        for index in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][index] ^= 1
            with self.assertRaises(ValueError): m.c.assess('\n'.join(map(json.dumps,bad)),expected,'valid')
        for page in range(6):
            bad = copy.deepcopy(expected); data = bytearray.fromhex(bad[0]['pages']); data[page*4096+17] ^= 1
            bad[0]['pages'] = data.hex()
            with self.assertRaises(ValueError): m.c.assess('\n'.join(map(json.dumps,bad)),expected,'valid')

    def test_profiles_fail_closed_and_main_dispatch_unchanged(self):
        self.assertEqual(m.producer_profile(m.ALTERNATE)[1:],(0x10b00,0x10b30))
        self.assertEqual(m.producer_profile(m.producer.RVA)[1:],(0x10970,0x109a0))
        for bad in (True,'10b60',0,0x10b61):
            with self.assertRaises(ValueError): m.producer_profile(bad)
            with self.assertRaises(ValueError): m.bridge_source(m.c.BRIDGE.read_text(),'valid',True,bad)
        bodies = {r:'/* authored '+str(r)+' */' for r in (m.RVA,m.c.MODULE_COMPARE,m.producer.RVA)}
        self.assertEqual(m.assemble(bodies,True),m.assemble(bodies,True,m.producer.RVA))
        self.assertIn('return 0xA00109DAu;',m.assemble(bodies,True))


if __name__ == '__main__': unittest.main()
