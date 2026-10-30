"""Authored producer publication contracts; no game bytes or private fixtures."""
import copy
import struct
import unittest

from test_recomp_classifier_scan import images, m


class ProducerScanTests(unittest.TestCase):
    def expected(self, regs, pages, sample):
        _, obj, link, pointer = struct.unpack_from('<4I', pages[m.PAGES[0]], regs['esp']-m.PAGES[0])
        names = m.names_from_pages({p:pages[p] for p in m.IMAGES})
        hits = [i for i,name in enumerate(names) if name.lower() == sample.lower()]
        value = 6 if not pointer else hits[0] if hits else 0xffffffff
        after = copy.deepcopy(pages)
        if value != 0xffffffff:
            for offset, word in ((0,m.c.BASE+0x10970),(4,m.c.BASE+0x109a0),(0x34,m.c.BASE+0xfcf0),(0x4c,link)):
                struct.pack_into('<I',after[m.PAGES[1]],obj-m.PAGES[1]+offset,word)
            after[m.PAGES[1]][obj-m.PAGES[1]+0x49] = value
            struct.pack_into('<I',after[m.PAGES[1]],link-m.PAGES[1],obj)
        out = dict(regs,eax=int(value != 0xffffffff),esp=regs['esp']+4)
        return value, dict(regs=[out[r] for r in m.c.REGS],pages=b''.join(after[p] for p in m.PAGES).hex())

    def test_inline_fixtures_cover_publication_and_failure_without_alias(self):
        data = images(); original = copy.deepcopy(data); outcomes = set()
        for n in range(64):
            regs,pages,sample = m.producer_state(n,data)
            self.assertEqual((regs,pages,sample),m.producer_state(n,data))
            _,obj,link,pointer = struct.unpack_from('<4I',pages[m.PAGES[0]],regs['esp']-m.PAGES[0])
            self.assertEqual(obj,link+4)
            self.assertTrue(pointer == 0 or m.c.DATA_PAGES[3] <= pointer < m.c.DATA_PAGES[3]+4096)
            value,result = self.expected(regs,pages,sample)
            outcomes.add(m.producer_contract(regs,pages,sample,result))
            self.assertEqual(value,m.producer_contract(regs,pages,sample,result))
        self.assertEqual(outcomes,{*range(7),0xffffffff})
        self.assertEqual(data,original)

    def test_contract_rejects_wrong_result_nonvolatile_cleanup_and_memory(self):
        for n in (0,12,61):  # success, miss, null-input success
            regs,pages,sample = m.producer_state(n,images())
            _,result = self.expected(regs,pages,sample)
            for r in ('eax','ebx','ebp','esi','edi','esp'):
                bad = copy.deepcopy(result); bad['regs'][m.c.REGS.index(r)] ^= 1
                with self.assertRaises(ValueError): m.producer_contract(regs,pages,sample,bad)
            for offset in (4096+128,8192,12288,16384,20480):
                bad = copy.deepcopy(result); final = bytearray.fromhex(bad['pages'])
                final[offset] ^= 1; bad['pages'] = final.hex()
                with self.assertRaises(ValueError): m.producer_contract(regs,pages,sample,bad)
            bad = copy.deepcopy(result); bad['pages'] = bad['pages'][:-2]
            with self.assertRaises(ValueError): m.producer_contract(regs,pages,sample,bad)

    def test_three_bodies_verbatim_and_exact_two_nested_call_returns(self):
        bodies = {r:'static void marker_'+str(r)+'() {}' for r in (m.RVA,m.c.MODULE_COMPARE,m.producer.RVA)}
        text = m.assemble(bodies,True)
        for body in bodies.values(): self.assertEqual(text.count(body),1)
        self.assertIn('caller==0xA00109D0u && target==0xA0010700u) return 0xA00109DAu;',text)
        self.assertIn('caller==0xA0010700u && target==0xA000FCB0u) return 0xA001071Eu;',text)
        self.assertIn('cache_invoke(0xA00109D0u,in,adapter_109D0)',text)
        self.assertIn('default:reject();',text)
        with self.assertRaises(ValueError): m.assemble({m.RVA:bodies[m.RVA]},True)
        valid = m.bridge_source(m.c.BRIDGE.read_text(),'valid',True)
        self.assertIn('targets{0xA0010700u,0xA000FCB0u,0xA00109D0u}',valid)
        for mode,fault in (('wrong-result','s[0]^=4;'),('wrong-cleanup','s[7]+=8;')):
            self.assertEqual(m.bridge_source(m.c.BRIDGE.read_text(),mode,True),valid.replace('    current(s.data());','    current(s.data());\n    if(depth==1) '+fault))
