"""Authored value/list contracts; no private inputs or game-derived bytes."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_value_assignment.py'
spec = importlib.util.spec_from_file_location('value_assignment',PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ValueAssignmentTests(unittest.TestCase):
    def fixture(self, marker=0, value=b'authored-value'):
        regs = dict(zip(m.c.REGS,range(8)))
        regs['esp'] = m.c.DATA_PAGES[0]+0x800
        pages = {p:bytearray([0xa5])*4096 for p in m.PAGES}
        arena = m.heap.ARENA
        node, source, head = arena+0x300, arena+0x400, arena+0x500
        raw = pages[arena]
        struct.pack_into('<I',raw,0x1b4,0)
        struct.pack_into('<I',raw,0x60,0)
        raw[0x204] = marker
        struct.pack_into('<I',raw,0x304,0x12345678)
        struct.pack_into('<I',raw,0x500,0x87654321)
        raw[0x400:0x400+len(value)+1] = value+b'\0'
        struct.pack_into('<6I',pages[m.c.DATA_PAGES[0]],0x800,
                         m.c.RETURN,arena,node,0,source,head)
        after = copy.deepcopy(pages)
        record, payload = arena+m.OCCUPIED, arena+m.OCCUPIED+32
        text = value+(bytes([marker]) if marker else b'')
        expected = after[arena]+after[m.g.EXTRA]
        struct.pack_into('<7I',expected,m.OCCUPIED,
            node,0x87654321,0x12345678,0,payload,len(text),24+len(text))
        expected[m.OCCUPIED+32:m.OCCUPIED+32+len(text)] = text
        struct.pack_into('<I',expected,0x304,record)
        struct.pack_into('<I',expected,0x500,record)
        after[arena],after[m.g.EXTRA] = expected[:4096],expected[4096:]
        out = [regs[r] for r in m.c.REGS];out[0]=1;out[7]+=4
        result = dict(regs=out,pages=b''.join(after[p] for p in m.PAGES).hex())
        model = m.model();model.calls=2;model.requests=[28,24+len(text)]
        return regs,pages,result,model

    def test_marker_and_rep_width_tail_contracts(self):
        for marker in (0,1,255):
            for size in (1,2,3,4,5,7,8,31,32):
                m.contract(*self.fixture(marker,b'x'*size))

    def test_every_published_word_payload_and_dirty_slack_rejects(self):
        regs,pages,result,model = self.fixture()
        for offset in [0x304,0x500,*range(m.OCCUPIED,m.OCCUPIED+28,4),
                       m.OCCUPIED+28,m.OCCUPIED+32,m.OCCUPIED+60,8191]:
            bad = copy.deepcopy(result);raw=bytearray.fromhex(bad['pages'])
            raw[2*4096+offset if offset<4096 else 4*4096+offset-4096]^=1
            bad['pages']=raw.hex()
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                m.contract(regs,pages,bad,model)

    def test_immutable_pages_and_full_abi_reject(self):
        regs,pages,result,model = self.fixture()
        for i in (0,1,4,5,6,7):
            bad=copy.deepcopy(result);bad['regs'][i]^=4
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        for p in (1,3,5,6,7):
            bad=copy.deepcopy(result);raw=bytearray.fromhex(bad['pages']);raw[p*4096]^=1;bad['pages']=raw.hex()
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        for calls,requests in ((0,[]),(1,[28]),(2,[32,38]),(3,[28,38])):
            model.calls,model.requests=calls,requests
            with self.assertRaises(ValueError):m.contract(regs,pages,result,model)

    def test_unverified_free_list_callback_and_empty_sentinel_reject(self):
        for offset in (0x1b4,0x60,0x400):
            regs,pages,result,model=self.fixture()
            if offset==0x400:pages[m.heap.ARENA][offset]=0
            else:struct.pack_into('<I',pages[m.heap.ARENA],offset,1)
            with self.assertRaises(ValueError):m.contract(regs,pages,result,model)

    def test_transport_keeps_body_and_checks_rep_without_raw_host_mapping(self):
        bodies={r:f'/* authored {r:x} */' for r in m.UNITS}
        edges=[(m.c.BASE+m.ROOT_RVA,m.c.BASE+m.WRAPPER,m.c.BASE+r) for r in (0x1397,0x13a9)]
        text=m.assemble(bodies,edges,m.c.BASE+m.RVA+5)
        for body in bodies.values():self.assertEqual(text.count(body),1)
        self.assertIn('#define recomp_rep_movs checked_rep',text)
        self.assertIn('cache_read(src+j,1)',text)
        self.assertIn('cache_write(dst+j,1',text)
        self.assertIn('width!=1 && width!=4',text)
        self.assertIn('df!=1',text)
        self.assertIn('unsigned char pages[8*4096]',text)
        self.assertIn('adapter_1330',text)
        self.assertIn('value_calls=0;cache_reset(pages)',text)
        self.assertIn('if(value_calls>=2) reject()',text)
        self.assertIn('if(value_calls!=2) reject()',text)
        self.assertIn('0xA0001397u : 0xA00013A9u',text)
        for bad in ([],edges[:1],list(reversed(edges)),edges+[edges[0]]):
            with self.assertRaises(ValueError):m.assemble(bodies,bad,m.c.BASE+m.RVA+5)
        self.assertNotIn('@',text)
        with self.assertRaises(ValueError):m.assemble({},[],0)

    def test_bridge_owns_two_pages_and_binds_no_failure_responses(self):
        text=m.bridge_source('valid')
        self.assertIn('std::array<uint32_t,8> bases',text)
        self.assertIn('(write?5u:8u)',text)
        self.assertIn('p<8;',text)
        self.assertIn('invoke_allocate(r)',text)
        self.assertEqual(text.count('heap->allocate('),1)
        self.assertIn(f',0,{m.OCCUPIED})',text)
        self.assertNotIn('adapter_831A54',text)
        self.assertIn('s[0]+=8;',m.bridge_source('wrong-result'))
        self.assertIn('if(depth==1) s[7]+=4;',m.bridge_source('wrong-cleanup'))
        with self.assertRaises(ValueError):m.bridge_source('unknown')
        self.assertIn('std::array<uint32_t,6> bases',m.capacity.bridge_source('valid'))

    def test_allocation_model_is_independent_and_preserves_dirty_bytes(self):
        a,b=m.model(),m.model()
        self.assertEqual(len(a.cells),1024)
        self.assertEqual(sum(a.cells),m.OCCUPIED//8)
        a.cells[0]=False
        self.assertTrue(b.cells[0])
        self.assertEqual(a.calls,0)
        self.assertEqual(a.requests,[])

    def test_eight_page_comparator_rejects_behavior_and_malformed_controls(self):
        expected = [dict(case=n,regs=[0]*8,pages='00'*(len(m.PAGES)*4096)) for n in range(64)]
        encode = lambda rows:'\n'.join(json.dumps(r) for r in rows)
        self.assertEqual(m.assess(encode(expected),expected,'valid')['matched'],64)
        for mode in ('wrong-result','wrong-cleanup'):
            with self.assertRaises(ValueError):m.assess(encode(expected),expected,mode)
        for kind in ('reg','stack','last-page'):
            bad=copy.deepcopy(expected)
            if kind=='reg':bad[0]['regs'][7]=4
            else:
                pos=0 if kind=='stack' else len(bad[0]['pages'])-1
                text=bad[0]['pages'];bad[0]['pages']=text[:pos]+'1'+text[pos+1:]
            with self.assertRaises(ValueError):m.assess(encode(bad),expected,'valid')
            self.assertEqual(m.assess(encode(bad),expected,'wrong-result')['differing_cases'],1)
        for kind in ('truncated','duplicate','extra','rejected','six-page','hex','bool','wide'):
            bad=copy.deepcopy(expected)
            if kind=='truncated':bad.pop()
            elif kind=='duplicate':bad[1]['case']=0
            elif kind=='extra':bad[0]['ignored']=0
            elif kind=='rejected':bad[0]={'case':0,'rejected':True}
            elif kind=='six-page':bad[0]['pages']='00'*(6*4096)
            elif kind=='hex':bad[0]['pages']='G'+bad[0]['pages'][1:]
            elif kind=='bool':bad[0]['regs'][0]=True
            elif kind=='wide':bad[0]['regs'][0]=1<<32
            for mode in m.capacity.MODES:
                with self.subTest(kind=kind,mode=mode),self.assertRaises(ValueError):
                    m.assess(encode(bad),expected,mode)

    def test_missing_or_changed_live_input_fails_closed_before_read(self):
        for n in (-1,64,True,1.0):
            with self.assertRaises(ValueError):m.state(n)
        with patch.object(m.c,'digest',return_value='wrong'):
            with self.assertRaises(ValueError):m.state(0)


if __name__=='__main__':unittest.main()
