"""Public authored producer contracts; no original bytes or private fixture needed."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_initialization_producer.py'
sys.path.insert(0,str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location('producer_test',SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class InitializationProducerTests(unittest.TestCase):
    def test_deterministic_isolated_bounded_inputs_and_zero_argument(self):
        incoming = set()
        for n in range(64):
            regs,pages = m.state(n)
            self.assertEqual((regs,pages),m.state(n))
            obj,link = m.arguments(regs,pages)
            self.assertNotEqual(obj,link)
            self.assertEqual(struct.unpack_from('<I',pages[m.PAGES[0]],regs['esp']-m.PAGES[0]+12)[0],0)
            incoming.add(regs['edi'])
            pages[m.PAGES[1]][0] ^= 1
            self.assertNotEqual(pages,m.state(n)[1])
        self.assertEqual(len(incoming),64)
        for n in (-1,64,True):
            with self.assertRaises(ValueError): m.state(n)

    def test_independent_full_abi_writes_and_nested_frames(self):
        for n in range(64):
            regs,pages = m.state(n); before = copy.deepcopy((regs,pages))
            obj,link = m.arguments(regs,pages)
            result = m.oracle(regs,pages)
            # Success is a Boolean 1, not the publication-slot pointer left
            # in EAX during stores (the first private attempt caught this).
            out = dict(regs,eax=1,ecx=obj,esp=regs['esp']+4)
            self.assertEqual(result['regs'],[out[r] for r in m.REGS])
            expected = bytearray(b''.join(pages[p] for p in m.PAGES))
            def put(page,address,value):
                struct.pack_into('<I',expected,m.PAGES.index(page)*4096+address-page,value)
            for off,value in ((0,m.BASE+0x10970),(4,m.BASE+0x109a0),(0x34,m.BASE+0xfcf0),(0x4c,link)):
                put(m.PAGES[1],obj+off,value)
            expected[4096+obj-m.PAGES[1]+0x49] = 6
            put(m.PAGES[2],link,obj)
            put(m.PAGES[0],regs['esp']-4,regs['edi'])
            put(m.PAGES[0],regs['esp']-8,m.BASE+0x109da)
            self.assertEqual(result['pages'],expected.hex())
            self.assertEqual((regs,pages),before)

    def test_unsupported_contracts_reject_before_oracle(self):
        regs,pages = m.state(0)
        for offset,value in ((12,1),(12,0xffffffff),(4,m.PAGES[1]+4096-4),
                             (4,m.PAGES[1]+1),(8,m.PAGES[1]),(0,0)):
            bad = copy.deepcopy(pages)
            struct.pack_into('<I',bad[m.PAGES[0]],regs['esp']-m.PAGES[0]+offset,value)
            with self.assertRaises(ValueError): m.oracle(regs,bad)

    def test_verbatim_bodies_exact_dispatch_and_only_one_return_edge(self):
        bodies = {m.RVA:'static void initialization_producer_109D0(void) { /* authored */ }',
                  m.common.CLASSIFIER:'static void initialization_classifier_10700(void) { /* authored */ }'}
        text = m.assemble(bodies)
        for body in bodies.values(): self.assertEqual(text.count(body),1)
        self.assertIn('cache_invoke(0xA00109D0u,in,adapter_109D0)',text)
        self.assertIn('if(caller==0xA00109D0u && target==0xA0010700u) return 0xA00109DAu;',text)
        for rva in ('109D0','10700'):
            self.assertIn(f'case 0xA00{rva}u:',text)
        self.assertNotIn('case 0xA000FCB0u:',text)
        self.assertNotIn('void sub_A000FCB0(',text)
        self.assertIn('address_sub_A000FCB0=0xA000FCB0u',text)
        self.assertIn('default:reject();',text)
        with self.assertRaises(ValueError): m.assemble({m.RVA:bodies[m.RVA]})
        with self.assertRaises(ValueError): m.assemble(dict(bodies,external='body'))
        valid = m.bridge_source(m.common.BRIDGE.read_text(),'valid')
        self.assertIn('targets{0xA00109D0u,0xA0010700u}',valid)
        self.assertNotIn('0xA000FCB0u',valid)
        for mode,fault in [('wrong-slot','a+=4;'),('wrong-cleanup','if(depth==1) s[7]+=8;')]:
            # A nested-callee stack fault rejects before producing state. Only
            # the outer cleanup control is a measurable post-state difference.
            changed = m.bridge_source(m.common.BRIDGE.read_text(),mode)
            self.assertNotEqual(changed,valid); self.assertIn(fault,changed)
        with self.assertRaises(ValueError): m.bridge_source(valid,'unknown')

    def test_strict_full_state_comparison_and_nontrivial_controls(self):
        expected = [dict(case=n,**m.oracle(*m.state(n))) for n in range(64)]
        encode = lambda rows:'\n'.join(map(json.dumps,rows))
        self.assertEqual(m.common.assess(encode(expected),expected,'valid')['matched'],64)
        for mode in m.MODES[1:]:
            with self.assertRaises(ValueError): m.common.assess(encode(expected),expected,mode)
            bad = copy.deepcopy(expected)
            for row in bad: row['regs'][7] ^= 8
            self.assertEqual(m.common.assess(encode(bad),expected,mode)['differing_cases'],64)
        for reg in range(8):
            bad = copy.deepcopy(expected); bad[0]['regs'][reg] ^= 1
            with self.assertRaises(ValueError): m.common.assess(encode(bad),expected,'valid')
        for page in range(6):
            bad = copy.deepcopy(expected); b = bytearray.fromhex(bad[0]['pages']); b[page*4096] ^= 1
            bad[0]['pages'] = b.hex()
            with self.assertRaises(ValueError): m.common.assess(encode(bad),expected,'valid')
        for bad in (expected[:-1],[dict(case=0,rejected=True)]+expected[1:]):
            with self.assertRaises(ValueError): m.common.assess(encode(bad),expected,'wrong-slot')

    def test_index_provenance_extent_and_truncation_fail_closed(self):
        env = dict(schema='sims2-ghidra-query-envelope/1',provenance=dict(
            sourceImageSha256=m.common.IMAGE_SHA,mode='readOnly',analysisPerformed=False,
            headlessExitCode=0,outputParseError=None,ghidraVersion='authored'),
            queryLogSignals={'error':1}, result=dict(query={'rva':'0x109d0'},
            program={'imageBaseVa':hex(m.BASE)},truncation={'instructions':False},function=dict(
                resolution='function-at',entryRva='0x109d0',disassembly=dict(
                    instructionCount=18,extentBytes=61,extentEndVa='0xa0010a0c',
                    items=[{'va':'0xa00109d0'}]+[{} for _ in range(17)]))))
        self.assertTrue(m.check_index(env)['reliable_boundaries'])
        for key,value in [('instructionCount',17),('extentBytes',60),('extentEndVa','0xa0010a0d')]:
            bad = copy.deepcopy(env); bad['result']['function']['disassembly'][key] = value
            with self.assertRaises(ValueError): m.check_index(bad)
        bad = copy.deepcopy(env); bad['result']['truncation']['instructions'] = True
        with self.assertRaises(ValueError): m.check_index(bad)
        bad = copy.deepcopy(env); bad['provenance']['analysisPerformed'] = True
        with self.assertRaises(ValueError): m.check_index(bad)


if __name__ == '__main__': unittest.main()
