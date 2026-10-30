"""Public authored sequence/transport tests; no private game fixture required."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_continuous_opener.py'
spec = importlib.util.spec_from_file_location('continuous_native',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.c


class ContinuousNativeTests(unittest.TestCase):
    def trace_fixture(self):
        # Two sites invoke one leaf; a third call repeats the first leaf's
        # own site. The observer must not deduplicate or sort these events.
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        import probe_continuous_opener as ref
        regs,pages = ref.state(0,bytes(4096))
        entry = c.BASE+0x2000
        body = b'\xe8'+struct.pack('<i',11)+b'\xe8'+struct.pack('<i',6)+b'\xc3'+b'\x90'*5+b'\xc3'
        decoder = Cs(CS_ARCH_X86,CS_MODE_32); decoder.detail=True
        nodes = {i.address:i for i in decoder.disasm(body,entry)}
        return entry,regs,pages,nodes,{entry:body+bytes(4096-len(body))}

    def test_call_observation_matches_unobserved_reference_and_keeps_order(self):
        entry,regs,pages,nodes,code = self.trace_fixture()
        args = (nodes,code,entry,regs,pages)
        kwargs = dict(image_pages=m.IMAGES,extra_data_pages=m.EXTRA_PAGES)
        before = copy.deepcopy((regs,pages))
        expected = c.reference(*args,**kwargs)
        trace = []
        self.assertEqual(c.reference(*args,call_trace=trace,**kwargs),expected)
        self.assertEqual(trace,[(entry,entry+16,entry+5),(entry+5,entry+16,entry+10)])
        self.assertEqual((regs,pages),before)

    def test_observer_rejects_nonempty_nonlist_and_preserves_stop_before_call(self):
        entry,regs,pages,nodes,code = self.trace_fixture()
        kwargs = dict(image_pages=m.IMAGES,extra_data_pages=m.EXTRA_PAGES)
        for invalid in ((),{},False,[('stale',)]):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                c.reference(nodes,code,entry,regs,pages,call_trace=invalid,**kwargs)
        trace = []
        result,_ = c.reference(nodes,code,entry,regs,pages,call_trace=trace,
                              stop_before_call=(entry,entry+16),**kwargs)
        self.assertEqual(trace,[])
        self.assertEqual(result['boundary'],dict(site=entry,target=entry+16))

    def test_observer_records_actual_indirect_heap_target_without_inventing_response(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        regs,pages = m.reference.state(0,bytes(4096))
        entry = c.BASE+0x2000
        body = b''.join(b'\x68'+struct.pack('<I',v) for v in (9,8,m.heap.HANDLE))
        body += b'\xff\x15'+struct.pack('<I',m.heap.IAT)+b'\xc3'
        decoder = Cs(CS_ARCH_X86,CS_MODE_32); decoder.detail=True
        nodes = {i.address:i for i in decoder.disasm(body,entry)}
        service,trace = m.model(),[]
        result,_ = c.reference(nodes,{entry:body+bytes(4096-len(body)),
            m.heap.SERVICE:bytes(4096)},entry,regs,pages,
            image_pages=m.IMAGES,extra_data_pages=m.EXTRA_PAGES,
            heap_service=service,call_trace=trace)
        self.assertEqual(trace,[(entry+15,m.heap.SERVICE,entry+21)])
        self.assertEqual(service.requests,[(8,9)])
        self.assertEqual(result['regs'][0],m.heap.ARENA)
        self.assertEqual(result['regs'][-1],regs['esp']+4)

    def fixture(self):
        base = c.BASE
        edges = [(base+0x1330,base+m.WRAPPER,base+0x1397),
                 (base+0x1330,base+m.WRAPPER,base+0x13a9)]
        trace = [(base+0x1392,base+m.WRAPPER,base+0x1397),
                 (base+0x13a4,base+m.WRAPPER,base+0x13a9),
                 (base+0x1392,base+m.WRAPPER,base+0x1397)]
        return edges,[trace.copy() for _ in range(64)]

    def test_schedule_preserves_repeated_sites_and_rejects_exhaustion(self):
        edges,traces = self.fixture()
        declarations,cases,resets,checks = m.schedule(edges,traces)
        self.assertIn('static unsigned continuous_edge_0;',declarations)
        self.assertIn('case 0:return 0xA0001397u;',cases)
        self.assertIn('case 1:return 0xA00013A9u;',cases)
        self.assertIn('case 2:return 0xA0001397u;',cases)
        self.assertIn('default:reject();',cases)
        self.assertEqual(resets,'continuous_edge_0=0;')
        self.assertEqual(checks,'if(continuous_edge_0!=3) reject();')

    def test_schedule_rejects_case_drift_unknown_edge_owner_and_wrong_return(self):
        edges,traces = self.fixture()
        for kind in ('count','empty','drift','edge','owner','return'):
            bad = copy.deepcopy(traces)
            if kind == 'count': bad.pop()
            elif kind == 'empty': bad = [[] for _ in range(64)]
            elif kind == 'drift': bad[1].pop()
            else:
                site,target,ret = bad[0][0]
                if kind == 'edge': target += 1
                elif kind == 'owner': site = 1
                else: ret += 1
                bad = [[(site,target,ret)] for _ in range(64)]
            with self.subTest(kind=kind),self.assertRaises(ValueError): m.schedule(edges,bad)

    def test_transport_keeps_authored_bodies_and_checks_both_tail_edges(self):
        edges,traces = self.fixture()
        bodies = {r:f'static void capacity_{r:X}(void) {{ /* authored {r:x} */ }}'
                  for r in m.UNITS}
        text = m.assemble_traced(bodies,edges,c.BASE+m.RVA+20,traces)
        for body in bodies.values(): self.assertEqual(text.count(body),1)
        self.assertIn('0xA083A371u && target==0xA0849A00u',text)
        self.assertIn('0xA0831A6Fu && target==0xA08461F2u',text)
        self.assertIn('continuous_edge_0=0;cache_reset(pages);',text)
        self.assertIn('if(continuous_edge_0!=3) reject();cache_copy(pages);',text)
        self.assertIn('unsigned char pages[8*4096]',text)
        self.assertIn('return direct_return(caller,target);',text)
        self.assertIn('#define recomp_rep_movs checked_rep',text)

    def test_bridge_starts_empty_and_extends_only_explicit_writable_pages(self):
        for mode in m.rig.MODES:
            text = m.bridge_source(mode)
            self.assertIn('constexpr std::array<uint32_t,8> bases{',text)
            self.assertIn(f'0x{m.heap.ARENA:08X}u,8192)',text)
            self.assertNotIn('occupied prefix',text)
            self.assertIn('(write?5u:8u)',text)
            self.assertIn('p<8;',text)
        self.assertEqual(set(m.TAIL_WRAPPERS),{m.WRAPPER,m.reference.calloc.WRAPPER})
        self.assertTrue(all(m.REFERENCE_OPTIONS.values()))


if __name__ == '__main__': unittest.main()
