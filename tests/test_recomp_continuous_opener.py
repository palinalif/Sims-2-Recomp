"""Authored fixtures for continuous reference orchestration, not game code."""
import copy
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_continuous_opener.py'
spec = importlib.util.spec_from_file_location('continuous_opener',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.c


def mode():
    page = bytearray(4096)
    start = m.b.MODE_TEXT-m.b.MODE_PAGE
    page[start:start+10] = b'key=value\0'
    return page


def authored_result(n):
    regs,pages = m.state(n,mode())
    arena = bytearray(pages[m.heap.ARENA]+pages[m.EXTRA])
    source = pages[c.DATA_PAGES[3]]
    sample = source[m.b.t.SOURCE_OFFSET:source.index(0,m.b.t.SOURCE_OFFSET)+1]
    text = sum(m.b.t.opener.REQUESTS)+8
    key = text+len(sample)
    marker = m.b.MODE_BYTES[n%8]
    payload_text = b'value'+(bytes([marker]) if marker else b'')
    node,owned = m.tail.g.p.node.START,m.tail.g.p.OCCUPIED+8
    record,payload = m.value.OCCUPIED,m.value.OCCUPIED+32
    slots = sum(m.b.t.REQUESTS)
    arena[text:text+len(sample)] = sample
    arena[key:key+6] = b'value\0'
    arena[owned:owned+4] = b'key\0'
    arena[payload:payload+len(payload_text)] = payload_text
    for off,value in ((0xd0,m.heap.ARENA+text),(0x1dc,m.heap.ARENA+key),
                      (0x1e0,m.heap.ARENA+key),(0x204,marker)):
        struct.pack_into('<I',arena,off,value)
    struct.pack_into('<II',arena,node,m.heap.ARENA+owned,m.heap.ARENA+record)
    struct.pack_into('<I',arena,0x1b0,m.heap.ARENA+record)
    struct.pack_into('<7I',arena,record,m.heap.ARENA+node,0,0,0,
                     m.heap.ARENA+payload,len(payload_text),24+len(payload_text))
    struct.pack_into('<3I',arena,0x160,m.heap.ARENA+slots,64,1)
    arena[slots:slots+256] = bytes(256)
    struct.pack_into('<I',arena,slots,m.heap.ARENA+node)
    after = copy.deepcopy(pages)
    after[m.heap.ARENA],after[m.EXTRA] = arena[:4096],arena[4096:]
    out = dict(regs,eax=m.heap.ARENA,esp=regs['esp']+4)
    result = dict(regs=[out[r] for r in c.REGS],pages=b''.join(after[p] for p in m.ORDER).hex())
    requests = [(0,s) for s in m.b.t.REQUESTS]+[(8,256),(8,8),(0,1032),
                                            (0,28),(0,24+len(payload_text))]
    used = sum((s+7)//8 for _,s in requests)
    service = SimpleNamespace(requests=requests,cells=[True]*used+[False]*(m.SIZE//8-used))
    return regs,pages,result,service


class ContinuousOpenerTests(unittest.TestCase):
    def test_state_is_original_entry_fixture_with_all_storage_available_from_start(self):
        for n in range(64):
            regs,pages = m.state(n,mode())
            self.assertEqual((regs,pages),m.state(n,mode()))
            self.assertEqual(set(pages),set(m.ORDER))
            self.assertEqual(pages[m.EXTRA],bytearray([0xa5])*4096)
            self.assertEqual(pages[c.DATA_PAGES[3]].index(0,m.b.t.SOURCE_OFFSET)-m.b.t.SOURCE_OFFSET,
                             m.SOURCE_LENGTHS[n%8])
            sp = regs['esp']-c.DATA_PAGES[0]
            self.assertEqual(struct.unpack_from('<I',pages[c.DATA_PAGES[0]],sp)[0],c.RETURN)
        with self.assertRaises(ValueError): m.state(0,b'bad')

    def test_advance_uses_one_entry_cpu_and_both_exact_arithmetic_options(self):
        regs,pages = m.state(0,mode())
        with patch.object(c,'reference',return_value=({'authored':True},{123})) as reference:
            result,seen,service = m.advance(regs,pages,{}, {})
        args,kw = reference.call_args
        self.assertIs(args[3],regs); self.assertIs(args[4],pages)
        self.assertEqual(args[2],c.BASE+0x3c50)
        self.assertEqual(kw['budget'],4096)
        self.assertTrue(kw['checked_integer_multiply']); self.assertTrue(kw['checked_calloc_arithmetic'])
        self.assertNotIn('stop_before_call',kw); self.assertNotIn('stop_before_pc',kw)
        self.assertIs(kw['heap_service'],service); self.assertEqual(service.requests,[])
        self.assertEqual(seen,{123}); self.assertEqual(result,{'authored':True})

    def test_independent_contract_and_all_negative_controls(self):
        for n in range(64):
            regs,pages,result,service = authored_result(n)
            original = copy.deepcopy((regs,pages,result,service))
            m.contract(n,regs,pages,result,service)
            self.assertEqual(m.reject_controls(n,regs,pages,result,service),16)
            self.assertEqual((regs,pages,result,service.__dict__),
                             (*original[:3],original[3].__dict__))

    def test_contract_rejects_request_and_ownership_drift_and_truncation(self):
        regs,pages,result,service = authored_result(0)
        for change in ('flags','size','cells','truncated'):
            bad,heap = copy.deepcopy((result,service))
            if change == 'flags': heap.requests[4]=(0,256)
            elif change == 'size': heap.requests[-1]=(0,1)
            elif change == 'cells': heap.cells[-1]=True
            else: bad['pages']=bad['pages'][:-2]
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.contract(0,regs,pages,bad,heap)

    def service_stream(self,requests,*,handle=None):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        regs,pages = m.state(0,mode())
        entry = c.BASE+0x2000; code = bytearray()
        handle = m.heap.HANDLE if handle is None else handle
        for flags,size in requests:
            for value in (size,flags,handle): code += b'\x68'+struct.pack('<I',value)
            code += b'\xe8'+struct.pack('<i',m.heap.SERVICE-(entry+len(code)+5))
        code += b'\xc3'
        md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
        nodes={i.address:i for i in md.disasm(bytes(code),entry)}
        service=m.ArenaModel()
        result,_=c.reference(nodes,{entry:bytes(code)+bytes(4096-len(code)),m.heap.SERVICE:bytes(4096)},
            entry,regs,pages,image_pages=m.b.IMAGES,extra_data_pages=(m.EXTRA,),heap_service=service)
        return regs,pages,result,service

    def test_service_preserves_dirty_bytes_and_zeroes_rounded_extent_across_page(self):
        requests=[(0,4096),(0,5),(8,9)]
        regs,pages,result,service=self.service_stream(requests)
        self.assertEqual(service.requests,requests)
        raw=bytes.fromhex(result['pages'])
        out={p:raw[i*4096:(i+1)*4096] for i,p in enumerate(m.ORDER)}
        self.assertEqual(out[m.heap.ARENA],pages[m.heap.ARENA])
        self.assertEqual(out[m.EXTRA][:8],pages[m.EXTRA][:8])
        self.assertEqual(out[m.EXTRA][8:24],bytes(16))
        self.assertEqual(out[m.EXTRA][24:],pages[m.EXTRA][24:])
        self.assertEqual(result['regs'][0],m.EXTRA+8)
        self.assertEqual(result['regs'][-1],regs['esp']+4)
        self.assertEqual(sum(service.cells),515)

    def test_service_rejects_invalid_flags_token_sizes_exhaustion_and_unbounded_calls(self):
        for requests,handle in (([(1,8)],None), ([(8,8)],0), ([(0,0)],None),
            ([(0,4097)],None), ([(0,4096)]*3,None), ([(0,8)]*17,None)):
            with self.subTest(requests=requests,handle=handle),self.assertRaises(ValueError):
                self.service_stream(requests,handle=handle)


if __name__ == '__main__': unittest.main()
