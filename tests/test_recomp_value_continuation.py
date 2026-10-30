"""Authored caller-tail contracts only; no proprietary fixtures required."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_value_continuation.py'
spec = importlib.util.spec_from_file_location('value_continuation',PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ValueContinuationTests(unittest.TestCase):
    def fixture(self, marker=0, text=b'authored-value'):
        regs = dict(zip(m.c.REGS,range(8)))
        regs['esp'] = m.c.DATA_PAGES[0]+0x800
        obj = m.value.heap.ARENA
        node,source,head,owned = (obj+x for x in (0x300,0x400,0x500,0x600))
        pages = {p:bytearray([0xa5])*4096 for p in m.value.PAGES}
        arena = pages[obj]
        for offset in (0x60,0x1b4):struct.pack_into('<I',arena,offset,0)
        struct.pack_into('<I',arena,0x1dc,source+len(text)+1)
        struct.pack_into('<2I',arena,0x300,owned,0x12345678)
        struct.pack_into('<I',arena,0x500,0x87654321)
        arena[0x204] = marker
        arena[0x400:0x400+len(text)+1] = text+b'\0'
        arena[0x600:0x604] = b'key\0'
        frame = [obj,node,0,source,head,101,102,103,104,105,106,m.c.RETURN]
        struct.pack_into('<12I',pages[m.c.DATA_PAGES[0]],0x800,*frame)
        after = copy.deepcopy(pages)
        raw = after[obj]+after[m.g.EXTRA]
        record,payload = obj+m.value.OCCUPIED,obj+m.value.OCCUPIED+32
        value = text+(bytes([marker]) if marker else b'')
        struct.pack_into('<7I',raw,m.value.OCCUPIED,
            node,0x87654321,0x12345678,0,payload,len(value),24+len(value))
        raw[m.value.OCCUPIED+32:m.value.OCCUPIED+32+len(value)] = value
        for offset,word in ((0x304,record),(0x500,record),(0x1dc,source)):
            struct.pack_into('<I',raw,offset,word)
        after[obj],after[m.g.EXTRA] = raw[:4096],raw[4096:]
        out = [0]*8
        for name,val in dict(eax=obj,ebx=103,esi=106,edi=101,ebp=102,esp=regs['esp']+48).items():
            out[m.c.REGS.index(name)] = val
        result = dict(regs=out,pages=b''.join(after[p] for p in m.value.PAGES).hex())
        service = m.value.model()
        end = m.value.OCCUPIED//8+4+(24+len(value)+7)//8
        service.cells = [True]*end+[False]*(m.g.SIZE//8-end)
        service.calls,service.requests = 2,[28,24+len(value)]
        return regs,pages,result,service

    def test_marker_and_payload_tails_return_with_owned_key(self):
        for marker in (0,1,255):
            for size in (1,3,4,5,31,36):
                m.contract(*self.fixture(marker,b'x'*size))

    def test_all_fifteen_behavior_controls_reject(self):
        fixture = self.fixture()
        m.contract(*fixture)
        self.assertEqual(m.reject_controls(*fixture),15)

    def test_heap_ownership_requests_and_call_counts_are_required(self):
        for kind in ('ownership','request','calls'):
            args = self.fixture()
            service = args[-1]
            if kind=='ownership':service.cells[0]=False
            elif kind=='request':service.requests[0]+=8
            else:service.calls=3
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.contract(*args)

    def test_callback_free_list_empty_value_and_wrong_return_sentinel_reject(self):
        for kind in ('callback','free-list','empty','sentinel'):
            regs,pages,result,service = self.fixture()
            obj = m.value.heap.ARENA
            if kind=='sentinel':struct.pack_into('<I',pages[m.c.DATA_PAGES[0]],0x800+44,0)
            elif kind=='empty':pages[obj][0x400]=0
            else:struct.pack_into('<I',pages[obj],0x60 if kind=='callback' else 0x1b4,1)
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.contract(regs,pages,result,service)

    def test_frame_restoration_is_from_stack_not_pending_registers(self):
        regs,pages,result,service = self.fixture()
        for name in ('ebx','esi','edi','ebp'):regs[name]=0xdeadbeef
        m.contract(regs,pages,result,service)
        for name in ('ebx','esi','edi','ebp'):
            bad = copy.deepcopy(result);bad['regs'][m.c.REGS.index(name)]=regs[name]
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,service)

    def test_protocol_length_keys_and_frame_bounds_reject(self):
        for kind in ('truncated','extra-key','short-regs','unaligned','out-of-page'):
            regs,pages,result,service = self.fixture()
            if kind=='truncated':result['pages']=result['pages'][:-2]
            elif kind=='extra-key':result['stop_pc']=m.ENTRY
            elif kind=='short-regs':result['regs'].pop()
            elif kind=='unaligned':regs['esp']+=1
            else:regs['esp']=m.c.DATA_PAGES[0]+4096-44
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.contract(regs,pages,result,service)

    def test_real_call_entry_preserves_arguments_and_explicit_service(self):
        regs,pages,result,_ = self.fixture()
        with patch.object(m.c,'reference',return_value=(result,{m.ENTRY})) as ref:
            actual,seen,service=m.advance(regs,pages,{}, {})
        self.assertIs(actual,result)
        self.assertEqual(seen,{m.ENTRY})
        self.assertEqual(ref.call_args.args[2],m.ENTRY)
        self.assertEqual(m.ENTRY,m.c.BASE+0x3861)
        self.assertIs(ref.call_args.args[3],regs)
        self.assertIs(ref.call_args.args[4],pages)
        self.assertIs(ref.call_args.kwargs['heap_service'],service)
        self.assertEqual(service.calls,0)
        self.assertNotIn('stop_before_call',ref.call_args.kwargs)
        self.assertNotIn('stop_before_pc',ref.call_args.kwargs)
        self.assertEqual(sum(service.cells),m.value.OCCUPIED//8)

    def test_state_uses_existing_pin_and_restores_real_stack(self):
        import json
        regs,pages,_,_=self.fixture()
        raw=b''.join(pages[p] for p in m.value.PAGES)
        rows=[dict(case=n,after=dict(pages=raw.hex(),regs=[regs[r] for r in m.c.REGS],
              boundary=dict(site=m.ENTRY,target=m.c.BASE+m.value.ROOT_RVA))) for n in range(64)]
        with patch.object(m.c,'digest',return_value=m.value.BOUNDARY_SHA), \
             patch.object(Path,'read_text',return_value=json.dumps(rows)):
            out,restored=m.state(0)
            self.assertEqual(out,regs)
            self.assertEqual(restored,pages)
            for kind in ('count','case','boundary','regs','pages'):
                bad=copy.deepcopy(rows)
                if kind=='count':bad.pop()
                elif kind=='case':bad[0]['case']=1
                elif kind=='boundary':bad[0]['after']['boundary']['target']+=4
                elif kind=='regs':bad[0]['after']['regs'].pop()
                else:bad[0]['after']['pages']='00'
                with patch.object(Path,'read_text',return_value=json.dumps(bad)):
                    with self.subTest(kind=kind),self.assertRaises(ValueError):m.state(0)
        for n in (-1,64,True,0.5):
            with self.assertRaises(ValueError):m.state(n)
        with patch.object(m.c,'digest',return_value='wrong'):
            with self.assertRaises(ValueError):m.state(0)

    def test_receipt_source_audit_accepts_json_keys_and_rejects_mutation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'authored.py'
            source.write_text('# authored fixture\n')
            pins={str(source):m.c.digest(source)}
            m.verify_sources(pins)
            source.write_text('# changed fixture\n')
            with self.assertRaises(ValueError):m.verify_sources(pins)
            source.unlink()
            with self.assertRaises(FileNotFoundError):m.verify_sources(pins)

    def test_enclosing_opener_epilogue_is_an_explicit_original_unit(self):
        self.assertIn(0x3c50,m.UNITS)
        self.assertEqual(m.UNITS[0x3c50],m.g.p.node.p.UNITS[0x3c50])
        self.assertEqual(set(m.UNITS),{0x3700,0x3c50,*m.value.UNITS})


if __name__=='__main__':unittest.main()
