"""Public authored fixtures; no private game inputs or generated bodies."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_table_allocation.py'
spec = importlib.util.spec_from_file_location('table_allocation', PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, b = m.c, m.b


def fixture():
    regs,pages = b.state(0)
    pages[b.MODE_PAGE] = bytearray(4096)
    before = dict(boundary=dict(site=m.p.STOP[0],target=m.p.STOP[1]),
                  regs=[regs[r] for r in c.REGS],
                  pages=b''.join(pages[p] for p in (*c.DATA_PAGES,*b.IMAGES)).hex())
    service = m.AllocationModel()
    end = sum(b.t.REQUESTS)
    service.occupied[:(end+256)//8] = [True]*((end+256)//8)
    service.calls = 5
    pages[b.heap.ARENA][end:end+256] = bytes(256)
    struct.pack_into('<I',pages[b.heap.ARENA],0x160,b.heap.ARENA+end)
    after = dict(boundary=dict(site=m.STOP[0],target=m.STOP[1]),
                 regs=[regs[r] for r in c.REGS],
                 pages=b''.join(pages[p] for p in (*c.DATA_PAGES,*b.IMAGES)).hex())
    after['regs'][7] += 8
    return before,after,service


class TableAllocationTests(unittest.TestCase):
    def test_publication_zero_extent_ownership_and_controls(self):
        before,after,service = fixture()
        m.contract(before,after,service)
        m.reject_controls(before,after,service)

    def test_boundary_frame_and_descriptor_register_reject(self):
        before,after,service = fixture()
        for kind in ('target','site','esp','edi','truncated-regs','truncated-pages'):
            bad = copy.deepcopy(after)
            if kind in ('site','target'): bad['boundary'][kind] ^= 4
            elif kind in ('esp','edi'): bad['regs'][c.REGS.index(kind)] ^= 4
            elif kind == 'truncated-regs': bad['regs'].pop()
            else: bad['pages'] = bad['pages'][:-2]
            with self.subTest(kind=kind),self.assertRaises(ValueError): m.contract(before,bad,service)

    def test_resume_is_exact_independent_and_fails_closed(self):
        before,_,_ = fixture()
        regs,pages = m.resume(before)
        self.assertEqual(list(regs.values()),before['regs'])
        self.assertEqual(b''.join(pages[p] for p in (*c.DATA_PAGES,*b.IMAGES)).hex(),before['pages'])
        pages[b.heap.ARENA][0] ^= 1
        self.assertNotEqual(b''.join(pages[p] for p in (*c.DATA_PAGES,*b.IMAGES)).hex(),before['pages'])
        for field in ('boundary','regs','pages'):
            bad = copy.deepcopy(before)
            if field == 'boundary': bad[field]['site'] ^= 4
            elif field == 'regs': bad[field].pop()
            else: bad[field] = bad[field][:-2]
            with self.assertRaises(ValueError): m.resume(bad)

    def test_call_count_and_occupancy_are_not_empty_heap(self):
        before,after,service = fixture()
        for calls in (0,4,6):
            service.calls = calls
            with self.assertRaises(ValueError): m.contract(before,after,service)
        service.calls = 5; service.occupied[0] = False
        with self.assertRaises(ValueError): m.contract(before,after,service)

    def test_live_zero_service_preserves_prior_allocations(self):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        # Authored import call, NOT original code. Execute the fifth request
        # with four persistent allocations, verify the returned offset/zeroing.
        regs,pages = b.state(0)
        service = m.AllocationModel(); service.calls = 4
        end = sum(b.t.REQUESTS)
        service.occupied[:end//8] = [True]*(end//8)
        entry = c.BASE+0x2000
        code = b'\x68'+struct.pack('<I',256)+b'\x6a\x08\x68'+struct.pack('<I',b.heap.HANDLE)
        code += b'\xe8'+struct.pack('<i',b.heap.SERVICE-(entry+len(code)+5))+b'\xc3'
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(code,entry)}
        result,_ = c.reference(nodes,{entry:code+bytes(4096-len(code)),b.heap.SERVICE:bytes(4096)},
            entry,regs,pages,image_pages=b.heap.IMAGES,heap_service=service)
        raw = bytes.fromhex(result['pages'])[2*4096:3*4096]
        self.assertEqual(result['regs'][0],b.heap.ARENA+end)
        self.assertEqual(raw[:end],pages[b.heap.ARENA][:end])
        self.assertEqual(raw[end:end+256],bytes(256))
        self.assertEqual(raw[end+256:],pages[b.heap.ARENA][end+256:])
        self.assertEqual(service.calls,5)
        # A sixth request cannot silently allocate again.
        with self.assertRaises(ValueError): service.invoke(None,None,None)


if __name__ == '__main__': unittest.main()
