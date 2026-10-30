"""Authored fixtures only: exact-call capture and alternate-opener contracts."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_table_create.py'
spec = importlib.util.spec_from_file_location('table_create',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
b, c = m.b, m.c


def binding_fixture(n=0):
    regs,pages = b.state(n)
    pages[b.MODE_PAGE] = bytearray(4096)
    off = b.MODE_TEXT-b.MODE_PAGE
    pages[b.MODE_PAGE][off:off+5] = b'abc=\0'  # public authored grammar
    after = copy.deepcopy(pages)
    arena = after[b.heap.ARENA]
    chunk = sum(b.t.opener.REQUESTS)
    text = b.heap.ARENA+chunk+8
    source = pages[c.DATA_PAGES[3]]
    end = source.index(0,b.t.SOURCE_OFFSET)
    sample = source[b.t.SOURCE_OFFSET:end+1]
    key = text+len(sample)
    arena[chunk+8:chunk+8+len(sample)] = sample
    arena[key-b.heap.ARENA:key-b.heap.ARENA+4] = b'abc\0'
    for off,value in {0xd0:text,0x1d0:b.heap.ARENA+chunk,0x1d4:0,
                      0x1d8:b.heap.ARENA+sum(b.t.REQUESTS),0x1dc:key+4,0x1e0:key,
                      0x78:b.heap.ARENA+0x7c,0xc8:b.heap.ARENA+0x78,
                      0xb0:c.BASE+0xfcf0,0xd4:1,0x204:b.MODE_BYTES[n%8]}.items():
        struct.pack_into('<I',arena,off,value)
    struct.pack_into('<II',arena,chunk,0,1024)
    arena[0x160:0x170] = bytes(16); arena[0xc5] = 6
    out = dict(regs,esi=b.heap.ARENA,edi=b.heap.ARENA+0x160,esp=regs['esp']-32)
    struct.pack_into('<II',after[c.DATA_PAGES[0]],out['esp']-c.DATA_PAGES[0],key,8)
    observed = dict(boundary=dict(site=b.STOP[0],target=b.STOP[1]),
                    regs=[out[r] for r in c.REGS],
                    pages=b''.join(after[p] for p in (*b.heap.PAGES,b.MODE_PAGE)).hex())
    return regs,pages,observed


def creation_fixture(before):
    after = copy.deepcopy(before)
    after['boundary'] = dict(site=m.STOP[0],target=m.STOP[1])
    after['regs'][7] -= 36
    raw = bytearray.fromhex(after['pages'])
    struct.pack_into('<II',raw,after['regs'][7]-c.DATA_PAGES[0],64,4)
    after['pages'] = raw.hex()
    return after


class TableCreateTests(unittest.TestCase):
    def reference(self, code, *, extra=False, stop=True, **kwargs):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        regs,pages,_ = b.heap.state(0)
        images = b.heap.IMAGES
        if extra:
            pages[b.MODE_PAGE] = bytearray(4096); images = b.IMAGES
        entry = c.BASE+0x1000
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(code,entry)}
        cp = bytearray(4096); cp[:len(code)] = code
        result,seen = c.reference(nodes,{entry:cp},entry,regs,pages,
            image_pages=images,stop_before_call=(entry,entry+0x105) if stop else None,**kwargs)
        return result,seen,regs,pages

    def test_exact_call_stop_has_no_return_push_or_callee_execution(self):
        # Authored CALL unknown; RET. The exact stop is before the CALL.
        result,seen,regs,pages = self.reference(b'\xe8\x00\x01\x00\x00\xc3')
        self.assertEqual(result['boundary'],dict(site=c.BASE+0x1000,target=c.BASE+0x1105))
        self.assertEqual(result['regs'],[regs[r] for r in c.REGS])
        self.assertEqual(result['pages'],b''.join(pages[p] for p in b.heap.PAGES).hex())
        self.assertEqual(seen,set())

    def test_default_reference_still_rejects_unknown_callee(self):
        with self.assertRaises(ValueError): self.reference(b'\xe8\x00\x01\x00\x00\xc3',stop=False)

    def test_noncall_wrong_target_and_unreached_stop_reject(self):
        for code in (b'\x90\xc3',b'\xe8\x01\x01\x00\x00\xc3',b'\xc3'):
            with self.assertRaises(ValueError): self.reference(code)

    def test_third_immutable_page_is_opt_in_and_preserved(self):
        result,_,_,pages = self.reference(b'\xe8\x00\x01\x00\x00',extra=True)
        self.assertEqual(len(bytes.fromhex(result['pages'])),7*4096)
        self.assertEqual(bytes.fromhex(result['pages'])[-4096:],pages[b.MODE_PAGE])
        # Authored MOV [absolute third immutable page],EAX; RET must reject.
        code = b'\xa3'+struct.pack('<I',b.MODE_PAGE)+b'\xc3'
        with self.assertRaises(ValueError): self.reference(code,extra=True,stop=False)
        # Authored MOV EAX,[absolute third page]; RET is permitted.
        result,_,_,_ = self.reference(b'\xa1'+struct.pack('<I',b.MODE_PAGE)+b'\xc3',extra=True,stop=False)
        self.assertEqual(result['regs'][0],0)

    def test_corpus_byte_option_and_bounds_are_deterministic(self):
        options = set()
        for n in range(64):
            regs,pages = b.state(n)
            self.assertEqual((regs,pages),b.state(n))
            value = struct.unpack_from('<I',pages[c.DATA_PAGES[0]],regs['esp']-c.DATA_PAGES[0]+8)[0]
            options.add(value)
            self.assertEqual(value,b.MODE_BYTES[n%8])
        self.assertEqual(options,set(b.MODE_BYTES))
        for n in (-1,64,True,1.5):
            with self.assertRaises(ValueError): b.state(n)

    def test_binding_subset_and_three_controls_for_all_cases(self):
        for n in range(64):
            regs,pages,result = binding_fixture(n)
            b.contract(n,regs,pages,result,4)
            b.reject_controls(n,regs,pages,result,4)
            with self.assertRaises(ValueError): b.contract(n,regs,pages,result,3)

    def test_binding_rejects_source_grammar_descriptor_and_stack_mutations(self):
        regs,pages,result = binding_fixture()
        for kind in ('source','grammar','descriptor','stack'):
            bad, inputs = copy.deepcopy(result),copy.deepcopy(pages)
            raw = bytearray.fromhex(bad['pages'])
            if kind == 'source': raw[3*4096+b.t.SOURCE_OFFSET] ^= 1
            elif kind == 'grammar': inputs[b.MODE_PAGE][b.MODE_TEXT-b.MODE_PAGE+3] = ord('!')
            elif kind == 'descriptor': raw[b.heap.PAGES.index(b.heap.ARENA)*4096+0x1d0] ^= 1
            else: raw[regs['esp']-c.DATA_PAGES[0]] ^= 1
            bad['pages'] = raw.hex()
            with self.assertRaises(ValueError,msg=kind): b.contract(0,regs,inputs,bad,4)

    def test_creation_subset_and_five_controls_for_all_cases(self):
        for n in range(64):
            _,_,before = binding_fixture(n)
            after = creation_fixture(before)
            m.contract(before,after); m.reject_controls(before,after)
            self.assertEqual(after['regs'][7],before['regs'][7]-36)

    def test_resume_preserves_every_live_gpr_and_page_without_frame_repair(self):
        _,_,before = binding_fixture()
        regs,pages = m.resume_state(before)
        self.assertEqual([regs[r] for r in c.REGS],before['regs'])
        self.assertEqual(b''.join(pages[p] for p in (*c.DATA_PAGES,*b.IMAGES)).hex(),before['pages'])
        # Independent storage: modifying the resumed fixture cannot alter its oracle.
        pages[c.DATA_PAGES[0]][0] ^= 1
        self.assertNotEqual(b''.join(pages[p] for p in (*c.DATA_PAGES,*b.IMAGES)).hex(),before['pages'])
        for key in ('boundary','pages','regs'):
            bad = copy.deepcopy(before)
            if key == 'boundary': bad[key]['site'] ^= 4
            elif key == 'pages': bad[key] = bad[key][:-2]
            else: bad[key] = bad[key][:-1]
            with self.assertRaises(ValueError,msg=key): m.resume_state(bad)

    def test_create_contract_rejects_descriptor_register_and_caller_corruption(self):
        _,_,before = binding_fixture()
        for kind in ('edi','caller','truncation','input-boundary'):
            after, start = creation_fixture(before),copy.deepcopy(before)
            if kind == 'edi': after['regs'][c.REGS.index('edi')] ^= 4
            elif kind == 'caller':
                raw = bytearray.fromhex(after['pages']); raw[before['regs'][7]-c.DATA_PAGES[0]] ^= 1
                after['pages'] = raw.hex()
            elif kind == 'truncation': after['pages'] = after['pages'][:-2]
            else: start['boundary']['site'] ^= 4
            with self.assertRaises(ValueError,msg=kind): m.contract(start,after)


if __name__ == '__main__': unittest.main()
