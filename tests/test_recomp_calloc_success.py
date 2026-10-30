"""Authored zeroing-policy fixtures; no proprietary bodies or private inputs."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_calloc_success.py'
spec = importlib.util.spec_from_file_location('calloc_success',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CallocSuccessTests(unittest.TestCase):
    def reference(self,n=0,*,flags=8,handle=None,target=None,bind=True,tail=False):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        regs,pages,size = m.state(n)
        handle = m.h.HANDLE if handle is None else handle
        target = m.h.SERVICE if target is None else target
        entry = m.c.BASE+0x2000
        # Authored push normalized product / flags / handle; CALL; RET.
        code = b'\x68'+struct.pack('<I',max(1,size))+b'\x6a'+bytes([flags])+b'\x68'+struct.pack('<I',handle)
        code += b'\xe8'+struct.pack('<i',target-(entry+len(code)+5))+b'\xc3'
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(code,entry)}
        block = bytearray(4096); block[:len(code)] = code
        model = m.ZeroModel(size)
        cp = {entry:block,m.h.SERVICE:bytes(4096)}
        start = entry
        if tail:
            start = entry+4096
            # Authored frame-save/restore then tail jump: no extra return word.
            wrapper = b'\x55\x89\xe5\x5d\xe9'+struct.pack('<i',entry-(start+9))
            nodes.update({i.address:i for i in md.disasm(wrapper,start)})
            cp[start] = wrapper+bytes(4096-len(wrapper))
        result,_ = m.c.reference(nodes,cp,start,regs,pages,
            image_pages=m.h.IMAGES,heap_service=model if bind else None)
        return regs,pages,result,model

    def test_corpus_contains_real_request_zero_and_full_page_edges(self):
        pairs = set()
        for n in range(64):
            regs,pages,size = m.state(n)
            self.assertEqual((regs,pages,size),m.state(n))
            ret,a,b = struct.unpack_from('<3I',pages[m.c.DATA_PAGES[0]],regs['esp']-m.c.DATA_PAGES[0])
            self.assertEqual(ret,m.c.RETURN); self.assertEqual(a*b,size)
            pairs.add((a,b))
        self.assertEqual(pairs,set(m.PAIRS))
        self.assertIn((64,4),pairs); self.assertIn((0,0),pairs); self.assertIn((1,4096),pairs)
        for n in (-1,64,True):
            with self.assertRaises(ValueError):m.state(n)

    def test_zeroing_contract_all_authored_cases(self):
        for n in range(64):
            regs,pages,result,model = self.reference(n)
            m.contract(regs,pages,result,model)
            self.assertEqual(model.calls,1)
            self.assertNotEqual(pages[m.h.ARENA],bytes(4096))

    def test_no_implicit_service_and_wrong_flags_handle_target_reject(self):
        for kw in ({'flags':0},{'handle':0},{'target':m.h.SERVICE+4},{'bind':False}):
            with self.subTest(kw=kw),self.assertRaises(ValueError):self.reference(**kw)

    def test_zeroing_extent_and_untouched_pages_reject_mutations(self):
        regs,pages,result,model = self.reference(7) # size7, rounded8
        original = copy.deepcopy((regs,pages,result))
        arena_offset = m.h.PAGES.index(m.h.ARENA)*4096
        for offset in (arena_offset,arena_offset+7,arena_offset+8,4096,len(bytes.fromhex(result['pages']))-1):
            bad = copy.deepcopy(result); raw = bytearray.fromhex(bad['pages'])
            raw[offset] ^= 1; bad['pages'] = raw.hex()
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        bad = copy.deepcopy(result); bad['pages'] = bad['pages'][:-2]
        with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        self.assertEqual((regs,pages,result),original)

    def test_result_cleanup_nonvolatiles_and_service_call_count_reject(self):
        regs,pages,result,model = self.reference()
        for index in (0,1,4,5,6,7):
            bad = copy.deepcopy(result); bad['regs'][index] ^= 4
            with self.assertRaises(ValueError):m.contract(regs,pages,bad,model)
        model.calls = 0
        with self.assertRaises(ValueError):m.contract(regs,pages,result,model)

    def test_authored_tail_preserves_arguments_and_return_frame(self):
        for n in range(64):
            regs,pages,result,model = self.reference(n,tail=True)
            m.contract(regs,pages,result,model)
            sp = regs['esp']-m.c.DATA_PAGES[0]
            self.assertEqual(bytes.fromhex(result['pages'])[sp:sp+12],pages[m.c.DATA_PAGES[0]][sp:sp+12])
            self.assertEqual(result['regs'][-1],regs['esp']+4)

    def test_composed_transport_retains_bodies_and_exact_tail_gate(self):
        body = '/* authored allocation body, not executed */'
        wrapper = '/* authored tail body, not executed */'
        text = m.h.assemble(body,{0x8437c6,0x842a91,0x831b17},m.c.BASE+m.RVA+1,rva=m.RVA,size=m.SIZE)
        composed = m.h.compose_transport(text,wrapper,rva=m.RVA,wrapper=m.WRAPPER)
        self.assertEqual(composed.count(body),1); self.assertEqual(composed.count(wrapper),1)
        self.assertIn('g_cur_func!=0xA083A371u || target!=0xA0849A00u',composed)
        self.assertIn('cache_invoke(0xA083A371u,in,default_adapter);',composed)
        self.assertIn('case 0xA083A371u:callback=default_adapter;break;',composed)
        self.assertNotIn('case 0xA0831A6Fu:',composed)
        bridge = m.h.compose_bridge(m.h.bridge_source('valid',rva=m.RVA),rva=m.RVA,wrapper=m.WRAPPER)
        self.assertIn('targets{0xA083A371u,0xA0849A00u,0x60000000u}',bridge)
        for bad in (text.replace('static void heap_success(void);',''),composed):
            with self.assertRaises(ValueError):m.h.compose_transport(bad,wrapper,rva=m.RVA,wrapper=m.WRAPPER)

    def test_authored_tail_decoder_pins_target_bytes_and_extent(self):
        import hashlib
        # Entirely authored fixture at unrelated public test RVAs.
        rva,target = 0x2000,0x3000
        code = b'\x55\x89\xe5\x5d\xe9'+struct.pack('<i',target-(rva+9))
        kw = dict(rva=rva,size=9,count=4,pin=hashlib.sha256(code).hexdigest(),target=target)
        _,nodes,metadata = m.h.decode_wrapper(code,lambda i:i,**kw)
        self.assertEqual(len(nodes),4); self.assertEqual(metadata['size_bytes'],9)
        for override in ({'target':target+1},{'pin':'0'*64},{'size':10},{'count':5}):
            with self.subTest(override=override),self.assertRaises(ValueError):
                m.h.decode_wrapper(code,lambda i:i,**(kw|override))
        bad = b'\x55\x89\xe5\x5d\xe8'+code[5:]
        with self.assertRaises(ValueError):
            m.h.decode_wrapper(bad,lambda i:i,**(kw|{'pin':hashlib.sha256(bad).hexdigest()}))

    def arithmetic(self,code,*,enabled=True,divisor=3,high=0,pointer=None):
        from capstone import Cs,CS_ARCH_X86,CS_MODE_32
        regs,pages,_ = m.state(0)
        regs.update(eax=21,edx=high,ecx=divisor,esi=m.h.ARENA if pointer is None else pointer)
        struct.pack_into('<I',pages[m.h.ARENA],0,7)
        entry = m.c.BASE+0x2000; code += b'\xc3'
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
        nodes = {i.address:i for i in md.disasm(code,entry)}
        block=bytearray(4096);block[:len(code)]=code
        return m.c.reference(nodes,{entry:block},entry,regs,pages,image_pages=m.h.IMAGES,
                             checked_calloc_arithmetic=enabled)[0]

    def test_arithmetic_is_opt_in_and_matches_independent_integer_results(self):
        # Authored DIV ecx / IMUL eax,[esi]; no original instructions copied.
        self.assertEqual(self.arithmetic(b'\xf7\xf1')['regs'][0],7)
        self.assertEqual(self.arithmetic(b'\x0f\xaf\x06')['regs'][0],147)
        self.assertEqual(self.arithmetic(b'\xf7\xf1\x0f\xaf\x06')['regs'][0],49)
        for code in (b'\xf7\xf1',b'\x0f\xaf\x06'):
            with self.assertRaises(ValueError):self.arithmetic(code,enabled=False)

    def test_arithmetic_narrow_prefix_memory_and_unsupported_forms_reject(self):
        for code in (b'\x66\xf7\xf1',b'\xf6\xf1',b'\xf7\x36',
                     b'\x0f\xaf\xc1',b'\x6b\xc1\x04',b'\x64\x0f\xaf\x06'):
            with self.subTest(code=code.hex()),self.assertRaises(ValueError):self.arithmetic(code)
        for pointer in (0,m.h.ARENA+4094,m.h.ARENA+4096):
            with self.assertRaises(ValueError):self.arithmetic(b'\x0f\xaf\x06',pointer=pointer)
        import unicorn
        for divisor,high in ((0,0),(1,1)):
            with self.assertRaises(unicorn.UcError):self.arithmetic(b'\xf7\xf1',divisor=divisor,high=high)

    def test_transport_exact_target_and_verbatim_body(self):
        body = '/* authored placeholder, never executed */'
        text = m.h.assemble(body,{0x8437c6,0x842a91,0x831b17},m.c.BASE+m.RVA+1,rva=m.RVA,size=m.SIZE)
        self.assertEqual(text.count(body),1)
        self.assertIn('case 0xA0849A00u:heap_success();break;',text)
        self.assertNotIn('case 0xA08461F2u:',text)
        self.assertNotIn('@',text)
        bridge = m.h.bridge_source('valid',rva=m.RVA)
        self.assertIn('targets{0xA0849A00u,0x60000000u}',bridge)
        self.assertIn('heap->invoke_allocate(r);',bridge)
        self.assertIn('heap.reset();',bridge)
        with self.assertRaises(ValueError):m.h.assemble(body,set(),0,rva=m.RVA,size=m.SIZE)


if __name__ == '__main__': unittest.main()
