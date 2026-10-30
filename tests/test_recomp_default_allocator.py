"""Public authored tail fixtures, never original game bodies or states."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/execute_heap_success.py'
spec = importlib.util.spec_from_file_location('default_allocator_success',PATH)
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class DefaultAllocatorTests(unittest.TestCase):
    def decode_authored(self,code):
        # Override ONLY fixture identity/extent: production accepts the pinned
        # 11-byte original, while these tests contain newly authored opcodes.
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
        count=len(list(md.disasm(code,m.c.BASE+m.WRAPPER)))
        with patch.multiple(m,WRAPPER_SIZE=len(code),WRAPPER_COUNT=count,
                            WRAPPER_PIN=hashlib.sha256(code).hexdigest()):
            return m.decode_wrapper(code,lambda i:i)

    def tail(self,target=None):
        target = m.c.BASE+m.RVA if target is None else target
        return b'\xe9'+struct.pack('<i',target-(m.c.BASE+m.WRAPPER+5))

    def test_pinned_decoder_rejects_untrusted_bytes(self):
        for code in (b'',self.tail(),bytes(11)):
            with self.assertRaises(ValueError):m.decode_wrapper(code,lambda i:i)

    def test_authored_exact_tail_decodes_without_following_target(self):
        function,nodes,metadata=self.decode_authored(b'\x90'+self.tail()[0:1]+
            struct.pack('<i',m.c.BASE+m.RVA-(m.c.BASE+m.WRAPPER+6)))
        self.assertEqual(function.address,m.c.BASE+m.WRAPPER)
        self.assertEqual(len(nodes),2)
        self.assertEqual(metadata['size_bytes'],6)
        self.assertEqual(metadata['instructions'],2)
        self.assertNotIn(m.c.BASE+m.RVA,nodes)

    def test_wrong_target_call_return_and_earlier_control_flow_reject(self):
        cases=(self.tail(m.c.BASE+m.RVA+1),b'\xc3',b'\xff\xe0',
               b'\xe8'+self.tail()[1:],b'\x74\x00'+self.tail())
        for code in cases:
            with self.subTest(code_length=len(code)):
                with self.assertRaises(ValueError):self.decode_authored(code)

    def test_authored_tail_preserves_return_frame_through_service(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
        target=m.c.BASE+m.RVA
        # Authored callee pushes the explicit portable-service arguments.
        body=b'\x6a\x09\x6a\x00\x68'+struct.pack('<I',m.HANDLE)
        body+=b'\xe8'+struct.pack('<i',m.SERVICE-(target+len(body)+5))+b'\xc3'
        nodes={};code_pages={m.SERVICE:bytes(4096)}
        for entry,code in ((m.c.BASE+m.WRAPPER,self.tail()),(target,body)):
            nodes.update({i.address:i for i in md.disasm(code,entry)})
            page=entry & ~4095;data=bytearray(4096)
            data[entry-page:entry-page+len(code)]=code;code_pages[page]=data
        regs,pages,_=m.state(1);before=copy.deepcopy((regs,pages));model=m.HeapModel(9)
        result,seen=m.c.reference(nodes,code_pages,m.c.BASE+m.WRAPPER,regs,pages,
                                 image_pages=m.IMAGES,heap_service=model)
        m.contract(regs,pages,result,model)
        self.assertEqual(result['regs'][-1],regs['esp']+4)
        self.assertEqual(len(seen),6)
        self.assertEqual((regs,pages),before)

    def test_transport_retains_both_bodies_and_only_exact_tail_pair(self):
        heap='/* authored heap placeholder */'
        wrapper='/* authored wrapper placeholder */'
        base=m.assemble(heap,{0x8437c6,0x842a91,0x831b17},m.c.BASE+m.RVA+1)
        text=m.compose_transport(base,wrapper)
        self.assertEqual(text.count(heap),1)
        self.assertEqual(text.count(wrapper),1)
        self.assertIn('if(g_cur_func!=0xA0831A6Fu || target!=0xA08461F2u) reject();',text)
        self.assertIn('cache_invoke(0xA0831A6Fu,in,default_adapter);',text)
        tail=text.split('#define RECOMP_ITAIL(va)',1)[1].split('while(0)',1)[0]
        self.assertNotIn('PUSH32',tail)
        self.assertNotIn('direct_return',tail)
        self.assertNotIn('@',text)

    def test_composition_rejects_missing_anchors_and_empty_body(self):
        for text,body in (('', '/* authored */'),('int main() {','/* authored */'),('', '')):
            with self.assertRaises(ValueError):m.compose_transport(text,body)
        with self.assertRaises(ValueError):m.compose_bridge('')

    def test_production_bridge_registers_closure_and_controls(self):
        for mode in m.MODES:
            text=m.compose_bridge(m.bridge_source(mode))
            self.assertIn('targets{0xA0831A6Fu,0xA08461F2u,0x60000000u}',text)
            self.assertIn('heap->invoke_allocate(r);',text)
            self.assertIn('heap.reset();',text)
            self.assertEqual('s[0]+=8;' in text,mode=='wrong-result')
            self.assertEqual('s[7]+=4;' in text,mode=='wrong-cleanup')


if __name__=='__main__':unittest.main()
