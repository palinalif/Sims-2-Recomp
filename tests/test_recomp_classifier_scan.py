"""Public authored tables/contracts; no original code or private fixture needed."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('classifier_scan', Path(__file__).resolve().parents[1]/'scripts/recomp/execute_classifier_scan.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def images():
    pages = {p:bytearray(4096) for p in m.IMAGES}
    for n, name in enumerate((b'alpha', b'bravo', b'charlie', b'delta', b'echo', b'foxtrot')):
        struct.pack_into('<I', pages[m.IMAGES[0]], m.TABLE-m.IMAGES[0]+n*4, m.IMAGES[1]+128+n*32)
        pages[m.IMAGES[1]][128+n*32:129+n*32+len(name)] = name+b'\0'
    return pages


class ClassifierScanTests(unittest.TestCase):
    def test_deterministic_fixtures_cover_every_result_without_changing_image(self):
        data = images(); original = copy.deepcopy(data); outcomes = set()
        for n in range(64):
            regs, pages, sample = m.state(n,data)
            self.assertEqual((regs,pages,sample), m.state(n,data))
            names = m.names_from_pages(data)
            matches = [i for i,name in enumerate(names) if name.lower() == sample.lower()]
            value = 6 if not regs['edi'] else matches[0] if matches else 0xffffffff
            out = dict(regs,eax=value,esp=regs['esp']+4)
            result = dict(regs=[out[r] for r in m.c.REGS], pages=b''.join(pages[p] for p in m.PAGES).hex())
            outcomes.add(m.contract(regs,pages,sample,result))
            for r in ('eax','ebx','ebp','esi','edi','esp'):
                bad = copy.deepcopy(result); bad['regs'][m.c.REGS.index(r)] ^= 1
                with self.assertRaises(ValueError): m.contract(regs,pages,sample,bad)
            bad = copy.deepcopy(result)
            final = bytearray.fromhex(bad['pages']); final[4096] ^= 1; bad['pages'] = final.hex()
            with self.assertRaises(ValueError): m.contract(regs,pages,sample,bad)
            for p in m.IMAGES: self.assertEqual(pages[p],data[p])
        self.assertEqual(outcomes, {*range(7),0xffffffff})
        self.assertEqual(data,original)
        for n in (True,-1,64):
            with self.assertRaises(ValueError): m.state(n,data)

    def test_image_table_rejects_invalid_duplicate_unterminated_and_long_names(self):
        data = images()
        for pointer in (0, m.IMAGES[1]-1, m.IMAGES[1]+4096):
            bad = copy.deepcopy(data); struct.pack_into('<I',bad[m.IMAGES[0]],m.TABLE-m.IMAGES[0],pointer)
            with self.assertRaises(ValueError): m.names_from_pages(bad)
        bad = copy.deepcopy(data); bad[m.IMAGES[1]][:] = b'x'*4096
        with self.assertRaises(ValueError): m.names_from_pages(bad)
        bad = copy.deepcopy(data)
        struct.pack_into('<I',bad[m.IMAGES[0]],m.TABLE-m.IMAGES[0]+4,m.IMAGES[1]+128)
        with self.assertRaises(ValueError): m.names_from_pages(bad)

    def test_verbatim_bodies_and_exact_nested_return_dispatch(self):
        bodies = {r:'static void '+m.c.body_name(r)+'() { /* authored marker '+str(r)+' */ }' for r in (m.RVA,m.c.MODULE_COMPARE)}
        text = m.assemble(bodies)
        for body in bodies.values(): self.assertEqual(text.count(body),1)
        self.assertIn('caller==0xA0010700u && target==0xA000FCB0u',text)
        self.assertIn('return 0xA001071Eu;',text)
        self.assertIn('default:reject();',text)
        self.assertIn('cache_invoke(0xA0010700u,in,adapter_10700)',text)
        with self.assertRaises(ValueError): m.assemble({m.RVA:bodies[m.RVA]})
        valid = m.bridge_source(m.c.BRIDGE.read_text(),'valid')
        self.assertIn('targets{0xA0010700u,0xA000FCB0u}',valid)
        self.assertIn('0xA1050000u,0xA0E19000u',valid)
        for mode,fault in (('wrong-result','s[0]^=4;'),('wrong-cleanup','s[7]+=8;')):
            self.assertEqual(m.bridge_source(m.c.BRIDGE.read_text(),mode),valid.replace('    current(s.data());','    current(s.data());\n    if(depth==1) '+fault))
        with self.assertRaises(ValueError): m.bridge_source(m.c.BRIDGE.read_text(),'wrong-slot')

    def test_reference_explicit_image_pages_are_readonly_and_validated(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail = True
        regs,pages,_ = m.state(0,images())
        pc = m.c.BASE+0x1000
        # Public authored MOV EAX,[absolute image address]; RET.
        code = b'\xa1'+struct.pack('<I',m.IMAGES[0])+b'\xc3'
        nodes = {i.address:i for i in md.disasm(code,pc)}
        cp = {pc:code+bytes(4096-len(code))}
        out,seen = m.c.reference(nodes,cp,pc,regs,pages,image_pages=m.IMAGES)
        self.assertEqual(out['regs'][0],0)
        self.assertEqual(out['regs'][7],regs['esp']+4)
        self.assertEqual(len(seen),2)
        self.assertEqual(out['pages'],b''.join(pages[p] for p in m.PAGES).hex())
        for bad in ((m.IMAGES[0],)*2,(m.IMAGES[0]+1,m.IMAGES[1]),(m.c.DATA_PAGES[0],m.IMAGES[1]),(m.c.RETURN,m.IMAGES[1])):
            with self.assertRaises(ValueError): m.c.reference(nodes,cp,pc,regs,pages,image_pages=bad)
        # A store to an explicit image page still fails before execution.
        code = b'\xa3'+struct.pack('<I',m.IMAGES[0])+b'\xc3'
        nodes = {i.address:i for i in md.disasm(code,pc)}
        with self.assertRaises(ValueError): m.c.reference(nodes,{pc:code+bytes(4096-len(code))},pc,regs,pages,image_pages=m.IMAGES)
