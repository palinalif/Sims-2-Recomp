"""Authored x86 fixtures for mode-prefix fault capture; no original game code."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_mode_prefix.py'
spec = importlib.util.spec_from_file_location('mode_prefix', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
c = m.c


class ModePrefixTests(unittest.TestCase):
    def execute(self, code, regs=None, pages=None, budget=128):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        if regs is None:
            regs, pages = m.state(0)
        md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
        entry = c.BASE+0x3000
        nodes = {i.address:i for i in md.disasm(code, entry)}
        self.assertEqual(sum(i.size for i in nodes.values()), len(code))
        cp = bytearray(4096); cp[:len(code)] = code
        return m.trace(nodes, {entry:cp}, regs, pages, entry, budget)

    def test_corpus_is_nonempty_disjoint_deterministic_and_page_bounded(self):
        texts, offsets = set(), set()
        for n in range(64):
            regs, pages = m.state(n)
            self.assertEqual((regs,pages), m.state(n))
            off = regs['eax']-c.DATA_PAGES[2]
            end = pages[c.DATA_PAGES[2]].index(0, off)
            texts.add(bytes(pages[c.DATA_PAGES[2]][off:end])); offsets.add(off)
            self.assertGreater(end, off)
            self.assertLess(end, 4096)
            self.assertEqual(set(pages), set(c.PAGES))
            self.assertTrue(all(len(b) == 4096 for b in pages.values()))
        self.assertEqual(texts, set(m.TEXTS))
        self.assertEqual(offsets, {0, 1, 128, 4088})
        for bad in (-1, 64, True, 1.5):
            with self.assertRaises(ValueError): m.state(bad)

    def test_first_invalid_read_captured_before_execution(self):
        regs,pages = m.state(0); regs['edx'] = 0x12345000
        before = copy.deepcopy((regs,pages))
        # Authored MOV EAX,[EDX+4]; RET.
        result = self.execute(b'\x8b\x42\x04\xc3', regs,pages)
        self.assertEqual((regs,pages), before)
        self.assertEqual(result['kind'], 'invalid-memory')
        self.assertEqual((result['site'],result['address'],result['size'],result['write']),
                         (c.BASE+0x3000,0x12345004,4,False))
        self.assertEqual((result['base'],result['displacement']), ('edx',4))
        self.assertEqual(result['visited'], [])
        self.assertEqual(result['regs'], regs)
        self.assertEqual(result['pages'], pages)

    def test_immutable_write_rejected_without_mutation(self):
        regs,pages = m.state(0); regs['edx'] = c.PAGES[-1]
        # Authored MOV [EDX],EAX; RET.
        result = self.execute(b'\x89\x02\xc3',regs,pages)
        self.assertEqual((result['kind'], result['write']), ('invalid-memory',True))
        self.assertEqual(result['pages'], pages)

    def test_implicit_stack_fault_is_captured(self):
        regs,pages = m.state(0); regs['esp'] = c.DATA_PAGES[0]
        result = self.execute(b'\x50\xc3',regs,pages)  # PUSH EAX; RET
        self.assertEqual((result['kind'],result['address'],result['base'],result['write']),
                         ('invalid-memory',c.DATA_PAGES[0]-4,'esp',True))
        self.assertEqual(result['visited'], [])

    def test_call_stops_before_unknown_callee_and_never_pushes_return(self):
        regs,pages = m.state(0)
        result = self.execute(b'\xe8\x00\x01\x00\x00\xc3',regs,pages)
        self.assertEqual((result['kind'],result['target']), ('call',c.BASE+0x3105))
        self.assertEqual(result['regs'],regs)
        self.assertEqual(result['pages'],pages)
        self.assertEqual(result['visited'],[])

    def test_valid_access_executes_then_return_has_checked_cleanup(self):
        regs,pages = m.state(0)
        # Authored MOVZX EAX,byte [EAX]; RET. An unaligned byte is allowed.
        result = self.execute(b'\x0f\xb6\x00\xc3',regs,pages)
        self.assertEqual(result['kind'],'return')
        self.assertEqual(result['regs'],dict(regs,eax=m.TEXTS[0][0],esp=regs['esp']+4))
        self.assertEqual(result['pages'],pages)
        self.assertEqual(len(result['visited']),2)

    def test_descriptor_binding_and_independent_subset_reject_mutations(self):
        for n in range(64):
            for bound in (False, True):
                regs,pages = m.state(n, bound_cursor=bound)
                h = regs['esi']-c.DATA_PAGES[1]
                cursor = struct.unpack_from('<I',pages[c.DATA_PAGES[1]],h+0x1dc)[0]
                observed = dict(regs=dict(regs),pages=copy.deepcopy(pages))
                if bound:
                    observed.update(kind='call',site=c.BASE+0x3903,target=c.BASE+0x1820)
                    sample = m.TEXTS[n%8]+b'\0'
                    observed['pages'][c.DATA_PAGES[3]][128:128+len(sample)] = sample
                    struct.pack_into('<I',observed['pages'][c.DATA_PAGES[1]],h+0x1dc,cursor+len(sample))
                    observed['regs']['esp'] -= 24
                    struct.pack_into('<II',observed['pages'][c.DATA_PAGES[0]],
                                     observed['regs']['esp']-c.DATA_PAGES[0],cursor,0)
                else:
                    observed.update(kind='invalid-memory',site=c.BASE+0x38b8,
                                    address=cursor,size=1,write=True)
                m.boundary_contract(regs,pages,observed,bound_cursor=bound)
                m.reject_controls(regs,pages,observed,bound_cursor=bound)
                for mutation in ('source','receiver','cursor','cleanup') if bound else ('width','direction'):
                    bad = copy.deepcopy(observed)
                    if mutation in ('source','receiver'):
                        page = c.DATA_PAGES[2 if mutation == 'source' else 1]
                        bad['pages'][page][64] ^= 1
                    elif mutation == 'cursor':
                        bad['pages'][c.DATA_PAGES[1]][h+0x1dc] ^= 1
                    elif mutation == 'cleanup': bad['regs']['esp'] += 4
                    elif mutation == 'width': bad['size'] = 4
                    else: bad['write'] = False
                    with self.assertRaises(ValueError,msg=mutation):
                        m.boundary_contract(regs,pages,bad,bound_cursor=bound)
        with self.assertRaises(ValueError): m.state(0,bound_cursor=1)

    def test_range_wrap_crosspage_and_unknown_execution_fail_closed(self):
        for args in ((-1,1),(0xffffffff,4),(c.DATA_PAGES[0]+4095,4),
                     (c.PAGES[-1],4,True),(c.DATA_PAGES[0],True)):
            self.assertFalse(m.allowed(*args),args)
        self.assertTrue(m.allowed(c.DATA_PAGES[0]+1,4))
        with self.assertRaises(ValueError): self.execute(b'\xeb\xfe',budget=3)
        with self.assertRaises(ValueError): self.execute(b'\x90',budget=True)
        with self.assertRaises(ValueError): self.execute(b'\xf4')  # HLT
        with self.assertRaises(ValueError): self.execute(b'\xeb\x10')


if __name__ == '__main__':
    unittest.main()
