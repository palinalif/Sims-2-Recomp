"""Authored ownership handoff checks, no private image or reference fixtures."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from test_recomp_live_growth import fixture as growth_fixture

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_key_publication.py'
spec = importlib.util.spec_from_file_location('key_publication',PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, g = m.c, m.g


def fixture(value=b'bounded value'):
    _, before, _ = growth_fixture()
    regs, pages = m.resume(before)
    arena = pages[g.heap.ARENA]+pages[g.EXTRA]
    key = struct.unpack_from('<I', arena, 0x1e0)[0]-g.heap.ARENA
    arena[key:key+4] = b'key\0'
    owned = g.p.OCCUPIED+8
    arena[owned:owned+4] = b'key\0'
    struct.pack_into('<II',arena,g.p.node.START,g.heap.ARENA+key,0)
    struct.pack_into('<I',arena,0x1dc,g.heap.ARENA+key+4)
    struct.pack_into('<I',arena,0x1d8,g.heap.ARENA+g.p.node.START)
    mode = pages[m.b.MODE_PAGE]
    pos = m.b.MODE_TEXT-m.b.MODE_PAGE
    mode[pos:pos+len(value)+5] = b'key='+value+b'\0'
    pages[g.heap.ARENA],pages[g.EXTRA] = arena[:4096],arena[4096:]
    before['pages'] = b''.join(pages[p] for p in g.ORDER).hex()
    struct.pack_into('<I',arena,g.p.node.START,g.heap.ARENA+owned)
    arena[key:key+len(value)+1] = value+b'\0'
    struct.pack_into('<I',arena,0x1dc,g.heap.ARENA+key+len(value)+1)
    pages[g.heap.ARENA],pages[g.EXTRA] = arena[:4096],arena[4096:]
    out = before['regs'].copy()
    out[7] -= 20
    out[c.REGS.index('esi')] = g.heap.ARENA
    struct.pack_into('<4I',pages[c.DATA_PAGES[0]],out[7]-c.DATA_PAGES[0],
                     g.heap.ARENA,g.heap.ARENA+g.p.node.START,0,g.heap.ARENA+key)
    after = dict(boundary=dict(site=m.STOP[0],target=m.STOP[1]),regs=out,
                 pages=b''.join(pages[p] for p in g.ORDER).hex())
    return before, after


class KeyPublicationTests(unittest.TestCase):
    def test_contract_empty_short_and_long_values_and_thirteen_mutations(self):
        for value in (b'', b'v', b'a=b c', b'z'*63):
            with self.subTest(length=len(value)):
                before,after = fixture(value)
                saved = copy.deepcopy((before,after))
                m.contract(before,after)
                self.assertEqual(m.reject_controls(before,after),13)
                self.assertEqual((before,after),saved)

    def test_resume_rejects_wrong_pc_register_count_or_extent(self):
        before,_ = fixture()
        for key in ('stop_pc','regs','pages'):
            bad = copy.deepcopy(before)
            if key=='stop_pc': bad[key] ^= 1
            elif key=='regs': bad[key].pop()
            else: bad[key] = bad[key][:-2]
            with self.subTest(key=key),self.assertRaises(ValueError):m.resume(bad)

    def test_resume_exact_handoff_without_new_page_or_mutation(self):
        before,_=fixture(); regs,pages=m.resume(before)
        self.assertEqual(list(regs.values()),before['regs'])
        self.assertEqual(set(pages),set(g.ORDER))
        self.assertEqual(b''.join(pages[p] for p in g.ORDER).hex(),before['pages'])
        pages[g.EXTRA][0]^=1
        self.assertNotEqual(b''.join(pages[p] for p in g.ORDER).hex(),before['pages'])

    def test_advance_has_no_service_and_stops_before_exact_call(self):
        before,after=fixture()
        with patch.object(c,'reference',return_value=(after,set())) as reference:
            m.advance(before,{}, {})
        args,options=reference.call_args
        self.assertEqual(args[2],g.STOP_PC)
        self.assertNotIn('heap_service',options)
        self.assertNotIn('stop_before_pc',options)
        self.assertEqual(options['stop_before_call'],m.STOP)
        self.assertEqual(options['extra_data_pages'],(g.EXTRA,))
        self.assertEqual(options['budget'],1024)

    def test_temporary_key_cannot_remain_published_after_value_overwrite(self):
        before,after=fixture(b'not the key')
        raw=bytearray.fromhex(after['pages']); old=bytes.fromhex(before['pages'])
        pos=g.ORDER.index(g.heap.ARENA)*4096+g.p.node.START
        raw[pos:pos+4]=old[pos:pos+4];after['pages']=raw.hex()
        with self.assertRaises(ValueError):m.contract(before,after)

    def test_incoming_mode_and_owned_key_must_agree(self):
        before,after=fixture()
        for page,offset in ((m.b.MODE_PAGE,m.b.MODE_TEXT-m.b.MODE_PAGE+3),
                            (g.heap.ARENA,g.p.OCCUPIED+8),
                            (g.heap.ARENA,g.p.node.START+4),
                            (g.heap.ARENA,0x1dc)):
            bad=copy.deepcopy(before);raw=bytearray.fromhex(bad['pages'])
            raw[g.ORDER.index(page)*4096+offset]^=1;bad['pages']=raw.hex()
            with self.subTest(offset=offset),self.assertRaises(ValueError):m.contract(bad,after)

    def test_output_extent_registers_and_boundary_are_strict(self):
        before,after=fixture()
        for key in ('pages','regs','boundary'):
            bad=copy.deepcopy(after)
            if key=='pages':bad[key]=bad[key][:-2]
            elif key=='regs':bad[key].pop()
            else:bad[key]['target']^=4
            with self.subTest(key=key),self.assertRaises(ValueError):m.contract(before,bad)

    def test_value_must_stay_inside_existing_text_capacity(self):
        before,after=fixture()
        raw=bytearray.fromhex(before['pages'])
        pos=g.ORDER.index(g.heap.ARENA)*4096
        key=struct.unpack_from('<I',raw,pos+0x1e0)[0]
        struct.pack_into('<I',raw,pos+0x1d8,key+1)
        before['pages']=raw.hex()
        with self.assertRaises(ValueError):m.contract(before,after)


if __name__ == '__main__':unittest.main()
