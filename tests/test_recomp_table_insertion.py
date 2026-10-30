"""Authored insertion-boundary fixtures; no private original inputs required."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_table_insertion.py'
spec = importlib.util.spec_from_file_location('table_insertion', PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, b = m.c, m.b


def fixture():
    regs, pages = b.state(0)
    pages[b.MODE_PAGE] = bytearray(4096)
    start = sum(b.t.REQUESTS)
    struct.pack_into('<3I', pages[b.heap.ARENA], 0x160, b.heap.ARENA+start, 64, 0)
    pages[b.heap.ARENA][start:start+256] = bytes(256)
    before = dict(boundary=dict(site=m.a.STOP[0], target=m.a.STOP[1]),
                  regs=[regs[r] for r in c.REGS],
                  pages=b''.join(pages[p] for p in (*c.DATA_PAGES, *b.IMAGES)).hex())
    out = dict(regs, esp=regs['esp']-8)
    struct.pack_into('<II', pages[c.DATA_PAGES[0]], out['esp']-c.DATA_PAGES[0], 1, 8)
    after = dict(boundary=dict(site=m.STOP[0], target=m.STOP[1]),
                 regs=[out[r] for r in c.REGS],
                 pages=b''.join(pages[p] for p in (*c.DATA_PAGES, *b.IMAGES)).hex())
    return before, after


class TableInsertionTests(unittest.TestCase):
    def test_subset_and_all_five_controls(self):
        before, after = fixture()
        saved = copy.deepcopy((before, after))
        m.contract(before, after)
        m.reject_controls(before, after)
        self.assertEqual((before, after), saved)

    def test_exact_resume_and_independent_pages(self):
        before, _ = fixture()
        regs, pages = m.resume(before)
        self.assertEqual(list(regs.values()), before['regs'])
        self.assertEqual(b''.join(pages[p] for p in (*c.DATA_PAGES, *b.IMAGES)).hex(), before['pages'])
        pages[b.heap.ARENA][0] ^= 1
        self.assertNotEqual(b''.join(pages[p] for p in (*c.DATA_PAGES, *b.IMAGES)).hex(), before['pages'])

    def test_resume_rejects_wrong_boundary_and_truncation(self):
        for kind in ('site', 'target', 'regs', 'pages'):
            before, _ = fixture()
            if kind in ('site', 'target'): before['boundary'][kind] ^= 4
            elif kind == 'regs': before['regs'].pop()
            else: before['pages'] = before['pages'][:-2]
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.resume(before)

    def test_boundary_register_extent_and_bounds_fail_closed(self):
        for kind in ('site', 'target', 'regs', 'pages', 'esp', 'edi'):
            before, after = fixture()
            if kind in ('site', 'target'): after['boundary'][kind] ^= 4
            elif kind == 'regs': after['regs'].pop()
            elif kind == 'pages': after['pages'] = after['pages'][:-2]
            elif kind == 'esp': after['regs'][7] = c.DATA_PAGES[0]-4
            else: after['regs'][c.REGS.index(kind)] ^= 4
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.contract(before, after)

    def test_nonstack_and_caller_frame_preservation(self):
        before, after = fixture()
        for offset in (4096, 2*4096+0x160, 3*4096+40,
                       len(bytes.fromhex(after['pages']))-1,
                       before['regs'][7]-c.DATA_PAGES[0]):
            bad = copy.deepcopy(after)
            raw = bytearray.fromhex(bad['pages']); raw[offset] ^= 1
            bad['pages'] = raw.hex()
            with self.subTest(offset=offset), self.assertRaises(ValueError): m.contract(before, bad)

    def test_empty_owned_table_is_required_not_a_general_lookup_claim(self):
        for offset in (0x160, 0x164, 0x168, sum(b.t.REQUESTS)):
            before, after = fixture()
            raw = bytearray.fromhex(before['pages'])
            raw[c.DATA_PAGES.index(b.heap.ARENA)*4096+offset] ^= 1
            before['pages'] = raw.hex()
            with self.subTest(offset=offset), self.assertRaises(ValueError): m.contract(before, after)

    def test_subset_does_not_invent_volatile_register_or_stack_scratch_oracle(self):
        before, after = fixture()
        for r in ('eax', 'ecx', 'edx'): after['regs'][c.REGS.index(r)] ^= 0x1234
        raw = bytearray.fromhex(after['pages']); raw[0] ^= 1
        after['pages'] = raw.hex()
        m.contract(before, after)


if __name__ == '__main__': unittest.main()
