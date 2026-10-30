"""Authored node-topology fixtures; no proprietary inputs required."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_table_node.py'
spec = importlib.util.spec_from_file_location('table_node', PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, b = m.c, m.b


def fixture(bucket=17):
    regs, pages = b.state(0)
    pages[b.MODE_PAGE] = bytearray(4096)
    arena = pages[b.heap.ARENA]
    struct.pack_into('<3I', arena, 0x160, b.heap.ARENA+sum(b.t.REQUESTS), 64, 0)
    struct.pack_into('<I', arena, 0x1e0, b.heap.ARENA+512)
    arena[sum(b.t.REQUESTS):m.START] = bytes(256)
    struct.pack_into('<II', pages[c.DATA_PAGES[0]], regs['esp']-c.DATA_PAGES[0], 1, 8)
    before = dict(boundary=dict(site=m.p.STOP[0], target=m.p.STOP[1]),
                  regs=[regs[r] for r in c.REGS],
                  pages=b''.join(pages[p] for p in m.ORDER).hex())
    struct.pack_into('<I', arena, 0x168, 1)
    struct.pack_into('<II', arena, m.START, b.heap.ARENA+512, 0)
    struct.pack_into('<I', arena, sum(b.t.REQUESTS)+4*bucket, b.heap.ARENA+m.START)
    after = dict(boundary=dict(site=m.STOP[0], target=m.STOP[1]),
                 regs=[regs[r] for r in c.REGS],
                 pages=b''.join(pages[p] for p in m.ORDER).hex())
    service = m.model(); service.occupied[m.START//8] = True; service.calls = 1
    return before, after, service


def mutate(row, page, offset):
    raw = bytearray.fromhex(row['pages'])
    raw[m.ORDER.index(page)*4096+offset] ^= 1
    row['pages'] = raw.hex()


class TableNodeTests(unittest.TestCase):
    def test_subset_and_seven_controls_do_not_mutate_inputs(self):
        before, after, service = fixture()
        saved = copy.deepcopy((before, after, service.occupied))
        m.contract(before, after, service); m.reject_controls(before, after, service)
        self.assertEqual((before, after, service.occupied), saved)

    def test_resume_exact_independent_pages_and_fail_closed_extents(self):
        before, _, _ = fixture()
        regs, pages = m.resume(before)
        self.assertEqual(list(regs.values()), before['regs'])
        self.assertEqual(b''.join(pages[p] for p in m.ORDER).hex(), before['pages'])
        pages[b.heap.ARENA][0] ^= 1
        self.assertNotEqual(b''.join(pages[p] for p in m.ORDER).hex(), before['pages'])
        for kind in ('site', 'target', 'regs', 'pages'):
            bad = copy.deepcopy(before)
            if kind in ('site', 'target'): bad['boundary'][kind] ^= 4
            elif kind == 'regs': bad['regs'].pop()
            else: bad['pages'] = bad['pages'][:-2]
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.resume(bad)

    def test_fresh_request_and_descriptor_preconditions(self):
        for page, off in ((b.heap.ARENA, 0x160), (b.heap.ARENA, 0x164),
                          (b.heap.ARENA, 0x168), (b.heap.ARENA, sum(b.t.REQUESTS)),
                          (c.DATA_PAGES[0], 0x800)):
            before, after, service = fixture()
            if page == c.DATA_PAGES[0]: off = before['regs'][7]-page
            mutate(before, page, off)
            with self.subTest(page=page, off=off), self.assertRaises(ValueError): m.contract(before, after, service)

    def test_service_occupancy_call_count_and_padding_are_checked(self):
        for kind in ('calls', 'prior', 'node', 'slack'):
            before, after, service = fixture()
            if kind == 'calls': service.calls += 1
            else: service.occupied[{'prior':0, 'node':m.START//8, 'slack':511}[kind]] ^= True
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.contract(before, after, service)

    def test_rejects_unrelated_owned_and_immutable_mutations(self):
        for page, off in ((b.heap.ARENA, 0), (b.heap.ARENA, 0x1dc),
                          (b.heap.ARENA, 0x1e0), (b.heap.ARENA, m.START+8),
                          (c.DATA_PAGES[1], 0), (b.MODE_PAGE, 100)):
            before, after, service = fixture(); mutate(after, page, off)
            with self.subTest(page=page, off=off), self.assertRaises(ValueError): m.contract(before, after, service)

    def test_duplicate_or_absent_bucket_and_malformed_output_reject(self):
        for kind in ('duplicate', 'absent', 'pages', 'regs', 'target'):
            before, after, service = fixture()
            raw = bytearray.fromhex(after['pages'])
            base = m.ORDER.index(b.heap.ARENA)*4096+sum(b.t.REQUESTS)
            if kind == 'duplicate': struct.pack_into('<I', raw, base, b.heap.ARENA+m.START)
            elif kind == 'absent': struct.pack_into('<I', raw, base+17*4, 0)
            elif kind == 'pages': raw.pop()
            elif kind == 'regs': after['regs'].pop()
            else: after['boundary']['target'] ^= 4
            after['pages'] = raw.hex()
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.contract(before, after, service)

    def test_explicit_subset_not_bucket_index_or_gpr_or_stack_oracle(self):
        for bucket in (0, 1, 32, 63):
            before, after, service = fixture(bucket)
            after['regs'] = [x ^ 0x1234 for x in after['regs']]
            mutate(after, c.DATA_PAGES[0], 0)
            m.contract(before, after, service)

    def test_live_advance_enables_only_calloc_arithmetic(self):
        before, after, _ = fixture()
        nodes, code = {}, {}
        with patch.object(c, 'reference', return_value=(after, {m.p.STOP[0]})) as reference:
            observed, seen, service = m.advance(before, nodes, code)
        self.assertIs(observed, after)
        self.assertEqual(seen, {m.p.STOP[0]})
        args, options = reference.call_args
        self.assertEqual(args[:3], (nodes, code, m.p.STOP[0]))
        self.assertEqual(list(args[3].values()), before['regs'])
        self.assertEqual(b''.join(args[4][p] for p in m.ORDER).hex(), before['pages'])
        self.assertEqual(options, dict(budget=512, image_pages=b.IMAGES,
            heap_service=service, checked_calloc_arithmetic=True, stop_before_call=m.STOP))
        self.assertNotIn('checked_integer_multiply', options)

    def test_model_is_fresh_and_preserves_prior_extent(self):
        first, second = m.model(), m.model()
        self.assertEqual(first.calls, 0)
        self.assertEqual(sum(first.occupied)*8, m.START)
        first.occupied[0] = False
        self.assertTrue(second.occupied[0])


if __name__ == '__main__': unittest.main()
