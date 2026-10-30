"""Authored capacity-boundary fixtures and real occupancy-model checks."""
import copy
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

from test_recomp_table_node import fixture as node_fixture

PATH = Path(__file__).resolve().parents[1]/'scripts/recomp/probe_live_capacity.py'
spec = importlib.util.spec_from_file_location('live_capacity', PATH)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c, b = m.c, m.b


def fixture():
    _, before, _ = node_fixture()
    after = copy.deepcopy(before)
    after['boundary'] = dict(site=m.STOP[0], target=m.STOP[1])
    after['regs'][7] -= 32
    raw = bytearray.fromhex(after['pages'])
    struct.pack_into('<I', raw, after['regs'][7]-c.DATA_PAGES[0], m.REQUEST)
    after['pages'] = raw.hex()
    return before, after


def mutate(row, page, off):
    raw = bytearray.fromhex(row['pages'])
    raw[m.node.ORDER.index(page)*4096+off] ^= 1
    row['pages'] = raw.hex()


class LiveCapacityTests(unittest.TestCase):
    def test_boundary_and_seven_controls_preserve_inputs(self):
        before, after = fixture(); saved = copy.deepcopy((before, after))
        m.contract(before, after); m.reject_controls(before, after)
        self.assertEqual((before, after), saved)

    def test_resume_independent_pages_and_exact_extents(self):
        before, _ = fixture(); regs, pages = m.resume(before)
        self.assertEqual(list(regs.values()), before['regs'])
        self.assertEqual(b''.join(pages[p] for p in m.node.ORDER).hex(), before['pages'])
        pages[b.heap.ARENA][0] ^= 1
        self.assertNotEqual(b''.join(pages[p] for p in m.node.ORDER).hex(), before['pages'])
        for kind in ('site', 'target', 'regs', 'pages'):
            bad = copy.deepcopy(before)
            if kind in ('site', 'target'): bad['boundary'][kind] ^= 4
            elif kind == 'regs': bad['regs'].pop()
            else: bad['pages'] = bad['pages'][:-2]
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.resume(bad)

    def test_actual_advance_stops_before_allocator_without_response(self):
        before, after = fixture(); nodes, code = {}, {}
        with patch.object(c, 'reference', return_value=(after, set())) as ref:
            self.assertEqual(m.advance(before, nodes, code), (after, set()))
        args, options = ref.call_args
        self.assertEqual(args[:3], (nodes, code, m.node.STOP[0]))
        self.assertEqual(list(args[3].values()), before['regs'])
        self.assertEqual(b''.join(args[4][p] for p in m.node.ORDER).hex(), before['pages'])
        self.assertEqual(options, dict(budget=512, image_pages=b.IMAGES, stop_before_call=m.STOP))
        self.assertNotIn('heap_service', options)

    def test_incoming_table_and_node_are_not_invented(self):
        for off in (0x160, 0x164, 0x168, 0x1e0, m.node.START, m.node.START+4,
                    sum(b.t.REQUESTS)+17*4):
            before, after = fixture(); mutate(before, b.heap.ARENA, off)
            with self.subTest(off=off), self.assertRaises(ValueError): m.contract(before, after)

    def test_all_nonstack_bytes_and_preserved_stack_frame_checked(self):
        for page, off in ((b.heap.ARENA, 0), (b.MODE_PAGE, 15), (c.DATA_PAGES[1], 80),
                          (c.DATA_PAGES[0], 4095)):
            before, after = fixture(); mutate(after, page, off)
            with self.subTest(page=page), self.assertRaises(ValueError): m.contract(before, after)

    def test_malformed_output_and_pending_request_reject(self):
        for kind in ('pages', 'regs', 'request', 'cleanup'):
            before, after = fixture()
            if kind == 'pages': after['pages'] = after['pages'][:-2]
            elif kind == 'regs': after['regs'].pop()
            elif kind == 'cleanup': after['regs'][7] += 4
            else: mutate(after, c.DATA_PAGES[0], after['regs'][7]-c.DATA_PAGES[0])
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.contract(before, after)

    def test_subset_explicitly_excludes_volatile_gpr_and_stack_scratch(self):
        before, after = fixture()
        for i in range(7): after['regs'][i] ^= 0x5555
        mutate(after, c.DATA_PAGES[0], 0)
        m.contract(before, after)

    def test_fresh_occupancy_has_no_fitting_span(self):
        first, second = m.exhaustion_model(), m.exhaustion_model()
        self.assertEqual((m.OCCUPIED, m.FREE, m.REQUEST-m.FREE), (3104, 992, 40))
        self.assertEqual(first.calls, 0)
        self.assertEqual(first.occupied, [True]*388+[False]*124)
        first.occupied[0] = False
        self.assertTrue(second.occupied[0])

    def test_real_model_returns_zero_without_overwriting_occupied_memory(self):
        import unicorn.x86_const as x
        model = m.exhaustion_model()
        occupied = model.occupied.copy()
        sp, ret = c.DATA_PAGES[0]+256, 0x12345678
        class Cpu:
            def __init__(self): self.regs = {'esp': sp}
            def reg_read(self, key): return self.regs[key]
            def reg_write(self, key, value): self.regs[key] = value
            def mem_read(self, address, size):
                self_address = (address, size)
                if self_address != (sp, 16): raise AssertionError(self_address)
                return struct.pack('<4I', ret, b.heap.HANDLE, 0, m.REQUEST)
        cpu = Cpu()
        model.invoke(cpu, {'esp':'esp', 'eax':'eax'}, ret)
        self.assertEqual(cpu.regs, {'esp':sp+16, 'eax':0, x.UC_X86_REG_EIP:ret})
        self.assertEqual((model.calls, model.occupied), (1, occupied))


if __name__ == '__main__': unittest.main()
