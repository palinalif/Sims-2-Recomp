"""Authored CFG and failure-report controls; no game data in public tests."""
import importlib.util
import json
from pathlib import Path
import tempfile
import struct
import unittest
from unittest.mock import patch
from types import SimpleNamespace as NS

PATH = Path(__file__).resolve().parents[1] / 'scripts/recomp/measure_startup.py'
spec = importlib.util.spec_from_file_location('measure_startup', PATH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class StartupAttemptTests(unittest.TestCase):
    def decode(self, text):
        return bench.decode_flow(bytes.fromhex(text), 0xA0001000, lambda i: i)

    def test_branches_calls_and_dead_padding(self):
        # Both conditional arms join one return; CALL target deliberately external.
        function, nodes, edges, result = self.decode('7407e8f9000000eb0090c3')
        self.assertEqual(result['size_bytes'], 11)
        self.assertEqual(result['reachable_bytes'], 11)
        self.assertEqual(result['calls'], [0xA0001100])
        self.assertTrue(result['linear_boundary_agreement'])
        self.assertEqual(len(function.blocks), 3)
        self.assertEqual(len(edges[0xA0001000]), 2)
        _, nodes, _, result = self.decode('eb029090c3')
        self.assertEqual(result['size_bytes'], 5)
        self.assertEqual(result['reachable_bytes'], 3)
        self.assertNotIn(0xA0001002, nodes)

    def test_invalid_flow_rejects(self):
        for code in ('eb7fc3', '90', 'ff e0', 'ebfe', '7401b800000000c3', '0f', 'cb'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.decode(code)

    def test_interrupt_is_neither_return_nor_fallthrough(self):
        # Public INT3 / INT-immediate fixtures. A following RET must not hide
        # unsupported trap semantics, even when another branch can return.
        for code in ('ccc3', 'cd80c3', '7401ccc3'):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, 'nonreturn policy'):
                self.decode(code)

    def test_indirect_call_is_dependency_not_success(self):
        _, _, _, result = self.decode('ffd0c3')
        self.assertEqual(result['calls'], [None])
        for marker in ('UNIMPLEMENTED', 'unhandled', 'unresolved'):
            self.assertFalse(bench.supported('void f() { /* ' + marker + ' */ }'))
        self.assertTrue(bench.supported('void f() { return; }'))

    def test_absolute_iat_calls_resolve_without_guessing_register_targets(self):
        _, nodes, _, _ = self.decode('ff15942000a0ffd0ff15982000a0c3')
        pe = NS(DIRECTORY_ENTRY_IMPORT=[NS(dll=b'AUTHORED.dll', imports=[
            NS(address=0xA0002094, name=b'AuthoredService', ordinal=None)])])
        deps = bench.dependencies(nodes, pe)
        self.assertEqual(deps['direct_calls'], [])
        self.assertEqual(deps['indirect_calls'], 3)
        sites = deps['indirect_call_sites']
        self.assertEqual(sites[0]['slot_rva'], '0x2094')
        self.assertEqual(sites[0]['import_metadata'], dict(
            dll='AUTHORED.dll', name='AuthoredService', ordinal=None))
        self.assertIsNone(sites[1]['slot_rva'])
        self.assertIsNone(sites[1]['import_metadata'])
        self.assertEqual(sites[2]['slot_rva'], '0x2098')
        self.assertIsNone(sites[2]['import_metadata'])
        self.assertEqual(deps['absolute_memory_va'], ['0xa0002094', '0xa0002098'])

    def test_direct_calls_and_ordinal_imports(self):
        _, nodes, _, _ = self.decode('e8fb000000ff15942000a0c3')
        pe = NS(DIRECTORY_ENTRY_IMPORT=[NS(dll=b'AUTHORED.dll', imports=[
            NS(address=0xA0002094, name=None, ordinal=7)])])
        deps = bench.dependencies(nodes, pe)
        self.assertEqual(deps['direct_calls'], ['0x1100'])
        self.assertEqual(deps['indirect_call_sites'][0]['import_metadata']['ordinal'], 7)
        self.assertEqual(bench.dependencies(nodes, NS())['indirect_call_sites'][0]['import_metadata'], None)

    def test_segment_offsets_are_not_absolute_va_or_iat_slots(self):
        # Authored FS read/write/call plus an ordinary absolute read.
        _, nodes, _, _ = self.decode('64a10000000064a30000000064ff1500000000a1002000a0c3')
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['absolute_memory_va'], ['0xa0002000'])
        self.assertEqual(len(deps['segmented_memory_operands']), 3)
        self.assertTrue(all(o['segment'] == 'fs' and o['displacement'] == 0 and
                            o['size_bytes'] == 4 for o in deps['segmented_memory_operands']))
        self.assertIsNone(deps['indirect_call_sites'][0]['slot_rva'])
        self.assertIsNone(deps['indirect_call_sites'][0]['import_metadata'])

    def test_allowlist_rejects_before_output_creation(self):
        self.assertEqual(set(bench.ALLOWED_RVAS), {0x8258A9, 0x82585C, 0x8248A3, 0x824727, 0x825BB0, 0x1E36F0, 0x82A6D3, 0x82A47B, 0x1ABD40, 0x9B52C0, 0x1E95C0, 0x1D3E20, 0x1DA310, 0x1460, 0x1AB7E0})
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/rejected'
            with self.assertRaisesRegex(ValueError, 'Unselected'):
                bench.measure(output, 0x82585D)
            self.assertFalse(output.exists())

    def test_resource_index_required_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/resource'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, bench.RESOURCE_RVA)
            self.assertFalse(output.exists())

    def test_resource_window_is_bounded_and_does_not_follow_callees(self):
        # Public synthetic body: register call, base+offset vtable call, RET 8.
        code = bytes.fromhex('ffd0ff5170c20800')
        _, nodes, _, result = bench.decode_candidate(code, bench.RESOURCE_RVA, lambda i: i)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(result['calls'], [None, None])
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['indirect_calls'], 2)
        self.assertEqual(deps['direct_calls'], [])
        self.assertEqual(deps['absolute_memory_va'], [])
        self.assertTrue(all(s['slot_rva'] is None and s['import_metadata'] is None
                            for s in deps['indirect_call_sites']))
        with self.assertRaisesRegex(ValueError, 'Escaping'):
            bench.decode_candidate(b'\x90' * bench.BOUND, bench.RESOURCE_RVA, lambda i: i)

    def test_trap_retains_partial_counts_without_claiming_complete_cfg(self):
        # Authored direct CALL, indirect CALL, trap, unreachable RET.
        with self.assertRaises(bench.FlowRejection) as caught:
            self.decode('e8fb000000ffd0ccc3')
        evidence = caught.exception.evidence
        self.assertEqual(evidence['rejected_instruction_rva'], '0x1007')
        self.assertEqual(evidence['visited_instructions'], 2)
        self.assertEqual(evidence['observed_direct_call_rvas'], ['0x1100'])
        self.assertEqual(evidence['observed_indirect_calls'], 1)
        self.assertFalse(evidence['complete_cfg'])
        self.assertFalse(evidence['dependencies_complete'])
        self.assertNotIn('instructions', evidence)
        self.assertEqual(evidence['adjacent_predecessor_rva'], '0x1005')
        self.assertTrue(evidence['adjacent_predecessor_is_call'])
        self.assertIsNone(evidence['adjacent_call_target_rva'])
        json.dumps(evidence)
        with self.assertRaises(bench.FlowRejection) as direct:
            self.decode('e8fb000000ccc3')
        self.assertEqual(direct.exception.evidence['adjacent_call_target_rva'], '0x1100')
        # A preceding CALL is NOT proof it never returns: rejection stays intact.
        with self.assertRaises(bench.FlowRejection) as no_call:
            self.decode('90ccc3')
        self.assertFalse(no_call.exception.evidence['adjacent_predecessor_is_call'])

    def test_resource_index_context_preserves_caps_and_errors(self):
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals=dict(errorLines=1), result=dict(query=dict(rva='0x1e36f0'),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva='0x1e36f0', disassembly=dict(instructionCount=2, extentBytes=8,
                        extentEndVa=hex(bench.BASE+bench.RESOURCE_RVA+7))),
                truncation=dict(instructions=True)))
        result = bench.resource_index_context(envelope)
        self.assertTrue(result['truncation']['instructions'])
        self.assertEqual(result['log_signals']['errorLines'], 1)
        self.assertFalse(result['boundaries_crosschecked'])
        for section, key, value in [('provenance', 'sourceImageSha256', 'bad'),
                ('provenance', 'analysisPerformed', True), ('provenance', 'mode', 'write'),
                ('provenance', 'headlessExitCode', 1), ('provenance', 'outputParseError', 'bad')]:
            bad = json.loads(json.dumps(envelope))
            bad[section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.resource_index_context(bad)
        for section, key, value in [('query', 'rva', '0x1e36f1'),
                ('program', 'imageBaseVa', '0x400000'),
                ('function', 'resolution', 'address-only'), ('function', 'entryRva', '0x1000')]:
            bad = json.loads(json.dumps(envelope))
            bad['result'][section][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.resource_index_context(bad)

    def test_resource_extent_does_not_absorb_trap_after_nonreturn_candidate(self):
        # Authored CALL followed by INT3: index owns only the CALL.
        code = bytes.fromhex('e8fb000000ccc3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=5,
            indexed_extent_end_va=hex(bench.BASE+bench.RESOURCE_RVA+4))
        with self.assertRaisesRegex(bench.FlowRejection, 'Escaping') as caught:
            bench.decode_resource(code, context, lambda i: i)
        self.assertEqual(caught.exception.evidence['visited_instructions'], 1)
        self.assertEqual(caught.exception.evidence['rejected_instruction_rva'],
                         hex(bench.RESOURCE_RVA+5))
        self.assertTrue(caught.exception.evidence['adjacent_predecessor_is_call'])
        # The trap outside the indexed extent must never become a body instruction.
        capped = dict(context, truncation=dict(instructions=True))
        with self.assertRaisesRegex(ValueError, 'Capped'):
            bench.decode_resource(code, capped, lambda i: i)
        for extent, end in ((0, 0), (len(code)+1, 0), (5, 0)):
            with self.subTest(extent=extent, end=end), self.assertRaisesRegex(ValueError, 'extent mismatch'):
                bench.decode_resource(code, dict(context, indexed_extent_bytes=extent,
                                                indexed_extent_end_va=hex(end)), lambda i: i)

    def test_resource_missing_input_retains_unverified_flags(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/resource'
            with self.assertRaises(OSError):
                bench.measure(output, bench.RESOURCE_RVA, Path(temp) / 'missing-index.json')
            row = json.loads((output / 'metrics.jsonl').read_text())
            self.assertEqual(row['rva'], hex(bench.RESOURCE_RVA))
            self.assertEqual(row['failed_stage'], 'preflight')
            for key in ('attempted', 'lifted', 'compiled_for_aarch64', 'linked',
                        'matched_x86_reference', 'executed_under_qemu', 'android_executed'):
                self.assertFalse(row[key])
            self.assertIsNone(row['ghidra_boundaries_reliable'])

    def test_dependency_requires_index_before_output_creation(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/dependency'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, bench.HANDLER_RVA)
            self.assertFalse(output.exists())

    def test_dependency_index_extent_excludes_unowned_return(self):
        rva = bench.HANDLER_RVA
        # Authored direct CALL + RET: an index owning only CALL cannot use RET.
        code = bytes.fromhex('e8fb000000c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=5,
            indexed_extent_end_va=hex(bench.BASE+rva+4))
        with self.assertRaisesRegex(bench.FlowRejection, 'Escaping'):
            bench.decode_resource(code, context, lambda i: i, rva)
        complete = dict(context, indexed_extent_bytes=6,
                        indexed_extent_end_va=hex(bench.BASE+rva+5))
        _, nodes, _, result = bench.decode_resource(code+b'\xcc', complete, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], 6)
        self.assertEqual(result['calls'], [bench.BASE+rva+0x100])
        self.assertEqual(len(nodes), 2)
        for bad in (dict(complete, truncation=dict(instructions=True)),
                    dict(complete, indexed_extent_end_va=hex(bench.BASE+bench.RESOURCE_RVA+5))):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)

    def test_dependency_index_cannot_be_substituted_or_broaden_allowlist(self):
        rva = bench.HANDLER_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals=dict(errorLines=1), result=dict(query=dict(rva=hex(rva)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(rva), disassembly=dict(instructionCount=1, extentBytes=1,
                        extentEndVa=hex(bench.BASE+rva))), truncation=dict(instructions=False)))
        self.assertEqual(bench.resource_index_context(envelope, rva)['log_signals']['errorLines'], 1)
        for candidate in (bench.RESOURCE_RVA, rva+1, bench.FRAME_RVA):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                bench.resource_index_context(envelope, candidate)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_resource(b'\xc3', {}, lambda i: i, rva+1)

    def test_resource_leaf_keeps_required_index_and_extent_guards(self):
        rva = bench.RESOURCE_LEAF_RVA
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/policy'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=3,
            indexed_extent_end_va=hex(bench.BASE+rva+2))
        _, nodes, _, result = bench.decode_resource(bytes.fromhex('c20400cc'), context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], 3)
        self.assertEqual(len(nodes), 1)
        for bad in (dict(context, indexed_extent_bytes=2),
                    dict(context, truncation=dict(instructions=True))):
            with self.assertRaises(ValueError):
                bench.decode_resource(bytes.fromhex('c20400cc'), bad, lambda i: i, rva)
        with self.assertRaises(ValueError):
            bench.decode_resource(b'\xc3', context, lambda i: i, rva+1)

    def test_cache_refresh_is_already_selected_and_requires_own_index(self):
        from select_candidates import select_candidates
        rva = bench.CACHE_REFRESH_RVA
        selected = select_candidates()['selected']
        self.assertEqual(sum(int(row['rva'], 16) == rva for row in selected), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/cache'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_cache_caller_calls_stay_dependencies_and_padding_is_excluded(self):
        # Authored fixture: five calls to arbitrary external targets, then RET.
        rva = bench.CACHE_REFRESH_RVA
        targets = [bench.BASE+0x2100+n*0x100 for n in range(5)]
        code = b''.join(b'\xe8'+struct.pack('<i', target-(bench.BASE+rva+n*5)-5)
                        for n, target in enumerate(targets))+b'\xc3'
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, _, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(result['calls'], targets)
        self.assertEqual(len(nodes), 6)
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [hex(t-bench.BASE) for t in targets])
        self.assertEqual(deps['indirect_calls'], 0)
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2))):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)

    def test_cache_index_cannot_borrow_another_selected_entry(self):
        rva = bench.CACHE_REFRESH_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None, ghidraVersion='authored'),
            queryLogSignals=dict(errorLines=1), result=dict(query=dict(rva=hex(rva)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(rva), disassembly=dict(instructionCount=1, extentBytes=1,
                        extentEndVa=hex(bench.BASE+rva))), truncation=dict(instructions=False)))
        self.assertEqual(bench.resource_index_context(envelope, rva)['log_signals']['errorLines'], 1)
        for candidate in (bench.RESOURCE_RVA, bench.RESOURCE_LEAF_RVA, rva+1):
            with self.assertRaises(ValueError):
                bench.resource_index_context(envelope, candidate)

    def test_attachment_is_selected_and_requires_its_own_index(self):
        from select_candidates import select_candidates
        rva = bench.ATTACHMENT_RVA
        self.assertEqual(sum(int(row['rva'], 16) == rva
                             for row in select_candidates()['selected']), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/attachment'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_attachment_branch_calls_remain_unresolved_dependencies(self):
        # Authored conditional bypass, register call, direct call, RET.
        rva = bench.ATTACHMENT_RVA
        code = bytes.fromhex('7407ffd0e8f7000000c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, _, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(len(nodes), 4)
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [hex(rva+0x100)])
        self.assertEqual(deps['indirect_calls'], 1)
        self.assertIsNone(deps['indirect_call_sites'][0]['import_metadata'])
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2))):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)

    def test_attachment_cannot_use_cache_index(self):
        rva = bench.CACHE_REFRESH_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None), result=dict(query=dict(rva=hex(rva)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(rva))))
        with self.assertRaisesRegex(ValueError, 'provenance/entry mismatch'):
            bench.resource_index_context(envelope, bench.ATTACHMENT_RVA)

    def test_rebuild_is_selected_and_requires_exact_index(self):
        from select_candidates import select_candidates
        rva = bench.REBUILD_RVA
        self.assertEqual(sum(int(row['rva'], 16) == rva
                             for row in select_candidates()['selected']), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/rebuild'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        other = bench.ATTACHMENT_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None), result=dict(query=dict(rva=hex(other)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(other))))
        with self.assertRaisesRegex(ValueError, 'provenance/entry mismatch'):
            bench.resource_index_context(envelope, rva)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_rebuild_loop_and_callbacks_are_not_followed_or_stubbed(self):
        # Authored LOOP, indirect call, external direct call, RET (not game bytes).
        rva = bench.REBUILD_RVA
        code = bytes.fromhex('90e2fdffd0e8f6000000c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, edges, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(len(nodes), 5)
        self.assertEqual(edges[bench.BASE+rva+1], [bench.BASE+rva, bench.BASE+rva+3])
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [hex(rva+0x100)])
        self.assertEqual(deps['indirect_calls'], 1)
        self.assertIsNone(deps['indirect_call_sites'][0]['import_metadata'])
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2))):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)
        # A reachable trap cannot acquire nonreturn semantics just because
        # another branch reaches a return.
        with self.assertRaisesRegex(bench.FlowRejection, 'nonreturn policy'):
            bench.decode_candidate(bytes.fromhex('7401ccc3'), rva, lambda i: i)

    def test_factory_is_selected_and_requires_own_index(self):
        from select_candidates import select_candidates
        rva = bench.FACTORY_RVA
        self.assertEqual(sum(int(row['rva'], 16) == rva
                             for row in select_candidates()['selected']), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/factory'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        other = bench.REBUILD_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None), result=dict(query=dict(rva=hex(other)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(other))))
        with self.assertRaisesRegex(ValueError, 'provenance/entry mismatch'):
            bench.resource_index_context(envelope, rva)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_factory_segment_and_call_dependencies_do_not_supply_services(self):
        # Authored FS read, conditional call bypass, direct call, RET; not game bytes.
        rva = bench.FACTORY_RVA
        code = bytes.fromhex('64a1000000007405e8f3000000c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, edges, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(len(nodes), 4)
        self.assertEqual(edges[bench.BASE+rva+6], [bench.BASE+rva+13, bench.BASE+rva+8])
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [hex(rva+0x100)])
        self.assertEqual(deps['indirect_calls'], 0)
        self.assertEqual(deps['absolute_memory_va'], [])
        self.assertEqual(deps['segmented_memory_operands'], [dict(
            instruction_rva=hex(rva), segment='fs', displacement=0, size_bytes=4)])
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2))):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)
        with self.assertRaisesRegex(bench.FlowRejection, 'nonreturn policy'):
            bench.decode_candidate(bytes.fromhex('7401ccc3'), rva, lambda i: i)

    def test_sibling_factory_selected_and_cannot_borrow_factory_index(self):
        from select_candidates import select_candidates
        rva = bench.SIBLING_FACTORY_RVA
        self.assertEqual(sum(int(row['rva'], 16) == rva
                             for row in select_candidates()['selected']), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/sibling'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        other = bench.FACTORY_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None), result=dict(query=dict(rva=hex(other)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(other))))
        with self.assertRaisesRegex(ValueError, 'provenance/entry mismatch'):
            bench.resource_index_context(envelope, rva)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_sibling_factory_keeps_segment_indirect_and_boundary_limits(self):
        # Authored FS read, indirect call, RET; never supplies a service body.
        rva = bench.SIBLING_FACTORY_RVA
        code = bytes.fromhex('64a100000000ffd0c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, _, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [])
        self.assertEqual(deps['indirect_calls'], 1)
        self.assertIsNone(deps['indirect_call_sites'][0]['import_metadata'])
        self.assertEqual(deps['segmented_memory_operands'][0]['segment'], 'fs')
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2)),
                    dict(context, indexed_extent_bytes=bench.BOUND+1)):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)
        with self.assertRaisesRegex(bench.FlowRejection, 'nonreturn policy'):
            bench.decode_candidate(bytes.fromhex('7401ccc3'), rva, lambda i: i)

    def test_callback_producer_selected_and_requires_exact_index(self):
        from select_candidates import select_candidates
        rva = bench.CALLBACK_PRODUCER_RVA
        self.assertEqual(sum(int(row['rva'], 16) == rva
                             for row in select_candidates()['selected']), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/callback'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        other = bench.SIBLING_FACTORY_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None), result=dict(query=dict(rva=hex(other)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(other))))
        with self.assertRaisesRegex(ValueError, 'provenance/entry mismatch'):
            bench.resource_index_context(envelope, rva)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_callback_producer_indirect_service_does_not_resolve_target(self):
        # Authored base-relative indirect CALL, conditional bypass, RET.
        # This is not an original service/output/callback contract.
        rva = bench.CALLBACK_PRODUCER_RVA
        code = bytes.fromhex('ff51747402ffd0c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, _, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(result['calls'], [None, None])
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [])
        self.assertEqual(deps['indirect_calls'], 2)
        self.assertEqual(deps['absolute_memory_va'], [])
        self.assertTrue(all(site['slot_rva'] is None and site['import_metadata'] is None
                            for site in deps['indirect_call_sites']))
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2)),
                    dict(context, indexed_extent_bytes=bench.BOUND+1)):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)
        with self.assertRaisesRegex(bench.FlowRejection, 'nonreturn policy'):
            bench.decode_candidate(bytes.fromhex('7401ccc3'), rva, lambda i: i)

    def test_cache_mapping_is_selected_requires_index_and_rejects_substitution(self):
        from select_candidates import select_candidates
        rva = bench.CACHE_MAPPING_RVA
        self.assertEqual(sum(int(row['rva'], 16) == rva
                             for row in select_candidates()['selected']), 1)
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/mapping'
            with self.assertRaisesRegex(ValueError, 'requires index'):
                bench.measure(output, rva)
            self.assertFalse(output.exists())
        other = bench.CACHE_REFRESH_RVA
        envelope = dict(schema='sims2-ghidra-query-envelope/1', provenance=dict(
            sourceImageSha256=bench.IMAGE_SHA, mode='readOnly', analysisPerformed=False,
            headlessExitCode=0, outputParseError=None), result=dict(query=dict(rva=hex(other)),
                program=dict(imageBaseVa=hex(bench.BASE)), function=dict(resolution='function-at',
                    entryRva=hex(other))))
        with self.assertRaisesRegex(ValueError, 'provenance/entry mismatch'):
            bench.resource_index_context(envelope, rva)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', rva+1, lambda i: i)

    def test_cache_mapping_calls_do_not_follow_jump_table_dependency(self):
        # Authored conditional refresh and external CALL; not original bytes.
        rva = bench.CACHE_MAPPING_RVA
        code = bytes.fromhex('7405e8f9000000e8f4000000c3')
        context = dict(truncation=dict(instructions=False), indexed_extent_bytes=len(code),
            indexed_extent_end_va=hex(bench.BASE+rva+len(code)-1))
        _, nodes, _, result = bench.decode_resource(code+b'\xcc', context, lambda i: i, rva)
        self.assertEqual(result['size_bytes'], len(code))
        self.assertEqual(len(nodes), 4)
        self.assertEqual(result['calls'], [bench.BASE+rva+0x100]*2)
        deps = bench.dependencies(nodes, NS())
        self.assertEqual(deps['direct_calls'], [hex(rva+0x100)]*2)
        self.assertEqual(deps['indirect_calls'], 0)
        for bad in (dict(context, truncation=dict(instructions=True)),
                    dict(context, indexed_extent_bytes=len(code)-1,
                         indexed_extent_end_va=hex(bench.BASE+rva+len(code)-2)),
                    dict(context, indexed_extent_bytes=bench.BOUND+1)):
            with self.assertRaises(ValueError):
                bench.decode_resource(code, bad, lambda i: i, rva)
        # No exception is made for a jump table or a nonreturning callee.
        with self.assertRaisesRegex(ValueError, 'Unresolved jump'):
            bench.decode_candidate(bytes.fromhex('ffe0c3'), rva, lambda i: i)
        with self.assertRaisesRegex(bench.FlowRejection, 'nonreturn policy'):
            bench.decode_candidate(bytes.fromhex('7401ccc3'), rva, lambda i: i)

    def test_external_tail_is_not_a_local_label_or_return(self):
        base, call, tail = 0xA0001000, 0xA0002000, 0xA0003000
        code = b'\xe8' + struct.pack('<i', call-base-5) + b'\xe9' + struct.pack('<i', tail-base-10)
        function, nodes, edges, analysis = bench.decode_tail(code, base, call, tail, lambda i: i)
        self.assertEqual(set(function.blocks), {base})
        self.assertEqual(set(nodes), {base, base+5})
        self.assertEqual(edges, {base: [base+5], base+5: [tail]})
        self.assertEqual(analysis['calls'], [call])
        self.assertEqual(analysis['external_tail_va'], hex(tail))
        self.assertFalse(analysis['tail_target_decoded'])
        self.assertEqual(analysis['size_bytes'], 10)
        with self.assertRaisesRegex(ValueError, 'Escaping'):
            bench.decode_flow(code, base, lambda i: i)

    def test_tail_contract_rejects_wrong_indirect_truncated_and_internal_flow(self):
        base, call, tail = 0xA0001000, 0xA0002000, 0xA0003000
        code = b'\xe8' + struct.pack('<i', call-base-5) + b'\xe9' + struct.pack('<i', tail-base-10)
        for bad, target, endpoint in ((code[:-1], call, tail), (code+b'\xc3', call, tail),
                (code, call+1, tail), (code, call, tail+1),
                (b'\xff\xd0'+code[2:], call, tail), (code, call, base+5),
                (code[:5]+b'\xc3'+code[6:], call, tail)):
            with self.subTest(bad=bad, target=target, endpoint=endpoint), self.assertRaises(ValueError):
                bench.decode_tail(bad, base, target, endpoint, lambda i: i)

    def test_tail_region_cannot_absorb_entry_or_accept_backward_escape(self):
        base = bench.BASE + bench.TAIL_RVA
        extent = bench.ENTRY_RVA - bench.TAIL_RVA
        # Authored NOP/RET window, NOT original instructions. The RET is placed
        # exactly at the excluded entry: accepting it would silently widen scope.
        with self.assertRaisesRegex(ValueError, 'Escaping'):
            bench.decode_candidate(b'\x90' * extent + b'\xc3', bench.TAIL_RVA, lambda i: i)
        _, nodes, _, analysis = bench.decode_candidate(
            b'\x90' * (extent-1) + b'\xc3' + b'\xff\xe0', bench.TAIL_RVA, lambda i: i)
        self.assertEqual(analysis['size_bytes'], extent)
        self.assertEqual(max(nodes), base+extent-1)
        with self.assertRaisesRegex(ValueError, 'Escaping'):
            bench.decode_candidate(b'\xeb\xfd' + b'\xc3', bench.TAIL_RVA, lambda i: i)
        with self.assertRaisesRegex(ValueError, 'Unselected'):
            bench.decode_candidate(b'\xc3', bench.TAIL_RVA+1, lambda i: i)

    def test_missing_input_retains_failure_and_no_false_claims(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            output = Path(temp) / 'work/recomp-bench/test'
            with self.assertRaises(OSError):
                bench.measure(output)
            saved = (output / 'metrics.jsonl').read_bytes()
            row = json.loads(saved)
            for key in ('attempted', 'lifted', 'compiled_for_aarch64', 'linked',
                        'matched_x86_reference', 'executed_under_qemu', 'android_executed'):
                self.assertFalse(row[key])
            self.assertEqual(row['failed_stage'], 'preflight')
            with self.assertRaises(FileExistsError):
                bench.measure(output)
            self.assertEqual(saved, (output / 'metrics.jsonl').read_bytes())

    def test_output_escape_rejects(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(bench, 'ROOT', Path(temp)):
            root = Path(temp)
            private = root / 'work/recomp-bench'
            private.mkdir(parents=True)
            outside = root / 'outside'
            outside.mkdir()
            (private / 'link').symlink_to(outside)
            for output in (outside / 'test', private / 'link/test'):
                with self.assertRaises(ValueError):
                    bench.measure(output)
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
