#!/usr/bin/env python3
"""Actual 1AB665 receiver/mode/input binding via bounded original-x86 traces.

Independent pure-python prediction versus the checked single-step trace for four
decoded receiver families: populated +34 return, zero +1C no-open return, +7C==0
opening 3C50(string,0x40) and +7C!=0 opening 3A50(string). Opener CALL sites are
observed at the boundary only; no callee executes or responds. Private artifacts.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inspect_classifier_paths as probe
from inspect_initialization_graph import seed_receipt
from measure_startup import BASE, decode_flow, dependencies
c = probe.c
RVA, SIZE = 0x1ab665, 267
FUNCTION_SHA = '6c35c08430e158c83c52e190dacc59e507d1683e57f0b10cc735a620eb8ff4fe'
ENTRY = BASE + RVA
SITE_3A50, TARGET_3A50 = BASE + 0x1ab68f, BASE + 0x3a50
SITE_3C50, TARGET_3C50 = BASE + 0x1ab6a1, BASE + 0x3c50
PUSHES = (0x1ab665, 0x1ab666, 0x1ab668, 0x1ab669)
GATE = (0x1ab66b, 0x1ab66e, 0x1ab674, 0x1ab677)
GUARD_PATH = frozenset((0x1ab665, 0x1ab666, 0x1ab668, 0x1ab669, 0x1ab66b, 0x1ab66e,
                        0x1ab766, 0x1ab769, 0x1ab76a, 0x1ab76b))
FAMILIES = ('populated-34', 'zero-1c', 'mode-zero-3c50', 'mode-nonzero-3a50')
CONTROLS = ('swapped-target', 'dropped-argument')


def family(n):
    return n & 3


def heap_form(n):
    return bool(n & 4)


def visited_for(fam, heap):
    """Instruction sequence derived from the recorded decode, per family/form."""
    if fam == 0:
        return (*PUSHES, 0x1ab66b, 0x1ab66e, 0x1ab766, 0x1ab769, 0x1ab76a, 0x1ab76b)
    if fam == 1:
        return (*PUSHES, *GATE, 0x1ab76c, 0x1ab76e, 0x1ab769, 0x1ab76a, 0x1ab76b)
    if fam == 2:
        core = (0x1ab67d, 0x1ab681, 0x1ab684, 0x1ab696, 0x1ab69a)
        if heap:
            core = (*core, 0x1ab69c)
        # The boundary CALL site itself is recorded in pc, never in visited:
        # the trace refuses to execute it.
        return (*PUSHES, *GATE, *core, 0x1ab69e, 0x1ab6a0)
    core = (0x1ab67d, 0x1ab681, 0x1ab684, 0x1ab686, 0x1ab68a)
    if heap:
        core = (*core, 0x1ab68c)
    return (*PUSHES, *GATE, *core, 0x1ab68e)


def layout(n, mode_override=None):
    fam, heap = family(n), heap_form(n)
    rng = random.Random((RVA << 8) + n)
    esp = c.DATA_PAGES[0] + (0x800 if n % 2 else 0xc00)
    # Receiver stays far enough inside its page that base+0x7c is mapped.
    obj = c.DATA_PAGES[1] + (0x80, 0x800, 0xd00, 0xe00)[(n >> 3) % 4]
    mode = (0 if fam == 2 else (1, 0x80, 0xff)[(n >> 6) % 3]) if fam >= 2 \
        else rng.getrandbits(8)
    if mode_override is not None:
        mode = mode_override
    return dict(fam=fam, heap=heap, esp=esp, obj=obj,
                # std::string: heap form stores a separate buffer pointer at +0x60.
                capacity=(16, 0x1f, 31, 0xffffffff)[(n >> 5) % 4] if heap
                else (0, 7, 15, 15)[(n >> 5) % 4],
                data=c.DATA_PAGES[2] + (0x100 if (n >> 7) % 2 else 0x900),
                mode=mode,
                handle34=(rng.getrandbits(32) or 1) if fam == 0 else 0,
                gate1c=0 if fam == 1 else (rng.getrandbits(32) or 0xffffffff))


def state(n, mode_override=None):
    c.require(type(n) is int and 0 <= n < 64)
    rng = random.Random((RVA << 8) + n + 0x5eed)
    regs = {r: rng.getrandbits(32) for r in c.REGS}
    loc = layout(n, mode_override)
    pages = {p: bytearray(rng.randbytes(4096)) for p in probe.PAGES}
    struct.pack_into('<I', pages[c.DATA_PAGES[0]], loc['esp'] - c.DATA_PAGES[0], c.RETURN)
    off = loc['obj'] - c.DATA_PAGES[1]
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off + 0x34, loc['handle34'])
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off + 0x1c, loc['gate1c'])
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off + 0x74, loc['capacity'])
    struct.pack_into('<I', pages[c.DATA_PAGES[1]], off + 0x60,
                     loc['data'] if loc['heap'] else (rng.getrandbits(32) | 1))
    pages[c.DATA_PAGES[1]][off + 0x7c] = loc['mode']
    regs['esp'] = loc['esp']
    regs['ecx'] = loc['obj']
    return regs, pages, loc


def predicted_path(loc):
    """Pure input->path contract: populated +34, zero +1C, then +7C selector."""
    return 0 if loc['handle34'] else (
        1 if loc['gate1c'] == 0 else (2 if loc['mode'] == 0 else 3))


def predict(loc, regs, pages):
    """Independent pure-python final state; never consults trace nodes or unicorn."""
    heap = loc['heap']
    path = predicted_path(loc)
    after = {p: bytearray(b) for p, b in pages.items()}
    out = dict(regs)
    esp, obj = loc['esp'], loc['obj']
    string = loc['data'] if heap else obj + 0x60

    def push(value):
        nonlocal esp
        esp -= 4
        struct.pack_into('<I', after[c.DATA_PAGES[0]], esp - c.DATA_PAGES[0], value)

    entry_esi, entry_edi = out['esi'], out['edi']
    push(entry_esi)
    push(entry_edi)
    out.update(esi=obj, edi=0)
    if path < 2:
        out['eax'] = (out['eax'] & 0xffffff00) | (1 if path == 0 else 0)
        # Two pops restore the entry frame registers; ret consumes the entry
        # return slot, so final ESP is one word above the entry ESP.
        out.update(esi=entry_esi, edi=entry_edi, esp=loc['esp'] + 4)
        outcome, site = 'returned', c.RETURN
    else:
        if path == 2:
            push(0x40)
        push(string)
        out.update(eax=string, esp=esp)
        outcome = 'external-call'
        site = SITE_3C50 if path == 2 else SITE_3A50
    return dict(outcome=outcome, pc=site,
                visited=[BASE + a for a in visited_for(path, heap)],
                regs=[out[r] for r in c.REGS],
                pages=b''.join(after[p] for p in probe.PAGES).hex())


def mutate(mode, prediction, path):
    """Deterministic adversarial predictions that must NOT equal the observation."""
    c.require(mode in CONTROLS and path >= 2)
    if mode == 'swapped-target':
        other = 3 if path == 2 else 2
        return dict(prediction,
                    pc=SITE_3C50 if other == 2 else SITE_3A50,
                    visited=[BASE + a for a in visited_for(other, False)])
    regs = list(prediction['regs'])
    regs[c.REGS.index('esp')] += 4
    return dict(prediction, regs=regs)


def extract_contract(nodes):
    """Derive the mode-selection graph from decoded instruction nodes only."""
    at = lambda r: nodes[BASE + r]
    c.require(at(0x1ab66b).mnemonic == 'cmp' and '0x34' in at(0x1ab66b).op_str)
    c.require(at(0x1ab674).mnemonic == 'cmp' and '0x1c' in at(0x1ab674).op_str)
    c.require(at(0x1ab67d).mnemonic == 'cmp' and '0x7c' in at(0x1ab67d).op_str
              and at(0x1ab67d).op_str.endswith('0'))
    c.require(at(0x1ab681).mnemonic == 'lea' and '0x60' in at(0x1ab681).op_str)
    c.require(at(0x1ab684).mnemonic == 'je'
              and at(0x1ab684).operands[0].imm == BASE + 0x1ab696)
    calls = {}
    for r, expect in ((0x1ab68f, TARGET_3A50), (0x1ab6a1, TARGET_3C50)):
        insn = at(r)
        c.require(insn.mnemonic == 'call' and insn.operands[0].imm == expect)
        calls[hex(r)] = hex(expect - BASE)
    # The 3C50 branch pushes the constant 0x40 before the string pointer.
    c.require(at(0x1ab69e).mnemonic == 'push' and at(0x1ab69e).operands[0].imm == 0x40)
    c.require(at(0x1ab6a0).mnemonic == 'push' and at(0x1ab68e).mnemonic == 'push')
    for r in (0x1ab696, 0x1ab686):
        insn = at(r)
        c.require(insn.mnemonic == 'cmp' and '0x14' in insn.op_str
                  and insn.operands[0].size == 4)
    c.require(at(0x1ab6a7).mnemonic == 'mov' and '0x34' in at(0x1ab6a7).op_str)
    return dict(early_return_34_nonzero='1ab66e->1ab766 (AL=1)',
                no_open_1c_zero='1ab677->1ab76c (AL=0)',
                selector='[receiver+0x7c]==0 -> call 0x3c50(string,0x40) '
                         'else call 0x3a50(string)',
                string='std::string at receiver+0x60; data = capacity>0xf ? [base] : base',
                result_store='opener result -> [receiver+0x34]; zero -> 1ab763 arm',
                direct_call_sites=calls)


def trace_case(nodes, code_pages, n, mode_override=None):
    regs, pages, loc = state(n, mode_override)
    result = probe.trace(nodes, code_pages, ENTRY, regs, pages)
    expected = predict(loc, regs, pages)
    observed = {k: result[k] for k in expected}
    return loc, result, expected, observed


def run(output):
    output = c.private_output(output)
    row = dict(schema='ts2-enclosing-opener-selection-x86/1', success=False,
        rva=hex(RVA), size=SIZE, image_sha256=c.IMAGE_SHA,
        harness_sha256=c.digest(Path(__file__)),
        probe_sha256=c.digest(Path(probe.__file__)),
        helper_sha256=c.digest(Path(c.__file__)),
        invocation=[sys.executable, *sys.argv], families=list(FAMILIES),
        cases=64, oracle_matches=0, selector_flips=0, controls_rejected=0,
        adversarial_rejections=0, external_target_executed=False,
        host_executed=False, arm64_executed=False, android_executed=False,
        stub=False, whole_function_verified=False, e3_fragment=True, e3_complete=False,
        e4_complete=False, windows_heap_verified=False,
        compared=['outcome', 'stop site/pc', 'visited instruction sequence',
                  'eight final GPRs', 'all six complete 4096-byte pages'],
        limits=['Original-x86 bounded trace to the opener CALL boundary only; '
                'opener bodies never execute here and receive no response',
                'Receiver/string inputs are authored storage bound to the decoded '
                'reads, not producer-written ownership or lifetime proof',
                'No flags/FP/PC/native execution; not composed 3A50/3C50 or E3/E4',
                'Matrix covers four decoded receiver families reaching the opener '
                'selection; failure/cleanup/callback arms remain unvisited'])
    stage = 'preflight'
    try:
        import pefile
        image = c.ROOT / 'work/interop-legacy-002/analysis-image.bin'
        c.require(c.digest(image) == c.IMAGE_SHA)
        row['seed'] = seed_receipt(
            c.ROOT / 'work/recomp-bench/frontier-d3-sibling-final/result.json')
        pe = pefile.PE(data=image.read_bytes())
        c.require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        stage = 'decode'
        code = pe.get_data(RVA, SIZE)
        c.require(hashlib.sha256(code).hexdigest() == FUNCTION_SHA)
        function, nodes, _, _ = decode_flow(code, ENTRY, lambda i: i)
        c.require(len(nodes) == 83)
        deps = dependencies(nodes, pe)
        c.require(not deps['indirect_calls'] and not deps['absolute_memory_va']
                  and not deps['segmented_memory_operands'])
        seed = row['seed']
        c.require(len(deps['direct_calls']) == len(seed['direct'])
                  and set(deps['direct_calls']) == set(seed['direct']))
        row['dependencies'] = deps
        row['contract'] = extract_contract(nodes)
        code_pages = {BASE + 0x1ab000: bytearray(4096)}
        code_pages[BASE + 0x1ab000][0x665:0x665 + SIZE] = code
        stage = 'trace-differential'
        outcomes, visited, families_seen = {}, set(), set()
        for n in range(64):
            loc, result, expected, observed = trace_case(nodes, code_pages, n)
            c.require(observed == expected)
            fam = loc['fam']
            families_seen.add(fam)
            outcomes[result['outcome']] = outcomes.get(result['outcome'], 0) + 1
            visited.update(a - BASE for a in expected['visited'])
            if result['outcome'] == 'external-call':
                site = result['pc']
                c.require((fam, site, nodes[site].operands[0].imm) in
                          ((2, SITE_3C50, TARGET_3C50), (3, SITE_3A50, TARGET_3A50)))
            row['oracle_matches'] += 1
            if fam >= 2:
                for mode in CONTROLS:
                    c.require(mutate(mode, expected, fam) != observed)
                    row['controls_rejected'] += 1
        c.require(families_seen == {0, 1, 2, 3} and outcomes.get('returned', 0) == 32)
        stage = 'selector-differential'
        for n in range(64):
            if family(n) < 2:
                continue
            base_loc = layout(n)
            flipped_mode = 0x5a if base_loc['mode'] == 0 else 0
            _, a_res, _, _ = trace_case(nodes, code_pages, n)
            _, b_res, b_exp, b_obs = trace_case(nodes, code_pages, n, flipped_mode)
            c.require(b_obs == b_exp)
            target_a = nodes[a_res['pc']].operands[0].imm
            target_b = nodes[b_res['pc']].operands[0].imm
            c.require(target_a != target_b and
                      {target_a - BASE, target_b - BASE} == {0x3a50, 0x3c50})
            # Only the +0x7C selector byte differs between the two runs.
            _, pa, _ = state(n)
            _, pb, _ = state(n, flipped_mode)
            delta = [o for o in range(4096)
                     if pa[c.DATA_PAGES[1]][o] != pb[c.DATA_PAGES[1]][o]]
            c.require(delta == [base_loc['obj'] - c.DATA_PAGES[1] + 0x7c])
            c.require(a_res['regs'][-1] != b_res['regs'][-1])  # ESP argument shape
            row['selector_flips'] += 1
        stage = 'adversarial'
        for bad in ({'esp': c.DATA_PAGES[0] + 0x801},
                    {'ecx': c.DATA_PAGES[1] + 4096 - 0x30}):
            regs, pages, loc = state(0)
            regs.update(bad)
            result = probe.trace(nodes, code_pages, ENTRY, regs, pages)
            c.require(result['outcome'] == 'unsafe-access')
            row['adversarial_rejections'] += 1
        row['coverage'] = dict(visited=len(visited), total=83,
            newly_visited_vs_guard=len(visited - GUARD_PATH), outcomes=outcomes)
        c.require(c.digest(image) == c.IMAGE_SHA)
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage, error_type=type(exc).__name__)
        raise
    finally:
        (output / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        r = run(a.output)
    except Exception:
        p.exit(1, 'Enclosing opener selection trace failed; inspect private receipt.\n')
    print('1AB665 opener selection: 64/64 prediction matches, '
          f"{r['selector_flips']} selector flips, {r['controls_rejected']} controls "
          f"reject, {r['adversarial_rejections']} adversarial inputs refuse. "
          'x86 trace ONLY; NOT composed/E3/E4/Android.')


if __name__ == '__main__':
    main()
