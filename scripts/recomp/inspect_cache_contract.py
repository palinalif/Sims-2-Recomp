#!/usr/bin/env python3
"""Read-only five-cache caller ABI/scope preflight; never lift or execute bodies."""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, digest
from measure_startup import BASE, decode_flow, dependencies
from inspect_startup_dependency import crosscheck_index
from measure_module_acquisition import selection
from measure_group import CATALOG_SHA
from measure_wrappers import CATALOG_SHA as WRAPPER_CATALOG_SHA

RVA, SIZE = 0x1ABD40, 88
CALLEES = (0x1240, 0x1290, 0x12D0, 0x1250, 0x1270)
CACHES = (0x80, 0x84, 0x88, 0x8C, 0x90)


def require(ok):
    if not ok:
        raise ValueError('Five-cache contract mismatch')


def caller_contract(nodes):
    """Check the complete straight-line operand contract, not callee semantics.

    PUSH of each next argument precedes the prior result store. All five argument
    words remain on the stack until one ADD20. SETNE writes AL, not full EAX.
    No function-name, decompiler-type or standalone-leaf ABI inference is used.
    """
    from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
    items = sorted(nodes.values(), key=lambda i: i.address)

    def reg(i, op, name):
        return op.type == X86_OP_REG and i.reg_name(op.reg) == name

    def imm(op, value):
        return op.type == X86_OP_IMM and op.imm & 0xFFFFFFFF == value

    def mem(i, op, offset):
        return (op.type == X86_OP_MEM and op.size == 4 and
                not op.mem.segment and not op.mem.index and
                i.reg_name(op.mem.base) == 'esi' and op.mem.disp == offset)

    def take(mnemonic, predicates):
        require(bool(items))
        i = items.pop(0)
        require(i.mnemonic == mnemonic and len(i.operands) == len(predicates))
        require(all(check(i, op) for check, op in zip(predicates, i.operands)))
        return i

    r = lambda name: lambda i, op: reg(i, op, name)
    m = lambda offset: lambda i, op: mem(i, op, offset)
    v = lambda value: lambda i, op: imm(op, value)
    take('push', [r('esi')])
    take('mov', [r('esi'), r('ecx')])
    calls = []
    for n, callee in enumerate(CALLEES):
        argument = take('push', [m(0x34)])
        if n:
            take('mov', [m(CACHES[n-1]), r('eax')])
        call = take('call', [v(BASE+callee)])
        calls.append(dict(call_rva=hex(call.address-BASE), callee_rva=hex(callee),
                          argument_push_rva=hex(argument.address-BASE),
                          retained_argument_words=n+1, cache_offset=hex(CACHES[n])))
    take('add', [r('esp'), v(20)])
    take('mov', [m(CACHES[-1]), r('eax')])
    take('cmp', [m(CACHES[0]), v(0)])
    take('setne', [r('al')])
    take('pop', [r('esi')])
    take('ret', [])
    require(not items)
    return dict(calls=calls, receiver_register='ecx', saved_receiver_register='esi',
        handle_offset='0x34', null_guard=False, caller_argument_cleanup_bytes=20,
        result='AL = (cache80 != 0); upper EAX retains fifth callee result',
        flags='CMP cache80,0; SETNE/POP/RET preserve those flags',
        callee_contracts_verified=False, composed_reference_available=False)


def coverage(manifest, catalogs):
    """A source pin/catalog is inventory, never evidence of composed correctness."""
    chosen = [int(row['rva'], 16) for row in manifest['selected']]
    require(len(chosen) == len(set(chosen)) == manifest['counts']['selected'])
    require(len(chosen) <= manifest['authorization_limit'] and RVA in chosen)
    available = set()
    for catalog in catalogs:
        require(catalog['analysis_image_sha256'] == IMAGE_SHA)
        require(bool(catalog['states']))
        available.update(int(key, 16) for key in catalog['function_sha256_by_rva'])
    missing_selection = [r for r in CALLEES if r not in chosen]
    missing_reference = [r for r in CALLEES if r not in available]
    return dict(selected_count=len(chosen), authorization_limit=manifest['authorization_limit'],
        selected_callee_rvas=[hex(r) for r in CALLEES if r in chosen],
        catalog_callee_rvas=[hex(r) for r in CALLEES if r in available],
        unselected_callee_rvas=[hex(r) for r in missing_selection],
        missing_catalog_callee_rvas=[hex(r) for r in missing_reference],
        closed_native_body_count=len(chosen)+len(missing_selection),
        additional_native_bodies_needed=len(missing_selection),
        whole_caller_native_comparison_ready=False,
        reason='No composed caller reference; unselected callees cannot be silently translated',
        reference_only_dependencies_do_not_supply_native_implementations=True)


def inspect(index, output):
    output = output.resolve()
    require(output.is_relative_to((ROOT/'work/recomp-bench').resolve()))
    require(not output.exists())
    start = time.monotonic()
    fixture = ROOT/'work/interop-legacy-002'
    image = fixture/'analysis-image.bin'
    require(digest(image) == IMAGE_SHA)
    import pefile
    pe = pefile.PE(data=image.read_bytes())
    require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14C)
    code = pe.get_data(RVA, SIZE)
    require(len(code) == SIZE)
    _, nodes, _, flow = decode_flow(code, BASE+RVA, lambda i: i)
    require(flow['size_bytes'] == SIZE and flow['blocks'] == 1)
    body = dict(size_bytes=SIZE, instructions=len(nodes),
                instruction_rvas=[hex(a-BASE) for a in sorted(nodes)])
    indexed = crosscheck_index(json.loads(index.read_text()), body, RVA)
    contract = caller_contract(nodes)
    catalogs, pins = [], {}
    for name, pin in (('group-reference.json', CATALOG_SHA),
                      ('wrapper-reference.json', WRAPPER_CATALOG_SHA)):
        path = fixture/name
        require(digest(path) == pin)
        catalogs.append(json.loads(path.read_text()))
        pins[name] = pin
    inventory = coverage(selection(), catalogs)
    require(digest(image) == IMAGE_SHA)
    report = dict(schema='ts2-cache-contract-preflight/1', rva=hex(RVA),
        image_sha256=IMAGE_SHA, index_sha256=digest(index), catalog_pins=pins,
        harness_sha256=digest(Path(__file__)), invocation=[sys.executable, *sys.argv],
        index=indexed, flow=flow, dependencies=dependencies(nodes, pe),
        contract=contract, coverage=inventory, elapsed_seconds=time.monotonic()-start,
        inspection_complete=True, native_comparison_ready=False,
        selected_new=False, lift_attempted=False, matched_x86=False,
        qemu_executed=False, android_executed=False,
        limits=['Static caller operands and pinned catalog inventory only; no CPU execution',
                'Existing leaf/wrapper saved cases are not a five-callee composed reference',
                'No callee body read/lift, fabricated endpoint, ABI binding or scope expansion',
                'Callee effects, integer/FP ABI, ownership, invalid handles and services unresolved',
                'Need separate scoped approval for 1290/12D0 before native-body closure'])
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        inspect(args.index, args.output)
    except (OSError, ValueError, KeyError, TypeError):
        p.exit(1, 'Five-cache preflight rejected; no execution claim.\n')
    print('Static preflight complete; native comparison BLOCKED; no new translation')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
