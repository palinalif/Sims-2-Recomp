#!/usr/bin/env python3
"""E2: bounded setter/association lifts, x86 and GuestMemory two-ISA differential.

Only authored infrastructure is public. Bodies, states and logs stay in work/.
No callback invocation, opener composition or production registration is implied.
"""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from measure_leaf import ROOT, IMAGE_SHA, REVISION, digest, verify, decode_function
from measure_group import index_context
from execute_cache_skip import private_output, require
from execute_cache_dispatch import BASE, PAGES, DATA_PAGES, IMAGE_PAGES, REGS, RETURN, reference, compare
from execute_cache_caller import TEMPLATE, BRIDGE
from execute_text_leaf import assess as assess_text

RVA, SIZE = 0x1090, 12
OPENER_MEMBER = 0x122f0
OPENER_MEMBER_SHA = 'a9fa6fc184515b22de0f336fb8686d8afbf0c4acce800411280b1821c98b138d'
OPENER_MEMBER_TABLE = BASE+0x12220
ALLOCATOR_POLICY = 0x8437c6
ALLOCATOR_POLICY_SHA = 'ee654d19d8938203bb33ecc9fd9a28bfa336e0e9d5787817a20b4360295f7d26'
ALLOCATOR_POLICY_GLOBAL = BASE+0x10dff54
ZERO_INIT = 0x1a40
ZERO_INIT_SHA = '11db9b6ff0e668c81cff002ab076c0276dbda07a308ce921d927da8241de977b'
ZERO_INIT_FIELDS = (0, 4, 8, 12, 16)
BUFFER_INIT = 0x1a00
BUFFER_INIT_SHA = '1a97bec870e1dd6c9d47a447460f98d4a3e81cddf43f5a6fe790dd2bc6b31277'
ZERO_INITS = (ZERO_INIT, BUFFER_INIT)


def zero_span(rva):
    require(type(rva) is int and rva in ZERO_INITS)
    return 16 if rva == BUFFER_INIT else 20
SIZE_QUERY = 0x102d0
SIZE_QUERY_SHA = '3b73a12d19ef68dd2eb2de9a356093ad1d19307997a1d626133079d9f153e738'
SIZE_QUERY_VALUE = 1912
DESCRIPTOR = 0x10960
DESCRIPTOR_SHA = '662aed12ac9fa33ff2c98223a36bcc23f220c78827f4f5857a589a7304857038'
DESCRIPTOR_MODES = ('valid', 'wrong-result', 'wrong-cleanup')
CLASSIFIER = 0x10700
CLASSIFIER_SHA = 'ce7846a4ab5f552170393d81c4ae9e414f65b2d4d2f118f3de3330ca8436a654'
CLASSIFIER_PATH = (0x10700, 0x10702, 0x10704, 0x10709)
MODULE_COMPARE = 0xfcb0
MODULE_COMPARE_SHA = 'e421372813a3b58444c5ab2d43a0d893da6b0674e934ae72a77abd4eeee9aa52'


def comparison_pair(n):
    require(type(n) is int and 0 <= n < 64)
    corpus = (b'', b'a', b'Z', b'Az09', b'@[`{', b'\x80\xff', b'kernel32.dll', b'abc')
    left = corpus[n % 8]
    right = (left, left.swapcase(), left+b'x', b'x'+left)[n // 16]
    return left, right


def comparison_equal(left, right):
    # Independent value contract only; volatile registers come from x86.
    fold = lambda s: bytes(b-32 if 97 <= b <= 122 else b for b in s)
    return int(fold(left) == fold(right))


def comparison_contract(regs, pages, result, n):
    left, right = comparison_pair(n)
    require(result['regs'][0] == comparison_equal(left, right))
    for r in ('ebx', 'ebp', 'esi', 'edi'):
        require(result['regs'][REGS.index(r)] == regs[r])
    require(result['regs'][REGS.index('esp')] == regs['esp']+4)
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<I', after[DATA_PAGES[0]], regs['esp']-DATA_PAGES[0]-4, regs['esi'])
    require(result['pages'] == b''.join(after[p] for p in PAGES).hex())


def modes(rva):
    unit(rva)
    return DESCRIPTOR_MODES if rva in (*ZERO_INITS, SIZE_QUERY, DESCRIPTOR, CLASSIFIER, MODULE_COMPARE, ALLOCATOR_POLICY, OPENER_MEMBER) else MODES

FUNCTION_SHA = '21a7ed37d568ae1dbb045d45056f85ba66e5c3d5fe3a93c6547a4f9dce675806'
MODES = ('valid', 'wrong-slot', 'wrong-cleanup')
ASSOCIATION = 0x1030
STATUS_SETTER = 0x1140
STATUS_SETTER_SHA = '563422a3fe5ee46867a7a1bcf532e922889aa608ed455bb1cd81ee3a0bf2f32e'
PAIRED = 0x10c0
PAIRED_SHA = 'a3d4b616b5258f5ebd03c00b4a88f9a39725dacca3a27036c7232f640306eafc'
DUAL_EFFECT = 0x10e0
DUAL_EFFECT_SHA = '10f2d0d40bc418b6f2354b39bcb054612b2b4c9107496b0eecbcd54fa813c0a9'
ASSOCIATION_SHA = '231746029a42200df643885947a694fb180993660e29930d0908b697175c7571'
# Explicit pinned unit inventory; never accept arbitrary addresses/slots.
SETTERS = {
    0x1090: (0x30, FUNCTION_SHA),
    0x10a0: (0x34, '0d76afd585163ef7e1d5760e5ff6e8f65478773c699e66ea9aabd465bd607e42'),
    0x10b0: (0x38, '6e19f815285b70dd51971fcc440bd8aa20e77e78b69a4dc83dc51b24111f1eb7'),
    0x1100: (0x50, '534a2964e60c431dafa54d368fde485e40f4adb51f29f39db483694f96c26bb4'),
    0x1110: (0x5c, '931bcb30475520ea139a640163e59067a9b24ee7361dfbda6d01b985081f79f9'),
    0x1120: (0x54, '312384e1ba5f27dd3207c566c290f282d9a247db48381283308c0cb7fea3ef50'),
    0x1130: (0x6c, 'ed0bc461441416b0bbea753b89278e9c7d8733af0510a0e0aa8bb0f880d39437'),
}


def setter(rva):
    require(type(rva) is int and rva in SETTERS)
    return SETTERS[rva]


def unit(rva):
    if type(rva) is int and rva == OPENER_MEMBER:
        return None, OPENER_MEMBER_SHA, 25, 5, ((0, 25),)
    if type(rva) is int and rva == ALLOCATOR_POLICY:
        return None, ALLOCATOR_POLICY_SHA, 7, 3, ((0, 7),)
    if type(rva) is int and rva == BUFFER_INIT:
        return None, BUFFER_INIT_SHA, 14, 6, ((0, 14),)
    if type(rva) is int and rva == ZERO_INIT:
        return None, ZERO_INIT_SHA, 17, 7, ((0, 17),)
    if type(rva) is int and rva == SIZE_QUERY:
        return None, SIZE_QUERY_SHA, 6, 2, ((0, 6),)
    if type(rva) is int and rva == MODULE_COMPARE:
        return None, MODULE_COMPARE_SHA, 51, 26, ((0,3),(3,13),(13,17),(17,19),(19,24),(24,29),(29,32),(32,36),(36,40),(40,47),(47,51))
    if type(rva) is int and rva == CLASSIFIER:
        return None, CLASSIFIER_SHA, 49, 21, ((0, 4), (4, 10), (10, 16), (16, 34), (34, 40), (40, 45), (45, 49))
    if type(rva) is int and rva == DESCRIPTOR:
        return None, DESCRIPTOR_SHA, 6, 2, ((0, 6),)
    if type(rva) is int and rva == STATUS_SETTER:
        return 0x208, STATUS_SETTER_SHA, 20, 5, ((0, 20),)
    if type(rva) is int and rva == PAIRED:
        return 0x3c, PAIRED_SHA, 19, 6, ((0, 19),)
    if type(rva) is int and rva == DUAL_EFFECT:
        return 0x44, DUAL_EFFECT_SHA, 22, 5, ((0, 22),)
    if type(rva) is int and rva == ASSOCIATION:
        return 0, ASSOCIATION_SHA, 28, 11, ((0, 11), (11, 21), (21, 28))
    slot, sha = setter(rva)
    return slot, sha, SIZE, 4, ((0, SIZE),)


def body_name(rva):
    unit(rva)
    if rva == OPENER_MEMBER:
        return 'opener_member_122F0'
    kind = ('allocator_policy' if rva == ALLOCATOR_POLICY else 'zero_init' if rva in ZERO_INITS else 'size_query' if rva == SIZE_QUERY else 'module_compare' if rva == MODULE_COMPARE else 'classifier' if rva == CLASSIFIER else 'descriptor' if rva == DESCRIPTOR else
            'association' if rva == ASSOCIATION else 'setter')
    return f'initialization_{kind}_{rva:04X}'


def state(n, rva=RVA):
    slot, _, _, _, _ = unit(rva)
    require(type(n) is int and 0 <= n < 64)
    rng = random.Random((rva << 8)+n)
    pages = {p:bytearray(rng.randbytes(4096)) for p in PAGES}
    regs = {r:rng.getrandbits(32) for r in REGS}
    regs['esp'] = DATA_PAGES[0]+(0x800 if n % 2 else 0xc00)
    # The +0x208 status setter needs its complete object inside one page.
    high = 0xc00 if rva == STATUS_SETTER else 0xe00
    obj = DATA_PAGES[1]+(0x80 if n % 2 else high)
    edges = (0, 1, 0xffffffff, 0x80000000, BASE+0x1ab979, 0xaaaaaaaa, 0x55555555, 0x7fffffff)
    value = edges[n % 8] if n < 32 else rng.getrandbits(32)
    struct.pack_into('<III', pages[DATA_PAGES[0]], regs['esp']-DATA_PAGES[0], RETURN, obj, value)
    if rva == OPENER_MEMBER:
        obj = DATA_PAGES[1]+(0, 128, 1024, 4096-16)[n % 4]
        struct.pack_into('<I', pages[DATA_PAGES[0]], regs['esp']-DATA_PAGES[0]+4, obj)
        # Poison all members: +4 must survive, unlike the other three words.
        struct.pack_into('<4I', pages[DATA_PAGES[1]], obj-DATA_PAGES[1],
                         OPENER_MEMBER_TABLE ^ 0xffffffff, 1+n, 0xffffffff, 0)
        return regs, pages
    if rva == ALLOCATOR_POLICY:
        # Explicit input data, not an inferred process-global initialization.
        struct.pack_into('<I', pages[DATA_PAGES[3]],
                         ALLOCATOR_POLICY_GLOBAL-DATA_PAGES[3], value)
        return regs, pages
    if rva in ZERO_INITS:
        span = zero_span(rva)
        regs['eax'] = DATA_PAGES[1]+(0, 0x80, 0xe00, 4096-span)[n % 4]
        for offset in range(0, span, 4):
            struct.pack_into('<I', pages[DATA_PAGES[1]], regs['eax']-DATA_PAGES[1]+offset,
                             edges[(n+offset//4) % 8] if n < 32 else rng.getrandbits(32))
        return regs, pages
    if rva == MODULE_COMPARE:
        left, right = comparison_pair(n)
        regs['eax'], regs['edx'] = DATA_PAGES[1]+128, DATA_PAGES[2]+128
        for page, data in zip(DATA_PAGES[1:3], (left, right)):
            pages[page][128:129+len(data)] = data+b'\0'
        return regs, pages
    if rva in (SIZE_QUERY, DESCRIPTOR, CLASSIFIER):
        # No receiver or arguments are consumed on these tested paths.
        if rva == CLASSIFIER:
            regs['edi'] = 0  # Proven opener context; scanning path is out of scope.
        return regs, pages
    # Force an observable write even for zero and repeated edge inputs.
    struct.pack_into('<I', pages[DATA_PAGES[1]], obj-DATA_PAGES[1]+slot, value ^ 0xffffffff)
    if rva == PAIRED:
        # Independent callback arguments: equal and unequal edge/random pairs.
        second = value if n % 4 == 0 else (edges[n//4] if n < 32 else rng.getrandbits(32))
        if n % 4 != 0 and second == value:
            second ^= 0xffffffff
        struct.pack_into('<I', pages[DATA_PAGES[0]], regs['esp']-DATA_PAGES[0]+12, second)
        struct.pack_into('<I', pages[DATA_PAGES[1]], obj-DATA_PAGES[1]+0x40, second ^ 0xffffffff)
    if rva == DUAL_EFFECT:
        # Include unchanged-one as well as observable zero/edge/random writes.
        initial = (0, 1, 0xffffffff, 2)[n % 4] if n < 32 else rng.getrandbits(32)
        struct.pack_into('<I', pages[DATA_PAGES[1]], obj-DATA_PAGES[1]+0x110, initial)
    if rva == ASSOCIATION:
        # Equal contexts include creator-like zero/zero; unequal contexts must
        # retain +4. Both outcomes are observable even for zero input values.
        old = 0 if n < 8 else rng.getrandbits(32)
        context = old if n % 4 < 2 else old ^ 0xffffffff
        struct.pack_into('<II', pages[DATA_PAGES[1]], obj-DATA_PAGES[1], old, context)
    return regs, pages


def oracle(regs, pages, rva=RVA):
    """Independent final contract; pointer values are data, never invoked."""
    slot, _, _, _, _ = unit(rva)
    if rva == OPENER_MEMBER:
        require(set(regs) == set(REGS) and set(pages) == set(PAGES))
        require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
        require(all(len(pages[p]) == 4096 for p in PAGES))
        sp = regs['esp']-DATA_PAGES[0]
        require(0 <= sp <= 4088 and sp % 4 == 0)
        ret, obj = struct.unpack_from('<II', pages[DATA_PAGES[0]], sp)
        off = obj-DATA_PAGES[1]
        require(ret == RETURN and 0 <= off <= 4096-16 and off % 4 == 0)
        after = {p:bytearray(b) for p,b in pages.items()}
        struct.pack_into('<I', after[DATA_PAGES[1]], off, OPENER_MEMBER_TABLE)
        struct.pack_into('<II', after[DATA_PAGES[1]], off+8, 0, 1)
        out = dict(regs, eax=obj, esp=regs['esp']+4)
        return dict(regs=[out[r] for r in REGS], pages=b''.join(after[p] for p in PAGES).hex())
    if rva in ZERO_INITS:
        span = zero_span(rva)
        require(set(regs) == set(REGS) and set(pages) == set(PAGES))
        require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
        require(all(len(pages[p]) == 4096 for p in PAGES))
        sp, obj = regs['esp']-DATA_PAGES[0], regs['eax']-DATA_PAGES[1]
        require(0 <= sp <= 4092 and sp % 4 == 0)
        require(0 <= obj <= 4096-span and obj % 4 == 0)
        require(struct.unpack_from('<I', pages[DATA_PAGES[0]], sp)[0] == RETURN)
        after = {p:bytearray(b) for p,b in pages.items()}
        after[DATA_PAGES[1]][obj:obj+span] = bytes(span)
        out = dict(regs, ecx=0, esp=regs['esp']+4)
        return dict(regs=[out[r] for r in REGS], pages=b''.join(after[p] for p in PAGES).hex())
    if rva in (SIZE_QUERY, ALLOCATOR_POLICY):
        require(set(regs) == set(REGS) and set(pages) == set(PAGES))
        require(all(type(v) is int and 0 <= v <= 0xffffffff for v in regs.values()))
        require(all(len(pages[p]) == 4096 for p in PAGES))
        sp = regs['esp']-DATA_PAGES[0]
        require(0 <= sp <= 4092 and sp % 4 == 0)
        require(struct.unpack_from('<I', pages[DATA_PAGES[0]], sp)[0] == RETURN)
        value = (SIZE_QUERY_VALUE if rva == SIZE_QUERY else
                 struct.unpack_from('<I', pages[DATA_PAGES[3]],
                                    ALLOCATOR_POLICY_GLOBAL-DATA_PAGES[3])[0])
        out = dict(regs, eax=value, esp=regs['esp']+4)
        return dict(regs=[out[r] for r in REGS], pages=b''.join(pages[p] for p in PAGES).hex())
    if rva in (DESCRIPTOR, CLASSIFIER):
        if rva == CLASSIFIER:
            require(regs['edi'] == 0)
        out = dict(regs, eax=6 if rva == CLASSIFIER else BASE+0xe17d90, esp=regs['esp']+4)
        return dict(regs=[out[r] for r in REGS], pages=b''.join(pages[p] for p in PAGES).hex())
    sp = regs['esp']-DATA_PAGES[0]
    ret, obj, value = struct.unpack_from('<III', pages[DATA_PAGES[0]], sp)
    require(ret == RETURN)
    after = {p:bytearray(b) for p,b in pages.items()}
    struct.pack_into('<I', after[DATA_PAGES[1]], obj-DATA_PAGES[1]+slot, value)
    out = dict(regs, eax=1 if rva == STATUS_SETTER else value,
               ecx=obj, esp=regs['esp']+4)
    if rva == PAIRED:
        second = struct.unpack_from('<I', pages[DATA_PAGES[0]], sp+12)[0]
        struct.pack_into('<I', after[DATA_PAGES[1]], obj-DATA_PAGES[1]+0x40, second)
        out = dict(regs, eax=obj, ecx=value, edx=second, esp=regs['esp']+4)
    if rva == DUAL_EFFECT:
        struct.pack_into('<I', after[DATA_PAGES[1]], obj-DATA_PAGES[1]+0x110, 1)
        out = dict(regs, eax=obj, ecx=value, esp=regs['esp']+4)
    if rva == ASSOCIATION:
        old, context = struct.unpack_from('<II', pages[DATA_PAGES[1]], obj-DATA_PAGES[1])
        out = dict(regs, eax=obj, esp=regs['esp']+4)
        if old == context:
            struct.pack_into('<I', after[DATA_PAGES[1]], obj-DATA_PAGES[1]+4, value)
            out['ecx'] = value
        else:
            out.update(ecx=context, edx=value)
    return dict(regs=[out[r] for r in REGS], pages=b''.join(after[p] for p in PAGES).hex())


def check_index(envelope, rva=RVA):
    _, _, size, count, _ = unit(rva)
    context = index_context(envelope, rva)
    f = envelope['result']['function']
    require(f['resolution'] == 'function-at' and int(f['entryRva'],16) == rva)
    d = f['disassembly']
    require(d['instructionCount'] == count and d['extentBytes'] == size and
            int(d['extentEndVa'],16) == BASE+rva+size-1)
    require(len(d['items']) == count and int(d['items'][0]['va'],16) == BASE+rva)
    context['reliable_boundaries'] = True
    return context


def assemble(body, rva=RVA):
    unit(rva)
    require(type(body) is str and body.strip())
    text = TEMPLATE.read_text()
    replacements = {
        '@PROTOTYPES@': 'static void initialization_setter_1090(void);',
        '@SELECT@': 'case 0xA0001090u: initialization_setter_1090();break;',
        '@ADAPTERS@': 'static void adapter_1090(uint32_t* s) {select_body(0xA0001090u,s);}',
        '@CALLBACKS@': 'case 0xA0001090u:callback=adapter_1090;break;',
        '@DIRECT_RETURNS@': '', '@INDIRECT_RETURNS@': '', '@BODY@': body,
        'cache_invoke(0xA01ABD40u,in,adapter_1ABD40)':
            'cache_invoke(0xA0001090u,in,adapter_1090)',
    }
    for old,new in replacements.items():
        require(text.count(old) == 1)
        # Adapt authored transport only, never the lifted body.
        if old != '@BODY@':
            new = new.replace('0xA0001090u', f'0x{BASE+rva:08X}u')
            new = new.replace('1090', f'{rva:04X}')
            new = new.replace(f'initialization_setter_{rva:04X}', body_name(rva))
        text = text.replace(old,new)
    if rva == CLASSIFIER:
        # Whole-body lift retains the out-of-contract call. Declare its address
        # only: direct_return/invoke still reject; no external callee is bound.
        marker = '#define RECOMP_GENERATED_CODE'
        require(text.count(marker) == 1)
        text = text.replace(marker, 'static constexpr unsigned address_sub_A000FCB0=0xA000FCB0u;\n'+marker)
    require(text.count(body) == 1)
    return text


def bridge_source(text, mode, rva=RVA):
    unit(rva)
    require(mode in modes(rva))
    old = 'constexpr std::array<uint32_t,8> targets{0xA01ABD40u,0xA0001240u,0xA0001250u,0xA0001270u,0xA0001290u,0xA00012D0u,0xA000FCF0u,0xA0009550u};'
    require(text.count(old) == 1)
    text = text.replace(old, 'constexpr std::array<uint32_t,1> targets{'+f'0x{BASE+rva:08X}u'+'};')
    if mode == 'valid':
        return text
    if mode == 'wrong-slot':
        old = '    check(a,size,true);'
        new = old+'\n    if(size==4) a+=4;'
    else:
        old = '    current(s.data());'
        new = old+('\n    s[0]^=4;' if mode == 'wrong-result' else '\n    s[7]+=8;')
    require(text.count(old) == 1)
    return text.replace(old,new)


def assess(text, expected, mode):
    require(mode in (*MODES, 'wrong-result'))
    # Invalid hex is malformed transport, never a behavioral kill.
    rows = [json.loads(line) for line in text.splitlines()]
    for row in rows:
        require(type(row) is dict and type(row.get('pages')) is str)
        require(len(row['pages']) == len(PAGES)*8192 and
                all(c in '0123456789abcdef' for c in row['pages']))
    # Reuse strict six-page/64-row parser and behavioral-kill policy.
    return assess_text(text, expected, {'valid':'valid', 'wrong-slot':'counter-destinations',
                                      'wrong-cleanup':'return-frame', 'wrong-result':'counter-destinations'}[mode])


def run(output, index, rva=RVA):
    slot, function_sha, size, count, blocks = unit(rva)
    output = private_output(output)
    schema = ('ts2-opener-member-native/1' if rva == OPENER_MEMBER else
              'ts2-allocator-policy-native/1' if rva == ALLOCATOR_POLICY else
              'ts2-buffer-zero-init-native/1' if rva == BUFFER_INIT else
              'ts2-opener-zero-init-native/1' if rva == ZERO_INIT else
              'ts2-service-size-query-native/1' if rva == SIZE_QUERY else
              'ts2-module-comparison-native/1' if rva == MODULE_COMPARE else
              'ts2-initialization-classifier-zero-native/1' if rva == CLASSIFIER else
              'ts2-initialization-descriptor-native/1' if rva == DESCRIPTOR else
              'ts2-initialization-association-native/1' if rva == ASSOCIATION else 'ts2-initialization-setter-native/1')
    row = dict(schema=schema, success=False, rva=hex(rva), slot=None if slot is None else hex(slot),
        size=size, selected=1, attempted=False, lifted=False, image_sha256=IMAGE_SHA,
        pcrecomp_revision=REVISION, harness_sha256=digest(Path(__file__)),
        template_sha256=digest(TEMPLATE), bridge_sha256=digest(BRIDGE),
        invocation=[sys.executable,*sys.argv], commands=[], timings={}, runs={},
        arm64_executed=False, android_executed=False, stub=False,
        compared=['eight final GPRs including ESP', 'six complete 4096-byte pages'],
        limits=['64 synthetic aligned valid objects; not producer/lifetime proof',
                'callback values stored as data only; not invoked',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no production binding or opener'])
    if rva in (*ZERO_INITS, SIZE_QUERY, ALLOCATOR_POLICY, OPENER_MEMBER):
        row.update(whole_function_verified=False, dependencies_newly_resolved=0)
    stage = 'preflight'
    def command(name, argv, data=None):
        rec = dict(name=name, argv=[str(a) for a in argv]); row['commands'].append(rec)
        start = time.monotonic()
        with (output/(name+'.stdout')).open('xb') as out, (output/(name+'.stderr')).open('xb') as err:
            child = subprocess.run(rec['argv'], input=data, stdout=out, stderr=err, cwd=ROOT, timeout=180)
        rec.update(exit_code=child.returncode, seconds=time.monotonic()-start)
        require(child.returncode == 0)
    try:
        start = time.monotonic()
        image = ROOT/'work/interop-legacy-002/analysis-image.bin'
        require(digest(image) == IMAGE_SHA)
        row['index'] = check_index(json.loads(index.read_text()), rva)
        row['index_sha256'] = digest(index)
        upstream = ROOT/'work/interop-legacy-002/pcrecomp'
        pristine = ROOT/'work/deps/pcrecomp/sp00nznet-pcrecomp-c0cbd3e'
        verify(pristine)
        locked = json.loads((ROOT/'config/dependencies.lock.json').read_text())['pcrecomp']['files']
        used = [n for n in locked if '/drm/' not in n]+['tools/lift/generate.py','tools/disasm/disasm32.py']
        require(all(digest(upstream/n) == digest(pristine/n) for n in used))
        row['upstream_files'] = {n:digest(upstream/n) for n in used}
        import pefile
        pe = pefile.PE(data=image.read_bytes())
        require(pe.OPTIONAL_HEADER.ImageBase == BASE and pe.FILE_HEADER.Machine == 0x14c)
        code = pe.get_data(rva,size)
        import hashlib
        require(hashlib.sha256(code).hexdigest() == function_sha)
        row['function_sha256'] = function_sha
        sys.path.insert(0,str(upstream))
        from tools.lift.lift32 import Lifter
        from tools.lift.generate import LinearInstruction
        require(Path(sys.modules[Lifter.__module__].__file__).resolve() == (upstream/'tools/lift/lift32.py').resolve())
        row['timings']['preflight'] = time.monotonic()-start
        stage = 'fresh-lift'; start = time.monotonic(); row['attempted'] = True
        if rva in (CLASSIFIER, MODULE_COMPARE):
            from measure_startup import decode_flow, dependencies
            function, flow_nodes, _, _ = decode_flow(code,BASE+rva,LinearInstruction)
            deps = dependencies(flow_nodes, pe)
            require(deps['direct_calls'] == (['0xfcb0'] if rva == CLASSIFIER else []) and deps['indirect_calls'] == 0)
            require(not deps['absolute_memory_va'] and not deps['segmented_memory_operands'])
            actual_blocks = tuple((a-BASE-rva, b.instructions[-1].address+b.instructions[-1].size-BASE-rva)
                                  for a,b in sorted(function.blocks.items()))
            require(actual_blocks == blocks)
            row['dependencies'] = deps
            if rva == CLASSIFIER:
                row['path_contract'] = dict(edi=0, external_target_executed=False,
                                            whole_function_verified=False)
        else:
            function = decode_function(code,blocks,BASE+rva,LinearInstruction)
        function.name = body_name(rva)
        row['lift_invocation'] = dict(api='Lifter(precise_carry=True).lift_function',
            address=hex(BASE+rva), blocks=blocks, name=function.name)
        body = Lifter(precise_carry=True).lift_function(function)
        require(body.strip() and 'unimplemented' not in body.lower() and 'unhandled' not in body.lower())
        (output/'lifted.c').write_text(body); row['lifted'] = True
        row['timings']['translation'] = time.monotonic()-start
        if rva == MODULE_COMPARE:
            row['limits'] = ['64 bounded NUL-terminated synthetic byte-string pairs; not caller/table semantics',
                'Independent oracle checks equality, nonvolatiles, ESP and all pages; volatile GPRs use x86 oracle only',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no production binding or whole classifier']
        if rva in ZERO_INITS:
            row['dependencies'] = dict(direct_calls=[], indirect_calls=0)
            row['limits'] = ['64 synthetic aligned EAX receiver spans; includes exact page-end span',
                'Independent final-state oracle; no store-order/transient-write claim',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no allocator, whole opener or production binding']
        if rva == ALLOCATOR_POLICY:
            row['dependencies'] = dict(direct_calls=[], indirect_calls=0,
                absolute_memory_va=[hex(ALLOCATOR_POLICY_GLOBAL)])
            row['limits'] = ['64 synthetic global words; not process initialization or lifetime proof',
                'Independent full final-state oracle; getter only, not malloc/HeapAlloc or retry semantics',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no production binding or whole opener']
        if rva == SIZE_QUERY:
            row['dependencies'] = dict(direct_calls=[], indirect_calls=0)
            row['limits'] = ['64 randomized guest states; two aligned stack positions',
                'Constant return only; size/allocation role is a HYPOTHESIS, not heap semantics',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no 1460 nonnull path or production binding']
        if rva == OPENER_MEMBER:
            row['dependencies'] = dict(direct_calls=[], indirect_calls=0)
            row['limits'] = ['64 aligned stack-argument receivers, including exact page end; member+4 preserved',
                'Table address stored as data only; no table dereference, callback or object lifetime proof',
                'Independent eight-GPR/six-page final-state oracle; no flags/FP/PC/transient-store comparison',
                'Diagnostic GuestMemory/exact-VA bridge; not composed 3A50/1AB665 or Android']
        if rva == DESCRIPTOR:
            row['limits'] = ['64 randomized guest states; descriptor address returned, never dereferenced',
                'no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no production binding or opener']
        if rva == CLASSIFIER:
            row['limits'] = ['EDI-zero opener path only; nonzero scanning/FCB0 branch unverified',
                'whole generated body retained; only exact entry registered, external calls reject',
                '64 randomized guest states; no flags/FP/PC/native transient-write comparison',
                'diagnostic GuestMemory/exact-VA bridge; no production binding or opener']
        stage = 'original-reference'; start = time.monotonic()
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32
        md = Cs(CS_ARCH_X86,CS_MODE_32); md.detail = True
        nodes = {i.address:i for i in md.disasm(code,BASE+rva)}
        indexed = json.loads(index.read_text())['result']['function']['disassembly']['items']
        require(len(nodes) == count and [int(i['va'],16) for i in indexed] == list(nodes))
        code_page = bytearray(4096); code_page[rva%4096:rva%4096+size] = code
        expected, inputs, visited = [], bytearray(), set()
        paths = {}
        for n in range(64):
            regs,pages = state(n, rva)
            result,seen = reference(nodes,{BASE+(rva//4096)*4096:code_page},BASE+rva,regs,pages,
                                    budget=512 if rva == MODULE_COMPARE else 16)
            if rva == MODULE_COMPARE:
                comparison_contract(regs,pages,result,n)
            else:
                require(result == oracle(regs,pages,rva))
            if rva == CLASSIFIER:
                require(seen == {BASE+a for a in CLASSIFIER_PATH})
            expected.append(dict(case=n,**result)); visited.update(seen)
            path = tuple(sorted(seen))
            paths[path] = paths.get(path, 0)+1
            inputs.extend(struct.pack('<8I',*(regs[r] for r in REGS)))
            inputs.extend(b''.join(pages[p] for p in PAGES))
        require(visited == ({BASE+a for a in CLASSIFIER_PATH} if rva == CLASSIFIER else set(nodes)))
        row['coverage'] = dict(visited=len(visited),total=len(nodes),
                               path_case_counts=sorted(paths.values()))
        if rva == ASSOCIATION:
            require(sorted(paths.values()) == [32, 32])
        row['x86_oracle_matches'] = 64
        if rva == MODULE_COMPARE:
            row['independent_oracle_components'] = ['equality EAX', 'EBX/EBP/ESI/EDI/ESP', 'six full pages']
            row['differential_oracle_components'] = ['eight final GPRs', 'six full pages']
        row['timings']['x86_reference_and_oracle'] = time.monotonic()-start
        (output/'reference.json').write_text(json.dumps(expected))
        (output/'input.bin').write_bytes(inputs)
        transport = output/'transport.cpp'; transport.write_text(assemble(body,rva))
        for mode in modes(rva):
            bridge = output/(mode+'.cpp'); bridge.write_text(bridge_source(BRIDGE.read_text(),mode,rva))
            for isa in ('host','arm64'):
                stage = mode+'-'+isa; binary = output/stage
                command(stage+'-compile',['zig-cxx',*([] if isa=='host' else ['-target','aarch64-linux-musl','-static']),
                    '-std=c++20','-D_POSIX_C_SOURCE=200809L','-O0','-I'+str(upstream/'runtime/recomp32'),
                    '-I'+str(ROOT/'native/include'),transport,bridge,ROOT/'native/src/guest_memory.cpp',
                    ROOT/'native/src/guest_dispatch.cpp','-lm','-o',binary])
                h = binary.read_bytes()[:20]
                require(h[:6] == b'\x7fELF\x02\x01' and int.from_bytes(h[18:20],'little') == (62 if isa=='host' else 183))
                command(stage+'-execute',[binary] if isa=='host' else [ROOT/'scripts/campaign/arm64-run.sh',binary],bytes(inputs))
                row['runs'][stage] = dict(compiled=True,**assess((output/(stage+'-execute.stdout')).read_text(),expected,mode))
                if isa == 'arm64': row['arm64_executed'] = True
        row['artifact_sha256'] = {n:digest(output/n) for n in ('lifted.c','transport.cpp','reference.json','input.bin')}
        require(digest(image) == IMAGE_SHA)
        require(all(digest(upstream/n) == sha for n,sha in row['upstream_files'].items()))
        require(digest(Path(__file__)) == row['harness_sha256'])
        require(digest(TEMPLATE) == row['template_sha256'] and digest(BRIDGE) == row['bridge_sha256'])
        if rva in (*ZERO_INITS, SIZE_QUERY, ALLOCATOR_POLICY, OPENER_MEMBER):
            row.update(whole_function_verified=True, dependencies_newly_resolved=1)
        if rva == OPENER_MEMBER:
            row['original_behaviour_newly_executable'] = [hex(OPENER_MEMBER)]
        row['success'] = True
    except Exception as exc:
        row.update(failed_stage=stage,error_type=type(exc).__name__)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(row,indent=2)+'\n')
    return row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--index',type=Path,required=True)
    p.add_argument('--rva',type=lambda s:int(s,16),choices=(*SETTERS, ASSOCIATION, DUAL_EFFECT, PAIRED, STATUS_SETTER, *ZERO_INITS, SIZE_QUERY, DESCRIPTOR, CLASSIFIER, MODULE_COMPARE, ALLOCATOR_POLICY, OPENER_MEMBER),default=RVA)
    a = p.parse_args()
    try: run(a.output,a.index,a.rva)
    except Exception: p.exit(1,'Initialization unit failed; inspect private receipt.\n')
    print(f'{a.rva:04X}: 64/64 host and Linux/AArch64; two controls rejected per ISA. NOT Android.')


if __name__ == '__main__': main()
