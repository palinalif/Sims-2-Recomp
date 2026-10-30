#!/usr/bin/env python3
"""Selftest for build_windows_rtti_index.py.

Proves three things without touching the real image:
  1. a synthetic PE carrying hand-built MSVC RTTI recovers exactly the planted
     class (name, COL, vtable VA, methods, base list);
  2. random garbage bytes yield ZERO type descriptors / COLs / vtables / classes;
  3. the Ghidra mapping gate hard-fails on an image whose functions.jsonl VA
     identity is wrong (the gate cannot be silently bypassed).
"""
import json
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_windows_rtti_index as B  # noqa: E402


def synth_pe():
    """Minimal i386 PE: .text at file 0x400 (code), .rdata at file 0x800.

    Planted: cWidget : cBase, vtable with 3 methods (one behind an E9 thunk),
    secondary-COL (offset!=0) for a second subobject.
    """
    BASE = 0x10000000
    TEXT_RVA, TEXT_OFF = 0x1000, 0x400
    RD_RVA, RD_OFF = 0x2000, 0x800
    img = bytearray(0xC00)

    def put(buf, off, *words):
        struct.pack_into("<%dI" % len(words), buf, off, *words)

    # headers
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, 0x40)              # e_lfanew
    img[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<H", img, 0x44, 0x14C)             # i386
    struct.pack_into("<H", img, 0x46, 2)                 # nsec
    struct.pack_into("<H", img, 0x54, 0xE0)              # SizeOfOptionalHeader
    struct.pack_into("<H", img, 0x58, 0x0102)            # magic 32-bit
    struct.pack_into("<I", img, 0x58 + 28, BASE)         # ImageBase
    for i, (name, rva, roff, rsz, chars) in enumerate([
            (b".text\x00\x00\x00", TEXT_RVA, TEXT_OFF, 0x400, 0x60000020),
            (b".rdata", RD_RVA, RD_OFF, 0x400, 0x40000040)]):
        so = 0x58 + 0xE0 + i * 40
        img[so:so + 8] = name
        struct.pack_into("<I", img, so + 8, 0x1000)      # VirtualSize
        struct.pack_into("<I", img, so + 12, rva)
        struct.pack_into("<I", img, so + 16, rsz)        # SizeOfRawData
        struct.pack_into("<I", img, so + 20, roff)
        struct.pack_into("<I", img, so + 36, chars)

    rd = bytearray(0x400)
    RD_BASE = BASE + RD_RVA
    # TDs: vfptr, spare, name
    def td(off, name):
        put(rd, off, 0, 0)
        rd[off + 8:off + 8 + len(name)] = name + b"\x00"
        return RD_BASE + off
    td_w = td(0x00, b".?AVcWidget@@")
    td_b = td(0x40, b".?AVcBase@@")
    # CHD for cWidget: sig, attrs, numBases=2, pBaseArray; array of BCD ptrs
    chd_w = RD_BASE + 0x80
    bca = RD_BASE + 0xA0
    bcd1, bcd2 = RD_BASE + 0xC0, RD_BASE + 0xD0
    put(rd, 0x80, 0, 0, 2, bca)
    put(rd, 0xA0, bcd1, bcd2)
    put(rd, 0xC0, td_w, 0, 0, 0)          # self entry (preorder first)
    put(rd, 0xD0, td_b, 0, 0, 0)
    # CHD for cBase (single)
    chd_b = RD_BASE + 0xE0
    bca_b = RD_BASE + 0xF8
    bcd_b = RD_BASE + 0x100
    put(rd, 0xE0, 0, 0, 1, bca_b)
    put(rd, 0xF8, bcd_b)
    put(rd, 0x100, td_b, 0, 0, 0)
    # primary COL (offset 0) and secondary COL (offset 4)
    col_w = RD_BASE + 0x120
    col_w2 = RD_BASE + 0x134
    put(rd, 0x120, 0, 0, 0, td_w, chd_w)
    put(rd, 0x134, 0, 4, 0, td_w, chd_w)
    # vtables: [ptr to COL][methods...]
    TEXT_BASE = BASE + TEXT_RVA
    m0, m1, m2 = TEXT_BASE + 0x10, TEXT_BASE + 0x40, TEXT_BASE + 0x80
    stub = TEXT_BASE + 0x200                       # E9 jmp stub -> m2
    vt = RD_BASE + 0x150
    put(rd, 0x150, col_w, m0, m1, stub, 0)
    vt2 = RD_BASE + 0x170
    put(rd, 0x170, col_w2, m2, 0)
    img[RD_OFF:RD_OFF + len(rd)] = rd
    # method bodies + stub
    img[TEXT_OFF + 0x10] = 0x55                    # push ebp
    img[TEXT_OFF + 0x40] = 0x53                    # push ebx
    img[TEXT_OFF + 0x80] = 0x56                    # push esi
    img[TEXT_OFF + 0x200:TEXT_OFF + 0x205] = \
        b"\xE9" + struct.pack("<i", m2 - (stub + 5))
    return bytes(img), {"vt": vt, "vt2": vt2, "col": col_w,
                        "methods": [m0, m1, stub, m2]}


def test_synth():
    data, exp = synth_pe()
    img = B.PeImage(data)
    idx, counts = B.build_index(img)
    assert counts["type_descriptors"] == 2, counts
    assert counts["cols"] == 2, counts
    assert "cWidget" in idx, sorted(idx)
    w = idx["cWidget"]
    assert w["primary_vtable"] == "0x%08X" % (exp["vt"] + 4), w["primary_vtable"]
    assert w["primary_slot_count"] == 3, w["primary_slot_count"]
    exp_methods = ["0x%08X" % m for m in (exp["methods"][0], exp["methods"][1],
                                          exp["methods"][3])]  # stub followed
    assert w["primary_methods"] == exp_methods, w["primary_methods"]
    assert w["bases"] == ["cBase"], w["bases"]
    assert len(w["cols"]) == 2, w["cols"]           # primary + secondary
    raw_slot2 = w["vtables"][0]["methods"][2]
    assert raw_slot2 == "0x%08X" % exp["methods"][2], raw_slot2  # raw kept
    assert B.verify_index_bytes(img, idx) > 0
    print("  synth PE recovery OK")


def test_garbage():
    rnd = random.Random(0xC0FFEE)
    empties = 0
    header = synth_pe()[0][:0x200]   # valid headers+sectab so PeImage parses
    for trial in range(5):
        # valid section table, but every section body is random bytes
        blob = bytearray(header) + bytearray(b"\x00" * (0x400 - 0x200)) + \
            rnd.randbytes(0x1400)
        img = B.PeImage(bytes(blob))
        idx, counts = B.build_index(img)
        if not idx and counts["type_descriptors"] == 0 and counts["cols"] == 0 \
                and counts["vtables"] == 0:
            empties += 1
    assert empties == 5, empties
    print("  random garbage -> 0 classes OK (5/5 seeds)")


def test_gate_fails():
    data, _ = synth_pe()
    img = B.PeImage(data)
    fns = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "..", "work", "private", "mac-leads",
                       "_selftest_funcs.jsonl")
    good_va = 0x10001010
    with open(fns, "w") as f:      # wrong va/rva identity -> must raise
        f.write(json.dumps({"rva": "0x1010", "va": "0x90001010",
                            "name": "x", "pseudo": ""}) + "\n")
        f.write(json.dumps({"rva": "0x1010", "va": "0x10001010",
                            "name": "y", "pseudo": ""}) + "\n")
    try:
        B.verify_mapping(img, fns, verbose=False)
    except RuntimeError:
        print("  mapping gate rejects bad functions.jsonl OK")
    else:
        raise AssertionError("gate must fail on bad VA identity")
    # and passes on a correct one
    with open(fns, "w") as f:
        f.write(json.dumps({"rva": "0x1010", "va": "0x10001010",
                            "name": "y", "pseudo": ""}) + "\n")
    st = B.verify_mapping(img, fns, verbose=False)
    assert st["identity_mismatch"] == 0 and st["unmappable"] == 0
    assert img.d[img.raw(good_va)] == 0x55
    os.remove(fns)
    print("  mapping gate accepts correct functions.jsonl OK")


if __name__ == "__main__":
    test_synth()
    test_garbage()
    test_gate_fails()
    print("build_windows_rtti_index selftest OK")
