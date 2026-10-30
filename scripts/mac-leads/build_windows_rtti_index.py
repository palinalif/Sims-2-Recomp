#!/usr/bin/env python3
"""Windows-side MSVC RTTI + vtable recovery index for the pinned Sims 2 analysis
image, plus a cross-platform join against the Mac vtable-lead dataset.

Two modes:

  index  -- parse the recovered analysis image's MSVC 32-bit RTTI (TypeDescriptors,
         CompleteObjectLocators, ClassHierarchyDescriptors, vtables) and emit one
         JSONL record per class. Every VA emitted is cross-checked against the
         Ghidra function index (mapping gate, see verify_mapping). The mode exits
         non-zero if the gate fails; the gate is never relaxed to raise counts.

  join   -- join the emitted Windows index against the friend's Mac vtable leads
         (game-i386-vtables.json / method-candidates.tsv / recovered-labels-i386
         .tsv / game-i386-rtti.json) by portable simple class name and emit a
         per-class TSV with slot-layout agreement (slots-match / slots-shift /
         mac-only / windows-only). Mac addresses and slot numbers are treated as
         *name candidates only*, never as facts about Windows layout.

Structures (32-bit MSVC; all pointers absolute VAs — verified against this image,
and matching the layouts in work/interop-legacy-002/pcrecomp/tools/cpp/rtti.py):

  TypeDescriptor            { u32 vfptr; u32 spare; char name[]; }   # name at +8
  CompleteObjectLocator     { u32 sig; u32 offset; u32 cdOffset;
                              u32 pTD; u32 pCHD; }
  ClassHierarchyDescriptor  { u32 sig; u32 attrs; u32 numBaseClasses;
                              u32 pBaseClassArray; }
  BaseClassDescriptor       { u32 pTD; u32 numContainedBases; PMD where; u32 attrs; }

Vtables are found by the `vtable[-1] == &COL` property. MSVC's incremental linker
stores `jmp rel32` stubs in vtables; E9 stubs are followed one hop (raw slot value
is retained alongside the resolved entry).

NOTE ON ADDRESSING: the task brief's "Ghidra VA = 0xA0000000 + raw offset" is
true only for RVA, not for file offset — the file is an on-disk PE whose sections
are at their own file offsets. The verified mapping (gate-checked below) is
    Ghidra VA = PE ImageBase (0xA0000000) + RVA,
    RVA -> file offset via the PE section table (not identity).

Uses only struct/re/json/argparse (no pip installs).
"""
import argparse
import json
import os
import random
import re
import struct
import sys

TD_NAME = re.compile(rb"\.\?A[VU][A-Za-z0-9_@?$]{2,250}@@\x00")


# --------------------------------------------------------------------------
# PE-as-image view
# --------------------------------------------------------------------------
class PeImage:
    """Raw-bounded VA view over an on-disk 32-bit PE."""

    def __init__(self, data):
        self.d = data
        if data[:2] != b"MZ":
            raise ValueError("not an MZ image")
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e + 4] != b"PE\x00\x00":
            raise ValueError("no PE header")
        if struct.unpack_from("<H", data, e + 4)[0] != 0x14C:
            raise ValueError("not i386")
        opt = e + 24
        self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        nsec = struct.unpack_from("<H", data, e + 6)[0]
        sizeopt = struct.unpack_from("<H", data, e + 20)[0]
        self.secs = []          # (va, raw_off, raw_size, name)
        self.code = []          # (va_lo, va_hi)
        for i in range(nsec):
            so = opt + sizeopt + i * 40
            name = data[so:so + 8].rstrip(b"\x00").decode("latin1")
            rva = struct.unpack_from("<I", data, so + 12)[0]
            roff = struct.unpack_from("<I", data, so + 20)[0]
            rsz = struct.unpack_from("<I", data, so + 16)[0]
            chars = struct.unpack_from("<I", data, so + 36)[0]
            if rsz == 0:
                continue
            self.secs.append((self.image_base + rva, roff, rsz, name))
            if chars & 0x20000000:
                self.code.append((self.image_base + rva,
                                  self.image_base + rva + rsz))

    def raw(self, va):
        for v, r, rs, _ in self.secs:
            if v <= va < v + rs:
                return r + (va - v)
        return None

    def u32(self, va):
        r = self.raw(va)
        if r is None or r + 4 > len(self.d):
            return None
        return struct.unpack_from("<I", self.d, r)[0]

    def is_code(self, va):
        return any(lo <= va < hi for lo, hi in self.code)

    def follow_thunk(self, va):
        r = self.raw(va)
        if r is None or not self.is_code(va) or self.d[r] != 0xE9:
            return None
        t = (va + 5 + struct.unpack_from("<i", self.d, r + 1)[0]) & 0xFFFFFFFF
        return t if self.is_code(t) else None


# --------------------------------------------------------------------------
# RTTI recovery
# --------------------------------------------------------------------------
def demangle(name):
    """'.?AVcGZCOM@@' -> 'cGZCOM'. Templates stay decorated beyond the base name."""
    if name.startswith((".?AV", ".?AU")) and name.endswith("@@"):
        name = name[4:-2]
    if name.startswith("?$"):
        name = name[2:]
    return name


def simple_key(name):
    """Portable join key: first identifier segment, no mangling noise."""
    n = demangle(name)
    if n.startswith("?$"):
        n = n[2:]
    n = n.split("@")[0]
    return n


def type_descriptors(img):
    """{td_va: decorated_name}; the name field is 8 bytes into the TypeDescriptor."""
    out = {}
    for v, r, rs, _ in img.secs:
        lo, hi = 8, min(rs, len(img.d) - r)
        for m in TD_NAME.finditer(img.d[r + lo:r + hi]):
            out[v + lo + m.start() - 8] = m.group()[:-1].decode("latin1")
    return out


def locators(img, td):
    """{col_va: (td_name, subobj_offset, cd_offset, pchd_va)} (relaxed: any offset)."""
    out = {}
    for v, r, rs, _ in img.secs:
        limit = min(rs, len(img.d) - r)
        for off in range(0, max(0, limit - 19), 4):
            sig, sub, cd, ptd, pcd = struct.unpack_from("<5I", img.d, r + off)
            if sig != 0 or ptd not in td or img.raw(pcd) is None:
                continue
            if img.u32(pcd) != 0:          # CHD signature must be 0
                continue
            out[v + off] = (td[ptd], sub, cd, pcd)
    return out


def hierarchy(img, td, cols):
    """{td_name: [base td names]} in MSVC preorder, via CHD numBaseClasses/pBaseArray."""
    out = {}
    for _cva, (_nm, _sub, _cd, pcd) in cols.items():
        if _nm in out:
            continue
        n, pba = img.u32(pcd + 8), img.u32(pcd + 12)
        if not n or n >= 200 or pba is None or img.raw(pba) is None:
            continue
        bases = []
        ok = True
        for i in range(n):
            b = img.u32(pba + i * 4)
            ptd = img.u32(b) if b is not None else None
            if ptd not in td:
                ok = False
                break
            bases.append(td[ptd])
        if ok and bases:
            out[_nm] = bases
    return out


def vtables(img, cols):
    """[(vtable_va, td_name, subobj_offset, [method VAs])]; one row per COL reference."""
    out = []
    for v, r, rs, _ in img.secs:
        limit = min(rs, len(img.d) - r)
        for off in range(0, max(0, limit - 3), 4):
            w = struct.unpack_from("<I", img.d, r + off)[0]
            if w not in cols:
                continue
            start = v + off + 4
            methods = []
            while True:
                m = img.u32(start + len(methods) * 4)
                if m is None or not img.is_code(m):
                    break
                methods.append(m)
            if methods:
                name, sub, _cd, _ = cols[w]
                out.append((start, name, sub, methods))
    return out


def build_index(img):
    """{class_simple_key: record}; ties broken deterministically."""
    td = type_descriptors(img)
    cols = locators(img, td)
    hier = hierarchy(img, td, cols)
    vts = vtables(img, cols)
    thunks = {}
    for _va, _n, _s, ms in vts:
        for m in ms:
            if m not in thunks:
                thunks[m] = img.follow_thunk(m)

    by_class = {}

    def rec(mangled):
        key = simple_key(mangled)
        r = by_class.get(key)
        if r is None:
            r = by_class[key] = {
                "class": key,
                "mangled": mangled,
                "demangled": demangle(mangled),
                "type_descriptors": set(),
                "cols": set(),               # (col_va, offset, cd_offset, pchd)
                "vtables": {},               # vtable_va -> (offset, [slots])
                "bases": set(),
            }
        return r

    for tva, nm in td.items():
        rec(nm)["type_descriptors"].add(tva)
    for cva, (nm, sub, cd, pcd) in cols.items():
        rec(nm)["cols"].add((cva, sub, cd, pcd))
    for nm, bases in hier.items():
        r = rec(nm)
        for b in bases:
            if b != nm:
                r["bases"].add(simple_key(b))
    for va, nm, sub, ms in vts:
        r = rec(nm)
        r["vtables"][va] = (sub, ms)

    out = {}
    for key, r in by_class.items():
        # primary vtable: subobject offset 0, longest array wins
        pv_va, pv = None, []
        for va, (sub, ms) in sorted(r["vtables"].items()):
            if sub == 0 and len(ms) > len(pv):
                pv_va, pv = va, ms
        methods = [thunks.get(m) or m for m in pv]
        out[key] = {
            "class": key,
            "mangled": r["mangled"],
            "demangled": r["demangled"],
            "type_descriptor_vas": [f"0x{v:08X}" for v in sorted(r["type_descriptors"])],
            "col_vas": [f"0x{v:08X}" for v, *_ in sorted(r["cols"])],
            "cols": [{"va": f"0x{v:08X}", "offset": o, "cd_offset": c,
                      "chd": f"0x{p:08X}"} for v, o, c, p in sorted(r["cols"])],
            "vtables": [{"va": f"0x{va:08X}", "subobject_offset": sub,
                         "slot_count": len(ms),
                         "methods": [f"0x{m:08X}" for m in ms]}
                        for va, (sub, ms) in sorted(r["vtables"].items())],
            "primary_vtable": f"0x{pv_va:08X}" if pv_va else None,
            "primary_slot_count": len(pv),
            "primary_methods": [f"0x{m:08X}" for m in methods],
            "bases": sorted(r["bases"]),
            "has_vtable": bool(r["vtables"]),
        }
    return out, {"type_descriptors": len(td), "cols": len(cols),
                 "vtables": len(vts), "thunk_slots": sum(1 for t in thunks.values() if t)}


# --------------------------------------------------------------------------
# Mapping verification gate
# --------------------------------------------------------------------------
FUNC_RE = re.compile(r'"rva":\s*"0x([0-9a-fA-F]+)",\s*"va":\s*"0x([0-9a-fA-F]+)"')


def verify_mapping(img, functions_path, verbose=True):
    """Gate: the index's VA->file-offset mapping must equal Ghidra's.

    For every function record in functions.jsonl (regex-tolerant: a handful of
    lines contain raw control bytes inside pseudo and are repaired by regex):
      hard check 1: va == image_base + rva
      hard check 2: rva is file-backed through the PE section table
      soft check : the byte at the mapped file offset is not 0x00/0xCC padding
    Any hard-check failure raises; the caller must not emit an index over a
    mapping that failed. Soft failures are reported, never used to relax 1-2.
    """
    stats = {"records": 0, "regex_only": 0, "identity_mismatch": 0,
             "unmappable": 0, "padding_prologue": 0}
    with open(functions_path, "rb") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            m = FUNC_RE.search(s.decode("latin1"))
            if not m:
                continue
            stats["records"] += 1
            rva = int(m.group(1), 16)
            va = int(m.group(2), 16)
            try:
                json.loads(s)
            except Exception:
                stats["regex_only"] += 1
            if va - img.image_base != rva:
                stats["identity_mismatch"] += 1
            roff = img.raw(va)
            if roff is None:
                stats["unmappable"] += 1
                continue
            if img.d[roff] in (0x00, 0xCC):
                stats["padding_prologue"] += 1
    if stats["identity_mismatch"] or stats["unmappable"]:
        raise RuntimeError("mapping verification FAILED: %s" % stats)
    if verbose:
        print("[gate] functions.jsonl records=%d json_repaired=%d "
              "identity_mismatch=0 unmappable=0 padding_prologues=%d -> PASS"
              % (stats["records"], stats["regex_only"],
                 stats["padding_prologue"]))
    return stats


def verify_index_bytes(img, index):
    """Every VA written to the index must read back at its mapped file offset."""
    checked = mismatches = 0
    for rec in index.values():
        for c in rec["cols"]:
            checked += 1
            if img.u32(int(c["va"], 16) + 12) is None or \
               img.u32(int(c["va"], 16) + 16) is None:
                mismatches += 1
        for m in rec["primary_methods"]:
            va = int(m, 16)
            checked += 1
            if img.u32(va) is None:
                mismatches += 1
    if mismatches:
        raise RuntimeError("byte re-read verification FAILED on %d VAs" % mismatches)
    return checked


# --------------------------------------------------------------------------
# Mac side
# --------------------------------------------------------------------------
def mac_class_from_ztv(symbol):
    """'__ZTVN10nGZSceneGraph26cIAttributeFFTextureMatrixE' -> simple class name."""
    m = re.match(r"__ZTV\d+(.*)", symbol)
    if not m:
        return None
    nm = m.group(1)
    for _ in range(4):  # unwrap nested N..<name>.E namespaces, take innermost id
        em = re.match(r"N(.*)E\d*$", nm)
        if em:
            nm = em.group(1)
        else:
            break
    ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", nm)
    return ids[-1] if ids else None


def clean_class(name):
    return name.replace("(anonymous namespace)::", "").split("<")[0]


def load_mac(mac_dir):
    vtdir = os.path.join(mac_dir, "vtables")
    mac = {}

    def rec(cls):
        r = mac.get(cls)
        if r is None:
            r = mac[cls] = {"vtables": 0, "slots_t0": 0, "subtables": set(),
                            "named": {}}
        return r

    gt = json.load(open(os.path.join(vtdir, "game-i386-vtables.json")))
    for _k, val in gt.items():
        cls = mac_class_from_ztv(val.get("symbol", _k))
        if not cls:
            continue
        r = rec(cls)
        r["vtables"] += 1
        for g in val.get("groups", []):
            n = len(g.get("slots", []))
            r["subtables"].add(g.get("offset_to_top"))
            if g.get("offset_to_top") == 0 and n > r["slots_t0"]:
                r["slots_t0"] = n

    with open(os.path.join(vtdir, "method-candidates.tsv")) as f:
        hdr = f.readline().rstrip("\n").split("\t")
        for row in f:
            parts = row.rstrip("\n").split("\t")
            d = dict(zip(hdr, parts))
            if d.get("arch") != "i386":
                continue
            cls = clean_class(d["class"])
            r = rec(cls)
            slot = int(d["mac_slot"])
            r["subtables"].add(d["subtable"])
            if d["subtable"] == "0" and slot + 1 > r["slots_t0"]:
                r["slots_t0"] = slot + 1
            r["named"][(d["subtable"], slot)] = d["candidate_method"]
    return mac


# --------------------------------------------------------------------------
# Modes
# --------------------------------------------------------------------------
def cmd_index(args):
    data = open(args.image, "rb").read()
    img = PeImage(data)
    verify_mapping(img, args.functions)
    index, counts = build_index(img)
    checked = verify_index_bytes(img, index)
    classes = len(index)
    with_vt = sum(1 for r in index.values() if r["has_vtable"])
    gonzo = sum(1 for k in index
                if k.startswith(("cGZ", "cIGZ", "cTS", "cITS", "cGX", "cDH")))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        for key in sorted(index):
            f.write(json.dumps(index[key], sort_keys=True) + "\n")
    print("[index] TDs=%d cols=%d vtables=%d thunk_slots=%d" %
          (counts["type_descriptors"], counts["cols"], counts["vtables"],
           counts["thunk_slots"]))
    print("[index] classes=%d (with vtable=%d, Gonzo-style=%d); "
          "VA byte re-reads checked=%d mismatches=0" %
          (classes, with_vt, gonzo, checked))
    print("[index] wrote %s" % args.out)
    return 0


def cmd_join(args):
    index = {}
    with open(args.index) as f:
        for line in f:
            r = json.loads(line)
            index[r["class"]] = r
    mac = load_mac(args.mac_dir)
    rows = []
    stats = {"slots-match": 0, "slots-shift": 0, "mac-only": 0, "windows-only": 0,
             "transferred": 0, "matched_classes": 0}
    for key in sorted(set(index) | set(mac)):
        w = index.get(key)
        m = mac.get(key)
        w_slots = w["primary_slot_count"] if w and w["has_vtable"] else 0
        m_slots = m["slots_t0"] if m else 0
        if w and w["has_vtable"] and m:
            status = "slots-match" if w_slots == m_slots else "slots-shift"
        elif w and w["has_vtable"]:
            status = "windows-only"
        elif m:
            status = "mac-only"
        else:
            continue  # windows RTTI name with no vtable and no mac data
        stats[status] += 1
        if status in ("slots-match", "slots-shift"):
            stats["matched_classes"] += 1
        transferred = []
        if w and m and w["has_vtable"]:
            meths = w["primary_methods"]
            for (sub, slot), name in sorted(m["named"].items()):
                if str(sub) == "0" and slot < len(meths):
                    transferred.append("%d=%s@%s" % (slot, name, meths[slot]))
            stats["transferred"] += len(transferred)
        rows.append([
            key, status,
            f"{w_slots}" if w else "", (w or {}).get("primary_vtable", "") or "",
            str(len((w or {}).get("vtables", []))) if w else "",
            ";".join((w or {}).get("bases", [])[:6]),
            f"{m_slots}" if m else "", (str(len(m["subtables"])) if m else ""),
            str(len(m["named"])) if m else "", str(len(transferred)),
            "|".join(transferred[:8]),
        ])
    with open(args.out, "w", newline="\n") as f:
        f.write("\t".join(["class", "agreement", "win_slots", "win_vtable_va",
                           "win_vtable_count", "win_bases", "mac_slots_t0",
                           "mac_subtables", "mac_named_slots",
                           "method_candidates_transferred",
                           "transferred_sample(slot=MacName@WinVA)"]) + "\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    print("[join] classes_in_join=%d matched=%d (slots-match=%d slots-shift=%d) "
          "mac-only=%d windows-only=%d transferred_method_candidates=%d"
          % (len(rows), stats["matched_classes"], stats["slots-match"],
             stats["slots-shift"], stats["mac-only"], stats["windows-only"],
             stats["transferred"]))
    print("[join] wrote %s" % args.out)
    json.dump(stats, open(args.out + ".stats.json", "w"), indent=1)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="mode", required=True)
    default_img = "work/interop-legacy-002/analysis-image.bin"
    default_fn = "work/ghidra-index/functions.jsonl"
    pi = sub.add_parser("index")
    pi.add_argument("--image", default=default_img)
    pi.add_argument("--functions", default=default_fn)
    pi.add_argument("--out", default="work/private/mac-leads/windows-rtti-index.jsonl")
    pi.set_defaults(fn=cmd_index)
    pj = sub.add_parser("join")
    pj.add_argument("--index", default="work/private/mac-leads/windows-rtti-index.jsonl")
    pj.add_argument("--mac-dir", default="work/private/mac-leads")
    pj.add_argument("--out", default="work/private/mac-leads/join-mac-candidates.tsv")
    pj.set_defaults(fn=cmd_join)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
