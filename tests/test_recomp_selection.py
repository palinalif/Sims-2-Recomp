"""Public metadata tests; no private function bytes, states or derived code."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("recomp_selection", ROOT / "scripts/recomp/select_candidates.py")
selection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selection)


class SelectionTests(unittest.TestCase):
    def test_deterministic_manifest_and_checked_in_copy(self):
        first = selection.select_candidates()
        self.assertEqual(first, selection.select_candidates())
        self.assertEqual(first, json.loads((ROOT / "scripts/recomp/candidates.json").read_text()))
        self.assertEqual(first["counts"]["selected"], 21)
        self.assertLessEqual(first["counts"]["selected"], 25)
        self.assertEqual(first["counts"]["selected"], len(first["selected"]))
        rows = first["selected"] + first["rejected"]
        self.assertEqual(len(rows), len({r["rva"] for r in rows}))

    def test_hard_seeds_and_all_stress_categories_remain(self):
        manifest = selection.select_candidates()
        selected = {r["rva"]: r for r in manifest["selected"]}
        for rva in ("0x9B52C0", "0x1E36F0", "0x1E95C0", "0x1ABD40", "0x1D3E20", "0x1DA310", "0x8248A3", "0x8258A9", "0x82585C", "0x824727", "0x825BB0", "0x82A6D3", "0x82A47B", "0x1460"):
            self.assertIn(rva, selected)
        self.assertEqual(set(selection.CATEGORIES), {c for r in selected.values() for c in r["categories"]})
        self.assertEqual({"0x1AB79C", "0xC261A1"}, {r["rva"] for r in manifest["rejected"]})
        self.assertTrue(all(r["reason"] for r in manifest["rejected"]))

    def test_selection_never_claims_execution_or_invents_unknowns(self):
        manifest = selection.select_candidates()
        for key in ("attempted", "lifted", "compiled_for_aarch64", "matched_x86_reference", "executed_under_qemu"):
            self.assertEqual(manifest["counts"][key], 0)
        for row in manifest["selected"]:
            self.assertIsNone(row["reliable_ghidra_boundary"])
            self.assertIsNone(row["dependencies"])
            self.assertEqual(row["status"], "selected-not-attempted-this-run")
        self.assertIsNone(manifest["selected"][0]["size_bytes"])
        for row in manifest["selected"]:
            self.assertTrue((ROOT / row["source"]).is_file())

    def test_budget_and_duplicate_policy_fail_not_truncate(self):
        with patch.object(selection, "CATALOG", selection.CATALOG * 2):
            with self.assertRaisesRegex(ValueError, "budget"):
                selection.select_candidates()
        with patch.object(selection, "REJECTED", selection.REJECTED + (selection.REJECTED[0],)):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                selection.select_candidates()

    def test_pin_failure_is_readonly_sanitized_and_emits_no_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "owner-private-name"
            path.write_bytes(b"public authored wrong-pin fixture")
            before = path.read_bytes()
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(selection.main(["--image", str(path)]), 2)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(out.getvalue(), "")
            self.assertNotIn(tmp, err.getvalue())
            self.assertNotIn(path.name, err.getvalue())
            path.unlink()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(selection.main(["--image", str(path)]), 2)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
