from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import randgrid_deep_xrefs as analysis  # noqa: E402


class RuntimeLookupTests(unittest.TestCase):
    def test_half_open_runtime_ranges(self) -> None:
        lookup = analysis.RuntimeLookup(
            [
                {"begin_rva": 0x100, "end_rva": 0x120, "size": 0x20, "unwind_rva": 0x500},
                {"begin_rva": 0x140, "end_rva": 0x150, "size": 0x10, "unwind_rva": 0x510},
            ]
        )
        self.assertIsNone(lookup.containing(0xFF))
        self.assertEqual(lookup.containing(0x100)["begin_rva"], 0x100)
        self.assertEqual(lookup.containing(0x11F)["end_rva"], 0x120)
        self.assertIsNone(lookup.containing(0x120))
        self.assertIsNone(lookup.containing(0x130))
        self.assertEqual(lookup.containing(0x149)["begin_rva"], 0x140)
        self.assertIsNone(lookup.containing(0x150))


class SummaryTests(unittest.TestCase):
    def test_p95_nearest_rank(self) -> None:
        self.assertEqual(analysis.p95([]), 0)
        self.assertEqual(analysis.p95([7]), 7)
        self.assertEqual(analysis.p95(list(range(1, 101))), 95)

    def test_calls_are_separate_from_linkage_stubs(self) -> None:
        slots = {
            0x2000: {"dll": "ntoskrnl.exe", "name": "ObRegisterCallbacks", "iat_va": 0x2000}
        }
        direct = [
            {"name": "ObRegisterCallbacks", "kind": "call"},
            {"name": "ObRegisterCallbacks", "kind": "jmp"},
        ]
        stub = [
            {"name": "ObRegisterCallbacks", "kind": "call"},
            {"name": "ObRegisterCallbacks", "kind": "jmp"},
        ]
        linear = [
            {"name": "ObRegisterCallbacks", "mnemonic": "call"},
            {"name": "ObRegisterCallbacks", "mnemonic": "mov"},
        ]
        groups = analysis.summarize_focus(slots, direct, stub, linear)
        row = groups["object_callbacks"][0]
        self.assertTrue(row["imported"])
        self.assertEqual(row["direct_call_count"], 1)
        self.assertEqual(row["iat_jump_count"], 1)
        self.assertEqual(row["stub_call_count"], 1)
        self.assertEqual(row["stub_jump_count"], 1)
        self.assertEqual(row["effective_call_count"], 2)
        self.assertEqual(row["linear_other_reference_count"], 1)


class PublishedEvidenceContractTests(unittest.TestCase):
    def test_published_evidence_matches_the_analyzed_driver(self) -> None:
        candidates = (
            ROOT / "evidence" / "randgrid-deep-xrefs.json",
            ROOT / "analysis" / "randgrid-deep-xrefs.json",
        )
        evidence_path = next((path for path in candidates if path.is_file()), None)
        self.assertIsNotNone(evidence_path, "generated Randgrid evidence is missing")
        payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(
            payload["input"]["sha256"],
            "4150290a810ebebe9f9e6b5bd32c60299f9f34c3d2b6f02b89590ed49a6b895e",
        )
        self.assertEqual(payload["imports"]["slot_count"], 689)
        self.assertEqual(payload["imports"]["direct_call_count"], 527)
        self.assertEqual(payload["imports"]["stub_call_count"], 23)
        self.assertEqual(payload["imports"]["effectively_called_import_count"], 61)
        self.assertEqual(payload["runtime_functions"]["count"], 2191)
        self.assertEqual(payload["runtime_functions"]["max_size"], 0x2BADC9)
        self.assertEqual(payload["dynamic_kernel_name_scan"]["candidate_count"], 0)

        groups = payload["focus_groups"]
        object_registration = groups["object_callbacks"][0]
        self.assertEqual(object_registration["name"], "ObRegisterCallbacks")
        self.assertEqual(object_registration["effective_call_count"], 1)
        self.assertTrue(
            all(row["effective_call_count"] > 0 for row in groups["cng_signature_surface"])
        )

    def test_public_manifest_hashes_when_present(self) -> None:
        manifest_path = ROOT / "evidence" / "manifest.json"
        if not manifest_path.is_file():
            self.skipTest("public manifest is not present in the local research workspace")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for relative_path, expected in manifest["artifacts"].items():
            path = ROOT / relative_path
            self.assertTrue(path.is_file(), f"manifest artifact is missing: {relative_path}")
            actual = hashlib.sha256(path.read_bytes()).hexdigest().upper()
            self.assertEqual(actual, expected, relative_path)


if __name__ == "__main__":
    unittest.main()
