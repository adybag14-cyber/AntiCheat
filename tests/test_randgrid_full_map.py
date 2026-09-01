from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import randgrid_full_map as analysis  # noqa: E402


class ClassificationTests(unittest.TestCase):
    def test_iat_stub(self) -> None:
        insns = [{"mnemonic": "jmp", "text": "jmp qword ptr [rip + 0x10]"}]
        self.assertEqual(analysis.classify_from_head(insns, 6, bytes.fromhex("ff2500000000")), "iat_stub")

    def test_mba_epilogue(self) -> None:
        insns = [
            {"mnemonic": "pop", "text": "pop rax"},
            {"mnemonic": "popfq", "text": "popfq"},
        ]
        self.assertEqual(analysis.classify_from_head(insns, 2, b"\x58\x9d"), "mba_epilogue")

    def test_clear_wrapper(self) -> None:
        insns = [
            {"mnemonic": "mov", "text": "mov qword ptr [rsp + 8], rcx"},
            {"mnemonic": "mov", "text": "mov qword ptr [rsp + 0x10], rdx"},
            {"mnemonic": "sub", "text": "sub rsp, 0x108"},
            {"mnemonic": "jmp", "text": "jmp 0x140425dc6"},
        ]
        self.assertEqual(
            analysis.classify_from_head(insns, 0x20, bytes.fromhex("48894c2408")),
            "clear_wrapper_to_obfuscated",
        )

    def test_thunk(self) -> None:
        insns = [{"mnemonic": "jmp", "text": "jmp 0x14059a14c"}]
        self.assertEqual(analysis.classify_from_head(insns, 5, b"\xe9\x00\x00\x00\x00"), "thunk")

    def test_undecodable_padding(self) -> None:
        self.assertEqual(analysis.classify_from_head([], 16, b"\x00\x00\x11\x22"), "padding")

    def test_mba_push_is_not_msvc(self) -> None:
        insns = [
            {"mnemonic": "push", "text": "push 0x7f9fc4ed"},
            {"mnemonic": "sub", "text": "sub rsp, 8"},
            {"mnemonic": "push", "text": "push 0x6fe541aa"},
            {"mnemonic": "mov", "text": "mov qword ptr [rsp], rdx"},
            {"mnemonic": "pop", "text": "pop qword ptr [rsp]"},
            {"mnemonic": "pop", "text": "pop qword ptr [rsp]"},
        ]
        self.assertEqual(
            analysis.classify_from_head(insns, 80, b"\x68\xed\xc4\x9f\x7f"),
            "mba_obfuscated",
        )


class NamingTests(unittest.TestCase):
    def test_known_driver_entry(self) -> None:
        self.assertEqual(
            analysis.name_function(0x140C61000, "thunk", [], 0x14059A14C, None),
            "DriverEntry",
        )

    def test_iat_stub_name(self) -> None:
        self.assertEqual(
            analysis.name_function(0x140AB8CED, "iat_stub", [], None, "BCryptOpenAlgorithmProvider"),
            "iat_stub_BCryptOpenAlgorithmProvider",
        )

    def test_single_import_wrapper(self) -> None:
        self.assertEqual(
            analysis.name_function(0x14000ABCD, "clear_msvc", ["ObRegisterCallbacks"], None, None),
            "wrapper_ObRegisterCallbacks",
        )


class GapByteTests(unittest.TestCase):
    def test_legacy_ud(self) -> None:
        self.assertEqual(analysis.classify_gap_byte(0x60, b"\x48\x83"), ("legacy_ud", "PUSHA"))
        self.assertEqual(analysis.classify_gap_byte(0xD5, b""), ("legacy_ud", "AAD"))
        self.assertEqual(analysis.classify_gap_byte(0x27, b"\x90"), ("legacy_ud", "DAA"))

    def test_ff_group5_invalid(self) -> None:
        # ModR/M /7 → #UD in 64-bit group 5
        self.assertEqual(analysis.classify_gap_byte(0xFF, bytes([0x38])), ("invalid_ff", "group5_/7"))

    def test_lock_and_rex(self) -> None:
        self.assertEqual(analysis.classify_gap_byte(0xF0, b"\x48\x83"), ("invalid_prefix", "LOCK"))
        self.assertEqual(analysis.classify_gap_byte(0x48, b"\x83\xec"), ("orphan_rex", "REX_48"))

    def test_every_byte_is_named(self) -> None:
        for value in range(256):
            coarse, fine = analysis.classify_gap_byte(value, b"\x00")
            self.assertTrue(coarse)
            self.assertTrue(fine)


class PrologueTests(unittest.TestCase):
    def test_pushfq_and_msvc_home(self) -> None:
        self.assertTrue(analysis.looks_like_entry(b"\x9c\x50"))
        self.assertTrue(analysis.looks_like_entry(bytes.fromhex("48894c2408")))
        self.assertFalse(analysis.looks_like_entry(b"\x00\x00"))
        self.assertFalse(analysis.looks_like_entry(b""))


class PublishedEvidenceContractTests(unittest.TestCase):
    def test_full_map_evidence_when_present(self) -> None:
        path = ROOT / "evidence" / "randgrid-full-map.json"
        if not path.is_file():
            self.skipTest("full-map evidence has not been generated yet")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["input"]["sha256"], analysis.EXPECTED_SHA256)
        self.assertGreaterEqual(payload["seeds"]["pdata"], 2191)
        self.assertGreaterEqual(payload["seeds"]["unique_function_starts"], 2191)
        self.assertGreater(payload["coverage"]["instruction_count"], 100_000)
        self.assertGreater(payload["coverage"]["coverage"], 0.5)
        gaps = payload["coverage"]["gaps"]
        self.assertEqual(gaps["unclassified_bytes"], 0)
        self.assertEqual(gaps["classified_bytes"], gaps["bytes"])
        self.assertGreater(gaps["bytes"], 0)
        self.assertIn("legacy_ud", gaps["classes"])
        self.assertEqual(payload["coverage"]["classified_coverage"], 1.0)
        names = {row["name"] for row in payload["named_known"]}
        self.assertIn("DriverEntry", names)
        self.assertTrue(any(row.get("iat_imports") for row in payload["functions"]))


class ManifestHashTests(unittest.TestCase):
    def test_new_full_map_artifacts_match_manifest_when_listed(self) -> None:
        manifest_path = ROOT / "evidence" / "manifest.json"
        if not manifest_path.is_file():
            self.skipTest("manifest is not present")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for relative in (
            "evidence/randgrid-full-map.json",
            "evidence/randgrid-full-map.md",
            "scripts/randgrid_full_map.py",
            "docs/09-randgrid-full-function-map.md",
        ):
            expected = manifest.get("artifacts", {}).get(relative)
            if expected is None:
                continue
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            actual = hashlib.sha256(path.read_bytes()).hexdigest().upper()
            self.assertEqual(actual, expected, relative)


if __name__ == "__main__":
    unittest.main()
