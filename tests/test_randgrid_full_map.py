from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import randgrid_full_map as analysis


class ClassificationTests(unittest.TestCase):
    def test_iat_stub(self) -> None:
        insns = [{"mnemonic": "jmp", "text": "jmp qword ptr [rip + 0x10]"}]
        self.assertEqual(
            analysis.classify_from_head(insns, 6, bytes.fromhex("ff2500000000")),
            "iat_stub",
        )

    def test_mba_epilogue(self) -> None:
        insns = [
            {"mnemonic": "pop", "text": "pop rax"},
            {"mnemonic": "popfq", "text": "popfq"},
        ]
        self.assertEqual(
            analysis.classify_from_head(insns, 2, b"\x58\x9d"), "mba_epilogue"
        )

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
        self.assertEqual(
            analysis.classify_from_head(insns, 5, b"\xe9\x00\x00\x00\x00"), "thunk"
        )

    def test_undecodable_padding(self) -> None:
        self.assertEqual(
            analysis.classify_from_head([], 16, b"\x00\x00\x11\x22"), "padding"
        )

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
            analysis.name_function(
                0x140AB8CED, "iat_stub", [], None, "BCryptOpenAlgorithmProvider"
            ),
            "iat_stub_BCryptOpenAlgorithmProvider",
        )

    def test_single_import_wrapper(self) -> None:
        self.assertEqual(
            analysis.name_function(
                0x14000ABCD, "clear_msvc", ["ObRegisterCallbacks"], None, None
            ),
            "wrapper_ObRegisterCallbacks",
        )


class GapByteTests(unittest.TestCase):
    def test_legacy_ud(self) -> None:
        self.assertEqual(
            analysis.classify_gap_byte(0x60, b"\x48\x83"), ("legacy_ud", "PUSHA", True)
        )
        self.assertEqual(
            analysis.classify_gap_byte(0xD5, b""), ("legacy_ud", "AAD", True)
        )
        self.assertEqual(
            analysis.classify_gap_byte(0x27, b"\x90"), ("legacy_ud", "DAA", True)
        )

    def test_ff_group5_invalid(self) -> None:
        # ModR/M /7 → #UD in 64-bit group 5
        self.assertEqual(
            analysis.classify_gap_byte(0xFF, bytes([0x38])),
            ("invalid_ff", "group5_/7", True),
        )

    def test_lock_and_rex(self) -> None:
        self.assertEqual(
            analysis.classify_gap_byte(0xF0, b"\x48\x83"),
            ("invalid_prefix", "LOCK", True),
        )
        self.assertEqual(
            analysis.classify_gap_byte(0x48, b"\x83\xec"),
            ("orphan_rex", "REX_48", True),
        )

    def test_every_byte_is_labeled_but_unknown_is_not_recognized(self) -> None:
        for value in range(256):
            coarse, fine, recognized = analysis.classify_gap_byte(value, b"\x00")
            self.assertTrue(coarse)
            self.assertTrue(fine)
            self.assertIsInstance(recognized, bool)
        self.assertEqual(
            analysis.classify_gap_byte(0x90, b"\x00"), ("unknown", "op_90", False)
        )

    def test_truncated_valid_opcode_is_contextually_recognized(self) -> None:
        self.assertEqual(
            analysis.classify_gap_byte(0xE2, b""),
            ("truncated_instruction", "LOOP_family_E2_rel8", True),
        )
        self.assertEqual(
            analysis.classify_gap_byte(0xA9, b""),
            ("truncated_instruction", "TEST_EAX_imm32", True),
        )


class PrologueTests(unittest.TestCase):
    def test_pushfq_and_msvc_home(self) -> None:
        self.assertTrue(analysis.looks_like_entry(b"\x9c\x50"))
        self.assertTrue(analysis.looks_like_entry(bytes.fromhex("48894c2408")))
        self.assertFalse(analysis.looks_like_entry(b"\x00\x00"))
        self.assertFalse(analysis.looks_like_entry(b""))


class AuthorityTests(unittest.TestCase):
    def test_wrong_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "Randgrid.sys"
            target.write_bytes(b"not the pinned driver")
            with self.assertRaisesRegex(ValueError, "unexpected Randgrid.sys size"):
                analysis.verify_target(target)

    def test_ghidra_catalog_requires_complete_header_and_footer(self) -> None:
        header = {
            "type": "header",
            "program": "Randgrid.sys",
            "image_base": "140000000",
            "program_sha256": analysis.EXPECTED_SHA256,
            "ghidra_version": "test",
            "language_id": "x86:LE:64:default",
            "compiler_spec_id": "windows",
            "ghidra_function_count": 1,
        }
        function = {
            "type": "function",
            "name": "FUN_140001000",
            "entry": "140001000",
            "body_ranges": [{"min": "140001000", "max": "140001005"}],
            "body_addresses": 6,
            "external": False,
        }
        footer = {"type": "footer", "written_functions": 1, "cancelled": False}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ghidra-functions.jsonl"
            path.write_text(
                "\n".join(json.dumps(item) for item in (header, function, footer))
                + "\n",
                encoding="utf-8",
            )
            rows, provenance = analysis.load_ghidra_catalog(
                path,
                image_base=0x140000000,
                input_sha256=analysis.EXPECTED_SHA256,
            )
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["_body_ranges"], [(0x140001000, 0x140001006)])
            self.assertEqual(provenance["written_functions"], 1)
            path.write_text(
                "\n".join(json.dumps(item) for item in (header, function)) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "header, functions, or footer"):
                analysis.load_ghidra_catalog(
                    path,
                    image_base=0x140000000,
                    input_sha256=analysis.EXPECTED_SHA256,
                )

    def test_invalid_ghidra_catalog_is_rejected_before_dump_generation(self) -> None:
        fake_pe = mock.Mock()
        fake_pe.OPTIONAL_HEADER.ImageBase = 0x140000000
        fake_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        with (
            mock.patch.object(
                analysis,
                "verify_target",
                return_value={"sha256": analysis.EXPECTED_SHA256},
            ),
            mock.patch.object(analysis.pefile, "PE", return_value=fake_pe),
            mock.patch.object(
                analysis,
                "load_ghidra_catalog",
                side_effect=ValueError("invalid catalog"),
            ),
            mock.patch.object(analysis, "linear_coverage") as linear_coverage,
            self.assertRaisesRegex(ValueError, "invalid catalog"),
        ):
            analysis.build_payload(
                Path("Randgrid.sys"), Path("analysis"), Path("catalog.jsonl")
            )
        linear_coverage.assert_not_called()


class CallOwnershipTests(unittest.TestCase):
    def test_smallest_exact_ghidra_body_is_the_single_owner(self) -> None:
        entries = [
            {
                "va": 0x140001000,
                "rva": 0x1000,
                "name": "outer",
                "ghidra_body_ranges": [(0x140001000, 0x140001100)],
                "ghidra_body_addresses": 0x100,
                "pdata": None,
            },
            {
                "va": 0x140001040,
                "rva": 0x1040,
                "name": "inner",
                "ghidra_body_ranges": [(0x140001040, 0x140001060)],
                "ghidra_body_addresses": 0x20,
                "pdata": None,
            },
        ]
        call = {
            "instruction_va": 0x140001050,
            "instruction_rva": 0x1050,
            "name": "ObRegisterCallbacks",
            "dll": "ntoskrnl.exe",
            "instruction": "call qword ptr [rip]",
            "bytes": "ff1500000000",
        }
        sites = analysis.build_call_sites([call], [], entries)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["owner_va"], 0x140001040)
        self.assertEqual(sites[0]["owner_basis"], "ghidra_body")
        self.assertEqual(sites[0]["owner_candidate_count"], 2)


class PublishedEvidenceContractTests(unittest.TestCase):
    def test_full_map_evidence_when_present(self) -> None:
        path = ROOT / "evidence" / "randgrid-full-map.json"
        if not path.is_file():
            self.skipTest("full-map evidence has not been generated yet")
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(payload["input"]["sha256"], analysis.EXPECTED_SHA256)
        self.assertTrue(payload["authority"]["pinned_input_enforced"])
        self.assertEqual(
            payload["authority"]["ghidra_catalog"]["program_sha256"],
            analysis.EXPECTED_SHA256,
        )
        self.assertGreaterEqual(payload["seeds"]["pdata"], 2191)
        self.assertEqual(payload["seeds"]["ghidra_catalog"], 8105)
        self.assertEqual(payload["seeds"]["unique_entry_candidates"], 8764)
        self.assertGreater(payload["coverage"]["instruction_count"], 100_000)
        self.assertGreater(payload["coverage"]["coverage"], 0.5)
        gaps = payload["coverage"]["gaps"]
        self.assertEqual(gaps["unclassified_bytes"], 0)
        self.assertEqual(gaps["classified_bytes"], gaps["bytes"])
        self.assertEqual(gaps["classes"]["truncated_instruction"], 2)
        self.assertGreater(gaps["bytes"], 0)
        self.assertIn("legacy_ud", gaps["classes"])
        self.assertEqual(payload["coverage"]["classified_coverage"], 1.0)
        names = {row["name"] for row in payload["named_known"]}
        self.assertIn("DriverEntry", names)
        self.assertEqual(payload["imports"]["unique_call_site_count"], 550)
        self.assertEqual(payload["imports"]["owned_call_site_count"], 550)
        self.assertEqual(payload["imports"]["unresolved_call_site_count"], 0)
        self.assertEqual(payload["imports"]["entries_with_owned_iat_calls"], 543)
        self.assertEqual(
            payload["imports"]["call_sites_with_multiple_owner_candidates"], 103
        )
        self.assertFalse(
            any("iat_call" in row["source"].split("+") for row in payload["entries"])
        )
        self.assertTrue(any(row.get("iat_imports") for row in payload["entries"]))


class ManifestHashTests(unittest.TestCase):
    def test_new_full_map_artifacts_match_manifest_when_listed(self) -> None:
        manifest_path = ROOT / "evidence" / "manifest.json"
        if not manifest_path.is_file():
            self.skipTest("manifest is not present")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for relative in (
            "README.md",
            "evidence/randgrid-full-map.json",
            "evidence/randgrid-full-map.md",
            "evidence/randgrid-source-reconstruction-summary.json",
            "examples/randgrid-source-reconstruction.c",
            "scripts/randgrid_full_map.py",
            "scripts/randgrid_source_reconstruction.py",
            "scripts/update_evidence_manifest.py",
            "scripts/ghidra/GhidraFullFunctionCatalog.java",
            "docs/09-randgrid-full-function-map.md",
            "docs/10-randgrid-source-reconstruction.md",
            "tests/test_randgrid_source_reconstruction.py",
        ):
            expected = manifest.get("artifacts", {}).get(relative)
            self.assertIsNotNone(expected, relative)
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            actual = hashlib.sha256(path.read_bytes()).hexdigest().upper()
            self.assertEqual(actual, expected, relative)

    def test_private_authority_hashes_match_public_summary(self) -> None:
        manifest = json.loads(
            (ROOT / "evidence" / "manifest.json").read_text(encoding="utf-8")
        )
        summary = json.loads(
            (
                ROOT / "evidence" / "randgrid-source-reconstruction-summary.json"
            ).read_text(encoding="utf-8")
        )
        authority = manifest["authority_inputs"]
        self.assertEqual(
            authority["ghidra_catalog"]["sha256"].lower(),
            summary["authority"]["ghidra_catalog"]["sha256"],
        )
        self.assertEqual(
            authority["instruction_dump"]["sha256"].lower(),
            summary["authority"]["instruction_dump_sha256"],
        )
        self.assertEqual(
            authority["gap_dump"]["sha256"].lower(),
            summary["authority"]["gap_dump_sha256"],
        )
        self.assertEqual(
            authority["full_source_like_reconstruction"]["sha256"].lower(),
            summary["full_local_reconstruction"]["sha256"],
        )


if __name__ == "__main__":
    unittest.main()
