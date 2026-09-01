from __future__ import annotations

import gzip
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import randgrid_source_reconstruction as reconstruction


class SourceReconstructionTests(unittest.TestCase):
    def test_full_reconstruction_covers_each_dump_byte_once(self) -> None:
        evidence = {
            "input": {"sha256": "a" * 64},
            "coverage": {
                "executable_virtual_bytes": 3,
                "sections": [
                    {
                        "name": ".text",
                        "va": 0x140001000,
                        "virtual_size": 3,
                    }
                ],
            },
            "call_sites": [],
            "entries": [
                {
                    "name": "example",
                    "va": "0x140001000",
                    "end_va": "0x140001003",
                    "entry_kind": "ghidra_function",
                    "entry_confidence": "medium",
                }
            ],
        }
        ghidra = [
            {
                "entry": "140001000",
                "body_addresses": 3,
                "_body_ranges": [(0x140001000, 0x140001003)],
            }
        ]
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            instructions = temp_path / "instructions.tsv.gz"
            gaps = temp_path / "gaps.tsv.gz"
            output = temp_path / "reconstruction.c.gz"
            with gzip.open(
                instructions, "wt", encoding="utf-8", newline="\n"
            ) as handle:
                handle.write("va\tsize\tbytes\ttext\tsection\n")
                handle.write("140001000\t2\t90c3\tnop ; ret\t.text\n")
            with gzip.open(gaps, "wt", encoding="utf-8", newline="\n") as handle:
                handle.write("va\tsize\tbytes\tcoarse\tfine\tsection\n")
                handle.write("140001002\t1\t60\tlegacy_ud\tPUSHA\t.text\n")
            result = reconstruction.write_full_reconstruction(
                evidence=evidence,
                ghidra_rows=ghidra,
                instructions=instructions,
                gaps=gaps,
                output=output,
            )
            self.assertEqual(result["covered_bytes"], 3)
            self.assertEqual(result["instruction_records"], 1)
            self.assertEqual(result["gap_records"], 1)
            self.assertEqual(result["unowned_records"], 0)
            with gzip.open(output, "rt", encoding="utf-8") as handle:
                text = handle.read()
            self.assertIn("0x140001000 90c3", text)
            self.assertIn("0x140001002 60 | SKIPDATA legacy_ud:PUSHA", text)
            self.assertIn("NOT ORIGINAL SOURCE", text)

    def test_overlap_and_compensating_hole_are_rejected(self) -> None:
        evidence = {
            "input": {"sha256": "a" * 64},
            "coverage": {
                "executable_virtual_bytes": 3,
                "sections": [
                    {
                        "name": ".text",
                        "va": 0x140001000,
                        "virtual_size": 3,
                    }
                ],
            },
            "call_sites": [],
            "entries": [],
        }
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            instructions = temp_path / "instructions.tsv.gz"
            gaps = temp_path / "gaps.tsv.gz"
            output = temp_path / "reconstruction.c.gz"
            with gzip.open(
                instructions, "wt", encoding="utf-8", newline="\n"
            ) as handle:
                handle.write("va\tsize\tbytes\ttext\tsection\n")
                handle.write("140001000\t2\t90c3\tnop ; ret\t.text\n")
            with gzip.open(gaps, "wt", encoding="utf-8", newline="\n") as handle:
                handle.write("va\tsize\tbytes\tcoarse\tfine\tsection\n")
                handle.write("140001001\t1\t60\tlegacy_ud\tPUSHA\t.text\n")
            with self.assertRaisesRegex(ValueError, "non-contiguous reconstruction"):
                reconstruction.write_full_reconstruction(
                    evidence=evidence,
                    ghidra_rows=[],
                    instructions=instructions,
                    gaps=gaps,
                    output=output,
                )

    def test_public_example_contains_no_operational_driver_calls(self) -> None:
        evidence = {
            "input": {"sha256": "b" * 64},
            "call_sites": [],
            "entries": [
                {
                    "name": "DriverEntry",
                    "va": "0x140001000",
                    "entry_kind": "pe_entry",
                    "entry_confidence": "high",
                    "source": "pe_entry+known",
                    "head": [
                        {
                            "va": "0x140001000",
                            "bytes": "e900000000",
                            "text": "jmp 0x140001005",
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "example.c"
            result = reconstruction.write_public_example(evidence, output)
            text = output.read_text(encoding="utf-8")
            self.assertEqual(result["entry_examples"], 1)
            self.assertIn("NOT original source".lower(), text.lower())
            for forbidden in (
                "DeviceIoControl(",
                "WriteProcessMemory(",
                "CreateRemoteThread(",
                "ZwDeviceIoControlFile(",
            ):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
