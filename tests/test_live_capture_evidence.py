from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "live-capture.json"
CAPTURE_SCRIPT = ROOT / "scripts" / "live_capture.py"


class LiveCaptureEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    def test_schema_and_capture_boundary(self) -> None:
        self.assertEqual(self.payload["schema_version"], 2)
        self.assertFalse(self.payload["capture"]["raw_capture_published"])
        self.assertEqual(
            self.payload["capture"]["original_capture_utc"],
            "2026-08-28T21:55:50.434944+00:00",
        )

    def test_requested_and_granted_access_are_distinct(self) -> None:
        process = self.payload["game_process"]
        self.assertEqual(process["requested_access"]["mask"], "0x00000410")
        self.assertEqual(process["non_admin_granted_access"]["mask"], "0x00001000")
        self.assertEqual(
            process["administrator_granted_access"]["mask"], "0x00001000"
        )
        self.assertTrue(process["access_reduction_observed"])
        self.assertFalse(process["token_is_elevated"])
        self.assertEqual(process["protection_level"], "PROTECTION_LEVEL_NONE")

    def test_module_error_and_region_success_are_not_conflated(self) -> None:
        modules = self.payload["module_snapshot"]
        self.assertFalse(modules["non_admin"]["succeeded"])
        self.assertEqual(modules["non_admin"]["error_code"], 5)
        self.assertIsNone(modules["non_admin"]["module_count"])
        self.assertFalse(modules["administrator"]["succeeded"])
        self.assertIsNone(modules["administrator"]["module_count"])
        regions = self.payload["region_metadata"]
        self.assertTrue(regions["non_admin"]["enumeration_succeeded"])
        self.assertTrue(regions["administrator"]["enumeration_succeeded"])
        self.assertGreater(regions["non_admin"]["region_count"], 0)
        self.assertGreater(regions["administrator"]["region_count"], 0)

    def test_public_safety_counters_are_zero(self) -> None:
        original = self.payload["safety"]["original_recorded_run"]
        independent = self.payload["safety"]["independent_verification"]
        self.assertEqual(original["device_ioctl_calls_reached"], 0)
        self.assertEqual(original["process_memory_write_calls_reached"], 0)
        self.assertFalse(original["injection_executed"])
        self.assertTrue(all(value == 0 for value in independent.values()))

    def test_sensitive_raw_fields_are_not_published(self) -> None:
        forbidden_keys = {
            "host",
            "user",
            "game_pid",
            "processid",
            "parentprocessid",
            "commandline",
            "handle",
            "object",
            "base",
            "path",
            "pathname",
            "original_hex",
            "after_write_hex",
            "header_hex",
        }

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key.lower()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        published_keys = set(keys(self.payload))
        self.assertTrue(forbidden_keys.isdisjoint(published_keys))
        serialized = json.dumps(self.payload)
        self.assertNotRegex(serialized, re.compile(r"[A-Za-z]:\\\\"))
        self.assertNotRegex(serialized, re.compile(r"0x[fF]{4}[0-9A-Fa-f]{12}"))

    def test_privacy_flags_are_all_false(self) -> None:
        self.assertTrue(all(value is False for value in self.payload["privacy"].values()))

    def test_raw_capture_defaults_to_ignored_local_analysis(self) -> None:
        source = CAPTURE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('default="local-analysis/live-capture.json"', source)
        self.assertNotIn('default="evidence/live-capture.json"', source)

    def test_public_text_artifacts_use_lf(self) -> None:
        for relative in (
            "evidence/live-capture.json",
            "docs/08-live-analysis.md",
            "scripts/live_capture.py",
        ):
            self.assertNotIn(b"\r\n", (ROOT / relative).read_bytes(), relative)


if __name__ == "__main__":
    unittest.main()
