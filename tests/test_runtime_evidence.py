from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_EVIDENCE = ROOT / "evidence" / "randgrid-runtime-passive-summary.json"


class RuntimeEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(RUNTIME_EVIDENCE.read_text(encoding="utf-8"))

    def test_live_driver_matches_static_authority(self) -> None:
        self.assertEqual(
            self.payload["driver"]["sha256"],
            "4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E",
        )
        self.assertEqual(self.payload["driver"]["state"], "Running")
        self.assertEqual(self.payload["driver"]["signature_status"], "Valid")

    def test_live_device_link_and_variant_identity(self) -> None:
        self.assertEqual(
            self.payload["live_object_namespace"]["result"], "\\Device\\Randgrid"
        )
        variants = {row["service"]: row for row in self.payload["variants"]}
        self.assertEqual(
            variants["atvi-randgrid_sr"]["sha256"],
            variants["atvi-randgrid_msstore"]["sha256"],
        )
        self.assertEqual(variants["atvi-randgrid_sr"]["state"], "Running")
        self.assertEqual(variants["atvi-randgrid_msstore"]["state"], "Stopped")

    def test_retry_pattern_is_preserved(self) -> None:
        collisions = self.payload["msstore_collision_events"]
        self.assertEqual(collisions["count"], 42)
        self.assertEqual(collisions["interval_count"], 41)
        self.assertEqual(collisions["intervals_at_or_below_7_seconds"], 36)
        self.assertAlmostEqual(collisions["median_interval_seconds"], 5.5499154)

    def test_handle_policy_is_explicitly_unresolved(self) -> None:
        result = self.payload["handle_policy_result"]
        self.assertTrue(result["static_registration"])
        self.assertFalse(result["runtime_access_stripping_proved"])
        self.assertFalse(result["runtime_access_stripping_disproved"])

    def test_sensitive_raw_fields_are_not_published(self) -> None:
        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key.lower()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        serialized = json.dumps(self.payload).lower()
        published_keys = set(keys(self.payload))
        self.assertNotIn("commandline", published_keys)
        self.assertNotIn("command_line", published_keys)
        self.assertNotIn("commandlines", published_keys)
        self.assertNotIn("launch token", serialized)
        self.assertFalse(self.payload["active_components"]["command_lines_published"])
        self.assertFalse(self.payload["process_handle_table"]["raw_metadata_published"])


class RuntimeCollectorSafetyTests(unittest.TestCase):
    def test_collectors_exclude_mutating_process_and_driver_apis(self) -> None:
        sources = [
            ROOT / "scripts" / "runtime" / "capture_randgrid_runtime.ps1",
            ROOT / "scripts" / "runtime" / "capture_runtime_metrics.ps1",
            ROOT / "scripts" / "runtime" / "snapshot_process_handles.py",
        ]
        forbidden = (
            "DeviceIoControl",
            "OpenProcess(PROCESS_ALL_ACCESS",
            "ReadProcessMemory",
            "WriteProcessMemory",
            "TerminateProcess",
            "Stop-Process",
            "sc.exe stop",
            "NtLoadDriver",
            "NtUnloadDriver",
        )
        for path in sources:
            text = path.read_text(encoding="utf-8")
            for token in forbidden:
                self.assertNotIn(token, text, f"{token} found in {path}")

    def test_snapshot_helper_opens_only_its_own_pid(self) -> None:
        source = (
            ROOT / "scripts" / "runtime" / "snapshot_process_handles.py"
        ).read_text(encoding="utf-8")
        self.assertEqual(source.count("open_process("), 1)
        self.assertIn(
            "open_process(PROCESS_QUERY_LIMITED_INFORMATION, 0, os.getpid())", source
        )


if __name__ == "__main__":
    unittest.main()
