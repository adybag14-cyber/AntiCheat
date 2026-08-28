from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts.runtime import analyze_randgrid_runtime as analyzer

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_EVIDENCE = ROOT / "evidence" / "randgrid-runtime-passive-summary.json"
ELEVATED_EVIDENCE = ROOT / "evidence" / "randgrid-runtime-elevated-summary.json"


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
            ROOT / "scripts" / "runtime" / "analyze_randgrid_runtime.py",
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

    def test_ob_capture_uses_an_independent_exactly_named_session(self) -> None:
        source = (
            ROOT / "scripts" / "runtime" / "capture_randgrid_runtime.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("-systemlogger -independent", source)
        self.assertIn("-eflag PROC_THREAD+LOADER+OB_HANDLE", source)
        self.assertIn("-stop $script:ObSessionName", source)
        self.assertNotIn("-stop 'NT Kernel Logger'", source)
        self.assertNotIn('-stop "NT Kernel Logger"', source)


class ElevatedRuntimeEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads(ELEVATED_EVIDENCE.read_text(encoding="utf-8"))

    def test_capture_and_decoders_completed_without_loss(self) -> None:
        capture = self.payload["capture"]
        self.assertEqual(capture["capture_phase"], "complete")
        self.assertTrue(capture["administrator"])
        self.assertFalse(capture["raw_artifacts_published"])
        self.assertTrue(all(code == 0 for code in capture["decoder_exit_codes"].values()))
        self.assertEqual(self.payload["trace"]["events_lost"], 0)
        self.assertEqual(self.payload["ob_handle_trace"]["events_lost"], 0)

    def test_driver_identity_is_unchanged(self) -> None:
        driver = self.payload["driver"]
        self.assertEqual(
            driver["sha256"],
            "4150290A810EBEBE9F9E6B5BD32C60299F9F34C3D2B6F02B89590ED49A6B895E",
        )
        self.assertEqual(driver["state"], "Running")
        self.assertEqual(driver["signature_status"], "Valid")

    def test_target_open_counts_and_results(self) -> None:
        target = self.payload["target_process"]
        self.assertEqual(target["process_open_count"], 2218)
        self.assertEqual(target["external_process_open_count"], 2218)
        self.assertEqual(target["process_open_success_count"], 2218)
        self.assertEqual(target["process_open_failure_count"], 0)
        self.assertEqual(target["thread_open_count"], 133)
        self.assertEqual(target["external_thread_open_count"], 0)

    def test_exact_object_and_rundown_correlation(self) -> None:
        exact = self.payload["exact_ob_correlation"]
        self.assertEqual(exact["status"], "exact-event-correlation")
        self.assertEqual(exact["matched_audit_events"], 2208)
        self.assertEqual(exact["unmatched_audit_events"], 10)
        self.assertEqual(exact["dominant_target_object_matches"], 2208)
        self.assertEqual(exact["dominant_target_object_ratio"], 1.0)
        self.assertLessEqual(exact["match_delta_us"]["p95_absolute"], 1.0)
        persistent = exact["persistent_handles"]
        self.assertEqual(persistent["snapshot_baseline_count"], 41)
        self.assertEqual(persistent["snapshot_final_count"], 41)
        self.assertEqual(persistent["ob_rundown_count"], 41)
        self.assertEqual(persistent["final_snapshot_rundown_tuple_overlap"], 41)

    def test_short_lifetimes_explain_absent_exact_mask_pairs(self) -> None:
        exact = self.payload["exact_ob_correlation"]
        events = exact["target_handle_events"]
        self.assertEqual(events["create_count"], 2250)
        self.assertEqual(events["close_count"], 2250)
        self.assertEqual(events["lifetime_us"]["median"], 4.0)
        self.assertEqual(events["lifetime_us"]["p95"], 11.0)
        self.assertEqual(events["lifetime_us"]["max"], 127.0)
        self.assertEqual(exact["exact_requested_granted_pair_count"], 0)
        self.assertFalse(self.payload["conclusion"]["runtime_access_stripping_proved"])
        self.assertFalse(self.payload["conclusion"]["runtime_access_stripping_disproved"])

    def test_persistent_owner_masks_preserve_selective_pattern(self) -> None:
        owners = {
            row["owner_name"]: row
            for row in self.payload["exact_ob_correlation"]["persistent_handles"][
                "baseline_owners"
            ]
        }
        self.assertEqual(owners["System"]["handle_count"], 14)
        self.assertEqual(owners["NahimicSvc64.exe"]["handle_count"], 5)
        self.assertEqual(
            owners["NahimicSvc64.exe"]["granted_access"][0]["mask"], "0x00001000"
        )
        self.assertEqual(owners["NahimicSvc32.exe"]["handle_count"], 1)

    def test_literal_hiding_is_rejected_without_overclaiming_stripping(self) -> None:
        conclusion = self.payload["conclusion"]
        self.assertTrue(conclusion["target_process_object_identified_at_runtime"])
        self.assertFalse(conclusion["universal_literal_handle_hiding_supported"])
        self.assertFalse(conclusion["runtime_access_stripping_proved"])
        self.assertFalse(conclusion["runtime_access_stripping_disproved"])

    def test_public_aggregate_excludes_raw_identifiers(self) -> None:
        serialized = json.dumps(self.payload)

        def keys(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield key.lower()
                    yield from keys(child)
            elif isinstance(value, list):
                for child in value:
                    yield from keys(child)

        published_keys = set(keys(self.payload))
        self.assertNotIn("caller_pid", published_keys)
        self.assertNotIn("owner_pid", published_keys)
        self.assertNotIn("target_pid", published_keys)
        self.assertNotIn("object_pointer", published_keys)
        self.assertNotRegex(serialized, re.compile(r"0x[fF]{4}[0-9A-Fa-f]{12}"))
        self.assertNotRegex(serialized, re.compile(r"[A-Za-z]:\\\\Users\\\\"))


class RuntimeAnalyzerParsingTests(unittest.TestCase):
    def test_process_and_thread_access_masks_use_distinct_rights(self) -> None:
        self.assertEqual(
            analyzer.decode_access(0x410, "process"),
            ["vm_read", "query_information"],
        )
        self.assertEqual(
            analyzer.decode_access(0x48, "thread"),
            ["get_context", "query_information"],
        )

    def test_audit_line_parser_distinguishes_process_and_thread_opens(self) -> None:
        process_line = (
            'Microsoft-Windows-Kernel-Audit-API-Calls//win:Info, 123, '
            '"Unknown" ( 42), 99, 1, , , , , "TargetProcessId : 7", '
            '"DesiredAccess : 1040", "ReturnCode : 0"'
        )
        thread_line = (
            'Microsoft-Windows-Kernel-Audit-API-Calls//win:Info, 124, '
            '"Unknown" ( 42), 99, 1, , , , , "TargetProcessId : 7", '
            '"TargetThreatId : 8", "DesiredAccess : 72", "ReturnCode : 0"'
        )
        process = analyzer.parse_audit_line(process_line)
        thread = analyzer.parse_audit_line(thread_line)
        self.assertIsNotNone(process)
        self.assertIsNotNone(thread)
        self.assertEqual(process.event_id, analyzer.PROCESS_OPEN_EVENT_ID)
        self.assertEqual(thread.event_id, analyzer.THREAD_OPEN_EVENT_ID)

    def test_kernel_handle_normalization_matches_table_values(self) -> None:
        self.assertEqual(analyzer.normalize_handle(0x8000CAB4), 0xCAB4)
        self.assertEqual(analyzer.normalize_handle(0x1788), 0x1788)


if __name__ == "__main__":
    unittest.main()
