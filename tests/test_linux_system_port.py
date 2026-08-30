from __future__ import annotations

import ast
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from anticheat_system.chain import seal_record, verify_record
from anticheat_system.cli import _write_json_atomic, main, verify_chain_file
from anticheat_system.linux import (
    LinuxProcfsBackend,
    categorize_fd_target,
    parse_proc_cgroup,
    parse_proc_maps,
    parse_proc_stat,
    parse_proc_status,
)
from anticheat_system.signals import derive_signals


class LinuxParserTests(unittest.TestCase):
    def test_proc_stat_handles_spaces_in_comm_and_extracts_identity(self) -> None:
        record = (
            "321 (game worker) S 10 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 7 0 123456 999 10"
        )
        parsed = parse_proc_stat(record)
        self.assertEqual(parsed["pid"], 321)
        self.assertEqual(parsed["comm"], "game worker")
        self.assertEqual(parsed["parent_pid"], 10)
        self.assertEqual(parsed["thread_count"], 7)
        self.assertEqual(parsed["start_time_ticks"], 123456)

    def test_proc_stat_rejects_truncation(self) -> None:
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse_proc_stat("12 (short) S 1 2")

    def test_proc_status_preserves_security_fields(self) -> None:
        parsed = parse_proc_status(
            """Name:\tgame
State:\tS (sleeping)
PPid:\t9
TracerPid:\t44
Uid:\t1000\t1000\t1000\t1000
Gid:\t100\t100\t100\t100
NSpid:\t55\t1
VmSize:\t1234 kB
VmRSS:\t321 kB
VmLck:\t5 kB
Threads:\t8
CapInh:\t0000000000000000
CapPrm:\t0000000000000400
CapEff:\t0000000000000400
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t2
Seccomp_filters:\t3
CoreDumping:\t0
"""
        )
        self.assertEqual(parsed["name"], "game")
        self.assertTrue(parsed["tracer_present"])
        self.assertTrue(parsed["no_new_privileges"])
        self.assertEqual(parsed["seccomp_mode"], 2)
        self.assertEqual(parsed["seccomp_filter_count"], 3)
        self.assertEqual(parsed["memory_kib"]["resident"], 321)
        self.assertEqual(parsed["capabilities"]["effective"], "0x0000000000000400")
        self.assertEqual(parsed["pid_namespace_depth"], 2)
        self.assertEqual(parsed["uid_values"], [1000, 1000, 1000, 1000])

    def test_missing_status_fields_remain_unknown(self) -> None:
        parsed = parse_proc_status("Name:\tminimal\n")
        self.assertIsNone(parsed["tracer_present"])
        self.assertIsNone(parsed["no_new_privileges"])
        self.assertIsNone(parsed["seccomp_mode"])

    def test_maps_are_aggregated_without_addresses_or_paths(self) -> None:
        parsed = parse_proc_maps(
            """00400000-00452000 r-xp 00000000 08:01 100 /opt/game/game
00651000-00652000 rw-p 00051000 08:01 100 /opt/game/game
7f000000-7f001000 rwxp 00000000 00:00 0
7f001000-7f002000 r-xp 00000000 08:01 200 /tmp/plugin.so (deleted)
7f002000-7f003000 rw-p 00000000 00:00 0 [heap]
""",
            include_basenames=True,
        )
        self.assertEqual(parsed["mapping_count"], 5)
        self.assertEqual(parsed["unique_file_count"], 2)
        self.assertEqual(parsed["unique_executable_file_count"], 2)
        self.assertEqual(parsed["writable_executable_mapping_count"], 1)
        self.assertEqual(parsed["deleted_mapping_count"], 1)
        self.assertEqual(parsed["deleted_executable_mapping_count"], 1)
        self.assertEqual(parsed["executable_file_basenames"], ["game", "plugin.so"])
        serialized = json.dumps(parsed)
        self.assertNotIn("00400000", serialized)
        self.assertNotIn("/opt/game", serialized)

    def test_malformed_map_line_is_not_counted_as_a_valid_zero(self) -> None:
        parsed = parse_proc_maps("this is not a maps row\n")
        self.assertEqual(parsed["mapping_count"], 0)
        self.assertEqual(parsed["malformed_line_count"], 1)

    def test_file_descriptor_targets_are_only_categorized(self) -> None:
        cases = {
            "socket:[123]": "socket",
            "pipe:[456]": "pipe",
            "anon_inode:[eventpoll]": "anonymous_inode",
            "/memfd:jit-cache (deleted)": "memory_file",
            "/tmp/old.so (deleted)": "deleted_file",
            "/var/lib/data": "filesystem",
            "net:[1]": "other",
        }
        self.assertEqual(
            {target: categorize_fd_target(target) for target in cases}, cases
        )

    def test_cgroup_paths_are_reduced_to_aggregates(self) -> None:
        parsed = parse_proc_cgroup("0::/user.slice/private.scope\n")
        self.assertEqual(parsed["version"], 2)
        self.assertEqual(parsed["membership_count"], 1)
        self.assertEqual(parsed["non_root_membership_count"], 1)
        self.assertFalse(parsed["raw_paths_included"])
        self.assertNotIn("private.scope", json.dumps(parsed))


class LinuxBackendSafetyTests(unittest.TestCase):
    def test_backend_contains_no_mutating_or_active_instrumentation_calls(self) -> None:
        source_path = ROOT / "src" / "anticheat_system" / "linux.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        qualified_calls: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                qualified_calls.add(f"{node.func.value.id}.{node.func.attr}")
            elif isinstance(node.func, ast.Name):
                qualified_calls.add(node.func.id)
        forbidden = {
            "os.kill",
            "os.system",
            "subprocess.run",
            "subprocess.Popen",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "pidfd_send_signal",
            "bpf",
        }
        self.assertTrue(
            forbidden.isdisjoint(qualified_calls), qualified_calls & forbidden
        )
        source = source_path.read_text(encoding="utf-8")
        self.assertNotIn("os.O_WRONLY", source)
        self.assertNotIn("os.O_RDWR", source)


class SignalContractTests(unittest.TestCase):
    def test_signals_are_caveated_observations_not_verdicts(self) -> None:
        snapshot = {
            "target": {
                "status": {
                    "status": "observed",
                    "tracer_present": True,
                    "capabilities": {"effective": "0x0000000000000001"},
                },
                "memory_maps": {
                    "status": "observed",
                    "writable_executable_mapping_count": 2,
                    "deleted_executable_mapping_count": 1,
                },
                "executable": {"status": "observed", "deleted": True},
                "namespaces": {
                    "status": "observed",
                    "different_from_observer_count": 2,
                },
            }
        }
        signals = derive_signals(snapshot)
        self.assertEqual(
            {signal["code"] for signal in signals},
            {
                "tracer_attached",
                "writable_executable_mappings",
                "deleted_executable_mappings",
                "deleted_main_executable",
                "namespace_isolation",
                "effective_linux_capabilities",
            },
        )
        self.assertTrue(all(signal["caveat"] for signal in signals))

    def test_unavailable_maps_do_not_create_false_signals(self) -> None:
        snapshot = {
            "target": {
                "status": {"status": "unavailable", "reason": "permission_denied"},
                "memory_maps": {
                    "status": "unavailable",
                    "reason": "permission_denied",
                },
                "executable": {"status": "unavailable"},
                "namespaces": {"status": "unavailable"},
            }
        }
        self.assertEqual(derive_signals(snapshot), [])


class HashChainTests(unittest.TestCase):
    def test_records_chain_and_tampering_is_detected(self) -> None:
        first = seal_record(sequence=0, previous_sha256=None, payload={"sample": 1})
        second = seal_record(
            sequence=1,
            previous_sha256=first["record_sha256"],
            payload={"sample": 2},
        )
        self.assertTrue(verify_record(first, expected_sequence=0, previous_sha256=None))
        self.assertTrue(
            verify_record(
                second,
                expected_sequence=1,
                previous_sha256=first["record_sha256"],
            )
        )
        second["record_schema_version"] = 2
        self.assertFalse(
            verify_record(
                second,
                expected_sequence=1,
                previous_sha256=first["record_sha256"],
            )
        )
        second["record_schema_version"] = 1
        second["payload"]["sample"] = 999
        self.assertFalse(
            verify_record(
                second,
                expected_sequence=1,
                previous_sha256=first["record_sha256"],
            )
        )

    def test_chain_verifier_rejects_an_incomplete_monitor_run(self) -> None:
        payload = {
            "monitor": {
                "planned_sample_count": 2,
                "sample_sequence": 0,
                "interval_seconds": 1.0,
            }
        }
        record = seal_record(sequence=0, previous_sha256=None, payload=payload)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "incomplete.jsonl"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8", newline="\n")
            with self.assertRaisesRegex(ValueError, "incomplete monitor chain"):
                verify_chain_file(path)


class OutputSafetyTests(unittest.TestCase):
    def test_snapshot_output_never_replaces_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text("sentinel\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                _write_json_atomic(path, {"new": True}, force=False)
            self.assertEqual(path.read_text(encoding="utf-8"), "sentinel\n")
            _write_json_atomic(path, {"new": True}, force=True)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")), {"new": True}
            )


@unittest.skipUnless(platform.system() == "Linux", "requires Linux procfs")
class LinuxLiveContractTests(unittest.TestCase):
    def test_live_self_snapshot_is_consistent_and_privacy_reduced(self) -> None:
        backend = LinuxProcfsBackend()
        payload = backend.capture(os.getpid(), privacy_mode="aggregate")
        self.assertEqual(payload["schema_version"], 1)
        self.assertTrue(payload["capture"]["read_only"])
        self.assertTrue(payload["capture"]["consistency"]["start_time_stable"])
        self.assertTrue(payload["capture"]["consistency"]["process_directory_anchored"])
        self.assertEqual(payload["summary"]["verdict"], "observation_only")
        self.assertNotIn("pid", payload["target"]["identity"])
        self.assertNotIn("path", payload["target"]["executable"])
        self.assertNotIn("parent_pid", payload["target"]["status"])
        self.assertNotIn("uid_values", payload["target"]["status"])
        self.assertNotIn("gid_values", payload["target"]["status"])
        self.assertNotIn("executable_file_basenames", payload["target"]["memory_maps"])
        self.assertFalse(payload["privacy"]["raw_memory_addresses_included"])
        self.assertFalse(payload["privacy"]["raw_file_descriptor_targets_included"])
        self.assertEqual(payload["target"]["memory_maps"]["status"], "observed")
        self.assertGreater(payload["target"]["memory_maps"]["mapping_count"], 0)
        self.assertEqual(
            payload["target"]["executable"]["integrity"]["status"], "observed"
        )

    def test_cli_snapshot_and_bounded_monitor_are_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "snapshot.json"
            monitor_path = Path(directory) / "monitor.jsonl"
            self.assertEqual(
                main(
                    [
                        "snapshot",
                        "--self",
                        "--no-hash-executable",
                        "--out",
                        str(snapshot_path),
                    ]
                ),
                0,
            )
            self.assertTrue(
                json.loads(snapshot_path.read_text())["capture"]["read_only"]
            )
            self.assertEqual(
                main(
                    [
                        "monitor",
                        "--self",
                        "--no-hash-executable",
                        "--samples",
                        "2",
                        "--interval",
                        "0",
                        "--out",
                        str(monitor_path),
                    ]
                ),
                0,
            )
            verification = verify_chain_file(monitor_path)
            self.assertEqual(verification["record_count"], 2)
            self.assertRegex(verification["terminal_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
