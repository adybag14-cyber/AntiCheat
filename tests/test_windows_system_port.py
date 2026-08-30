from __future__ import annotations

import ast
import ctypes
import json
import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import anticheat_system.windows as windows_backend
from anticheat_system.backend import backend_for_current_platform
from anticheat_system.cli import main, verify_chain_file
from anticheat_system.errors import UnsupportedPlatformError
from anticheat_system.windows import (
    MEMORY_BASIC_INFORMATION,
    MODULEENTRY32W,
    PROCESSENTRY32W,
    WindowsPassiveBackend,
    classify_windows_error,
)


class WindowsPortableContractTests(unittest.TestCase):
    def test_win32_errors_have_stable_non_path_reasons(self) -> None:
        self.assertEqual(classify_windows_error(5), "permission_denied")
        self.assertEqual(classify_windows_error(87), "not_found_or_process_exited")
        self.assertEqual(
            classify_windows_error(299), "architecture_or_access_restricted"
        )
        self.assertEqual(classify_windows_error(24), "transient_snapshot_error")
        self.assertEqual(classify_windows_error(120), "not_supported")
        self.assertEqual(classify_windows_error(99999), "win32_error")

    def test_unsupported_platform_fails_explicitly(self) -> None:
        with self.assertRaises(UnsupportedPlatformError):
            backend_for_current_platform("Darwin")

    def test_optional_architecture_apis_degrade_individually(self) -> None:
        with (
            mock.patch.object(windows_backend, "_IsWow64Process2", None),
            mock.patch.object(windows_backend, "_GetProcessInformation", None),
        ):
            result = windows_backend._query_architecture(1)
        self.assertEqual(result, {"status": "unavailable", "reason": "not_supported"})

    def test_windows_backend_has_no_active_or_mutating_apis(self) -> None:
        source_path = ROOT / "src" / "anticheat_system" / "windows.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = {
            f"{node.func.value.id}.{node.func.attr}"
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
        }
        forbidden_calls = {
            "os.kill",
            "os.system",
            "subprocess.Popen",
            "subprocess.run",
        }
        forbidden_win32 = {
            "AdjustTokenPrivileges",
            "CreateRemoteThread",
            "DebugActiveProcess",
            "DeviceIoControl",
            "ReadProcessMemory",
            "TerminateProcess",
            "VirtualAllocEx",
            "VirtualProtectEx",
            "WriteProcessMemory",
        }
        self.assertTrue(forbidden_calls.isdisjoint(names))
        self.assertTrue(forbidden_win32.isdisjoint(source.split()))
        for forbidden in forbidden_win32:
            self.assertNotIn(f'"{forbidden}"', source)
        self.assertNotIn("PROCESS_VM_READ", source)
        self.assertNotIn("PROCESS_VM_WRITE", source)


@unittest.skipUnless(platform.system() == "Windows", "requires Windows APIs")
class WindowsLiveContractTests(unittest.TestCase):
    def test_ctypes_structures_match_32_and_64_bit_windows_abi(self) -> None:
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        self.assertEqual(ctypes.sizeof(PROCESSENTRY32W), {4: 556, 8: 568}[pointer_size])
        self.assertEqual(
            ctypes.sizeof(MODULEENTRY32W), {4: 1064, 8: 1080}[pointer_size]
        )
        self.assertEqual(
            ctypes.sizeof(MEMORY_BASIC_INFORMATION), {4: 28, 8: 48}[pointer_size]
        )

    def test_factory_selects_native_windows_backend(self) -> None:
        backend = backend_for_current_platform()
        self.assertIsInstance(backend, WindowsPassiveBackend)
        self.assertEqual(backend.backend_name, "windows-passive-v1")

    def test_process_discovery_is_case_insensitive_and_contains_self(self) -> None:
        backend = WindowsPassiveBackend()
        name = Path(sys.executable).name.swapcase()
        self.assertIn(os.getpid(), backend.find_processes(name))
        self.assertEqual(backend.resolve_pid(self_process=True), os.getpid())

    def test_live_self_snapshot_has_windows_parity_and_aggregate_privacy(self) -> None:
        payload = WindowsPassiveBackend().capture(
            os.getpid(), privacy_mode="aggregate", hash_executable=True
        )
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["capture"]["backend"], "windows-passive-v1")
        self.assertTrue(payload["capture"]["read_only"])
        consistency = payload["capture"]["consistency"]
        self.assertTrue(consistency["process_handle_anchored"])
        self.assertTrue(consistency["creation_time_stable"])
        self.assertTrue(consistency["process_alive_after_capture"])
        self.assertTrue(consistency["information_handle_identity_verified"])

        target = payload["target"]
        self.assertNotIn("pid", target["identity"])
        self.assertNotIn("parent_pid", target["identity"])
        self.assertNotIn("path", target["executable"])
        self.assertEqual(target["executable"]["integrity"]["status"], "observed")
        self.assertEqual(target["memory_maps"]["status"], "observed")
        self.assertTrue(target["memory_maps"]["complete"])
        self.assertGreater(target["memory_maps"]["mapping_count"], 0)
        self.assertEqual(target["modules"]["status"], "observed")
        self.assertGreater(target["modules"]["module_count"], 0)
        self.assertNotIn("executable_file_basenames", target["modules"])
        self.assertEqual(target["file_descriptors"]["status"], "observed")
        self.assertGreater(target["file_descriptors"]["descriptor_count"], 0)

        status = target["status"]
        self.assertNotIn("creation_time_100ns", status["times"])
        self.assertEqual(status["debugger_present"]["status"], "observed")
        self.assertIsInstance(status["debugger_present"]["present"], bool)
        self.assertEqual(status["architecture"]["status"], "observed")
        self.assertEqual(status["token"]["status"], "observed")
        self.assertEqual(status["token"]["integrity"]["status"], "observed")
        self.assertFalse(status["token"]["user_sid_included"])
        self.assertEqual(status["protection"]["status"], "observed")
        self.assertEqual(status["mitigations"]["status"], "observed")
        self.assertEqual(
            payload["host_security"]["code_integrity"]["status"], "observed"
        )
        self.assertFalse(payload["host_security"]["writes_performed"])
        self.assertEqual(payload["summary"]["verdict"], "observation_only")

    def test_local_mode_is_explicit_about_additional_identifiers(self) -> None:
        payload = WindowsPassiveBackend().capture(
            os.getpid(), privacy_mode="local", hash_executable=False
        )
        self.assertEqual(payload["target"]["identity"]["pid"], os.getpid())
        self.assertIn("parent_pid", payload["target"]["identity"])
        self.assertIn("creation_time_100ns", payload["target"]["identity"])
        self.assertIn("path", payload["target"]["executable"])
        self.assertIn("executable_file_basenames", payload["target"]["modules"])
        self.assertTrue(payload["privacy"]["process_ids_included"])
        self.assertTrue(payload["privacy"]["executable_path_included"])

    def test_cli_snapshot_and_monitor_work_natively_on_windows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            snapshot_path = Path(directory) / "windows-snapshot.json"
            monitor_path = Path(directory) / "windows-monitor.jsonl"
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
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            self.assertEqual(snapshot["capture"]["backend"], "windows-passive-v1")
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
            self.assertEqual(verification["planned_record_count"], 2)


if __name__ == "__main__":
    unittest.main()
