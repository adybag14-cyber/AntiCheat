from __future__ import annotations

import copy
import json
import os
import platform
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import anticheat_system
from anticheat_system.backend import backend_for_current_platform
from anticheat_system.contract import (
    PRIVACY_KEYS,
    TARGET_SECTIONS,
    validate_snapshot_contract,
)


@unittest.skipUnless(
    platform.system() in {"Linux", "Windows"}, "requires a supported platform"
)
class PortableCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = backend_for_current_platform().capture(
            os.getpid(), privacy_mode="aggregate", hash_executable=False
        )

    def test_supported_python_and_package_version(self) -> None:
        self.assertGreaterEqual(sys.version_info, (3, 11))
        self.assertRegex(anticheat_system.__version__, r"^\d+\.\d+\.\d+$")

    def test_backend_neutral_sections_and_privacy_keys_are_complete(self) -> None:
        self.assertTrue(TARGET_SECTIONS.issubset(self.payload["target"]))
        self.assertTrue(PRIVACY_KEYS.issubset(self.payload["privacy"]))
        validate_snapshot_contract(self.payload)

    def test_snapshot_is_strict_json_round_trip_safe(self) -> None:
        serialized = json.dumps(
            self.payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
        )
        self.assertEqual(json.loads(serialized), self.payload)

    def test_contract_rejects_missing_sections(self) -> None:
        invalid = copy.deepcopy(self.payload)
        del invalid["target"]["modules"]
        with self.assertRaisesRegex(ValueError, "missing target sections"):
            validate_snapshot_contract(invalid)

    def test_contract_rejects_aggregate_identity_leaks(self) -> None:
        invalid = copy.deepcopy(self.payload)
        invalid["target"]["identity"]["pid"] = os.getpid()
        with self.assertRaisesRegex(ValueError, "process identity fields"):
            validate_snapshot_contract(invalid)


if __name__ == "__main__":
    unittest.main()
