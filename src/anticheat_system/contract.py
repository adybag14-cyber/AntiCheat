"""Backend-neutral snapshot schema invariants."""

from __future__ import annotations

from typing import Any

TARGET_SECTIONS = {
    "identity",
    "status",
    "executable",
    "memory_maps",
    "modules",
    "file_descriptors",
    "namespaces",
    "cgroups",
}

PRIVACY_KEYS = {
    "host_or_user_identity_included",
    "command_line_or_environment_included",
    "raw_memory_addresses_included",
    "raw_file_descriptor_targets_included",
    "raw_module_paths_included",
    "raw_namespace_identifiers_included",
    "raw_cgroup_paths_included",
    "process_ids_included",
    "executable_path_included",
    "user_sid_included",
}

SECTION_STATUSES = {
    "observed",
    "partial",
    "unavailable",
    "not_applicable",
    "not_requested",
}


def validate_snapshot_contract(snapshot: dict[str, Any]) -> None:
    """Raise ValueError/TypeError when a backend violates portable v1."""

    if snapshot.get("schema_version") != 1:
        raise ValueError("portable snapshot schema_version must be 1")
    capture = _mapping(snapshot, "capture")
    if capture.get("kind") != "passive_process_snapshot":
        raise ValueError("portable snapshot has an invalid capture kind")
    if capture.get("read_only") is not True:
        raise ValueError("portable snapshot must assert read_only=true")
    privacy_mode = capture.get("privacy_mode")
    if privacy_mode not in {"aggregate", "local"}:
        raise ValueError("portable snapshot has an invalid privacy mode")
    if not isinstance(capture.get("backend"), str) or not capture["backend"]:
        raise ValueError("portable snapshot backend is missing")
    if not isinstance(capture.get("consistency"), dict):
        raise TypeError("portable snapshot consistency contract is missing")

    target = _mapping(snapshot, "target")
    missing_sections = TARGET_SECTIONS - target.keys()
    if missing_sections:
        raise ValueError(
            f"portable snapshot is missing target sections: {sorted(missing_sections)}"
        )
    for section_name in TARGET_SECTIONS - {"identity"}:
        section = target[section_name]
        if not isinstance(section, dict):
            raise TypeError(f"target section {section_name} must be an object")
        if section.get("status") not in SECTION_STATUSES:
            raise ValueError(f"target section {section_name} has an invalid status")

    privacy = _mapping(snapshot, "privacy")
    missing_privacy = PRIVACY_KEYS - privacy.keys()
    if missing_privacy:
        raise ValueError(
            f"portable snapshot is missing privacy flags: {sorted(missing_privacy)}"
        )
    if any(type(privacy[key]) is not bool for key in PRIVACY_KEYS):
        raise ValueError("portable snapshot privacy flags must be booleans")
    if privacy["host_or_user_identity_included"]:
        raise ValueError("portable snapshots must not include host/user identity")
    if privacy["command_line_or_environment_included"]:
        raise ValueError("portable snapshots must not include command line/environment")

    identity = _mapping(target, "identity")
    executable = _mapping(target, "executable")
    modules = _mapping(target, "modules")
    if privacy_mode == "aggregate":
        if any(
            key in identity
            for key in ("pid", "parent_pid", "start_time_ticks", "creation_time_100ns")
        ):
            raise ValueError("aggregate snapshot contains process identity fields")
        if "path" in executable:
            raise ValueError("aggregate snapshot contains an executable path")
        if "executable_file_basenames" in modules:
            raise ValueError("aggregate snapshot contains module basenames")
        if privacy["process_ids_included"] or privacy["executable_path_included"]:
            raise ValueError("aggregate snapshot privacy flags contradict its mode")
    else:
        if (
            not privacy["process_ids_included"]
            or not privacy["executable_path_included"]
        ):
            raise ValueError("local snapshot privacy flags contradict its mode")
        if "pid" not in identity:
            raise ValueError("local snapshot is missing its selected PID")
        if not any(
            key in identity for key in ("start_time_ticks", "creation_time_100ns")
        ):
            raise ValueError("local snapshot is missing its process identity anchor")

    if not isinstance(snapshot.get("section_errors"), list):
        raise TypeError("portable snapshot section_errors must be a list")
    signals = snapshot.get("signals")
    if not isinstance(signals, list):
        raise TypeError("portable snapshot signals must be a list")
    for signal in signals:
        if (
            not isinstance(signal, dict)
            or not signal.get("code")
            or not signal.get("caveat")
        ):
            raise ValueError("portable snapshot contains an invalid signal")
    summary = _mapping(snapshot, "summary")
    if summary.get("verdict") != "observation_only":
        raise ValueError("portable snapshot must remain observation_only")


def _mapping(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise TypeError(f"portable snapshot {key} must be an object")
    return value
