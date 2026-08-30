"""Conservative observations derived from a passive snapshot.

Signals are triage hints, never proof of cheating or malicious intent. Legitimate
debuggers, JITs, crash handlers, containers, and deleted-on-upgrade libraries can
produce the same observations.
"""

from __future__ import annotations

import collections
from typing import Any


def derive_signals(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    target = snapshot.get("target", {})
    status = target.get("status", {})
    maps = target.get("memory_maps", {})
    executable = target.get("executable", {})
    namespaces = target.get("namespaces", {})
    signals: list[dict[str, Any]] = []

    if status.get("status") == "observed" and status.get("tracer_present") is True:
        signals.append(
            _signal(
                "tracer_attached",
                "medium",
                "The kernel reports a tracer for the target process.",
                "A debugger or crash handler can be legitimate; correlate with policy and launch context.",
            )
        )

    debugger = status.get("debugger_present", {})
    if (
        isinstance(debugger, dict)
        and debugger.get("status") == "observed"
        and debugger.get("present") is True
    ):
        signals.append(
            _signal(
                "debugger_attached",
                "medium",
                "Windows reports a user-mode debugger for the target process.",
                "A debugger or crash-analysis tool can be legitimate; correlate with launch policy.",
            )
        )

    if maps.get("status") == "observed":
        writable_executable = maps.get("writable_executable_mapping_count", 0)
        if writable_executable:
            signals.append(
                _signal(
                    "writable_executable_mappings",
                    "high",
                    f"Observed {writable_executable} writable-and-executable mappings.",
                    "JIT runtimes can create these mappings; inspect provenance before drawing a conclusion.",
                )
            )
        deleted_executable = maps.get("deleted_executable_mapping_count", 0)
        if deleted_executable:
            signals.append(
                _signal(
                    "deleted_executable_mappings",
                    "medium",
                    f"Observed {deleted_executable} executable mappings backed by deleted files.",
                    "Package upgrades can leave deleted mappings; compare file identity over time.",
                )
            )

    if executable.get("status") == "observed" and executable.get("deleted") is True:
        signals.append(
            _signal(
                "deleted_main_executable",
                "high",
                "The target's main executable link is marked deleted.",
                "Confirm whether this is an expected in-place software update.",
            )
        )

    if namespaces.get("status") == "observed":
        different = namespaces.get("different_from_observer_count", 0)
        if different:
            signals.append(
                _signal(
                    "namespace_isolation",
                    "info",
                    f"The target differs from the observer in {different} Linux namespaces.",
                    "Containers and sandboxed launchers normally use distinct namespaces.",
                )
            )

    capabilities = (
        status.get("capabilities", {}) if status.get("status") == "observed" else {}
    )
    effective = capabilities.get("effective")
    if effective and int(effective, 16) != 0:
        signals.append(
            _signal(
                "effective_linux_capabilities",
                "info",
                "The target has one or more effective Linux capabilities.",
                "Service processes may legitimately run with a narrow capability set.",
            )
        )

    return signals


def _signal(code: str, severity: str, observation: str, caveat: str) -> dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "observation": observation,
        "caveat": caveat,
    }


def summarize_signals(signals: list[dict[str, Any]]) -> dict[str, Any]:
    rank = {"none": 0, "info": 1, "low": 2, "medium": 3, "high": 4}
    highest = "none"
    counts: collections.Counter[str] = collections.Counter()
    for signal in signals:
        severity = signal["severity"]
        counts[severity] += 1
        if rank[severity] > rank[highest]:
            highest = severity
    return {
        "highest_signal_severity": highest,
        "signal_count": len(signals),
        "severity_counts": dict(sorted(counts.items())),
        "verdict": "observation_only",
    }
