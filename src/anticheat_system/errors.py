"""Stable error classes and privacy-safe error serialization."""

from __future__ import annotations

import errno


class ProbeError(RuntimeError):
    """A user-facing probe failure with a stable machine-readable code."""

    __slots__ = ("code", "message")

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return self.message


class TargetNotFoundError(ProbeError):
    def __init__(self, selector: str) -> None:
        super().__init__("target_not_found", f"no process matched {selector}")


class TargetAccessDeniedError(ProbeError):
    def __init__(self, selector: str) -> None:
        super().__init__(
            "target_access_denied",
            f"the operating system denied passive metadata access to {selector}",
        )


class AmbiguousTargetError(ProbeError):
    def __init__(self, selector: str, match_count: int) -> None:
        super().__init__(
            "ambiguous_target",
            f"{selector} matched {match_count} processes; select an explicit PID",
        )


class InconsistentSnapshotError(ProbeError):
    def __init__(self, reason: str) -> None:
        super().__init__("inconsistent_snapshot", reason)


class UnsupportedPlatformError(ProbeError):
    def __init__(self, system: str) -> None:
        super().__init__(
            "unsupported_platform",
            f"the passive portable backend is not implemented for {system}",
        )


def classify_os_error(error: OSError) -> str:
    """Map an OS error to a stable reason without leaking local paths."""

    if error.errno in {errno.EACCES, errno.EPERM}:
        return "permission_denied"
    if error.errno in {errno.ENOENT, errno.ESRCH}:
        return "not_found_or_process_exited"
    if error.errno == errno.ENOSYS:
        return "not_supported"
    if error.errno == errno.EOVERFLOW:
        return "size_limit_exceeded"
    return "os_error"


def unavailable(reason: str) -> dict[str, str]:
    """Represent unavailable evidence without failure-as-zero semantics."""

    return {"status": "unavailable", "reason": reason}
