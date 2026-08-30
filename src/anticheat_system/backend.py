"""Platform backend selection and the shared capture protocol."""

from __future__ import annotations

import platform
from typing import Any, Protocol

from .errors import UnsupportedPlatformError


class SystemCaptureBackend(Protocol):
    backend_name: str

    def resolve_pid(
        self,
        *,
        pid: int | None = None,
        name: str | None = None,
        self_process: bool = False,
    ) -> int: ...

    def capture(
        self,
        pid: int,
        *,
        privacy_mode: str = "aggregate",
        hash_executable: bool = True,
    ) -> dict[str, Any]: ...


def backend_for_current_platform(
    system: str | None = None,
) -> SystemCaptureBackend:
    selected = system or platform.system()
    if selected == "Linux":
        from .linux import LinuxProcfsBackend

        return LinuxProcfsBackend()
    if selected == "Windows":
        from .windows import WindowsPassiveBackend

        return WindowsPassiveBackend()
    raise UnsupportedPlatformError(selected)
