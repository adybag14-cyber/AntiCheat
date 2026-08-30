"""Portable, passive host-observation primitives for systems research."""

from .backend import backend_for_current_platform
from .linux import LinuxProcfsBackend
from .windows import WindowsPassiveBackend

__all__ = [
    "LinuxProcfsBackend",
    "WindowsPassiveBackend",
    "backend_for_current_platform",
]
__version__ = "0.2.0"
