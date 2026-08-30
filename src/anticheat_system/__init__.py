"""Portable, passive host-observation primitives for systems research."""

from .linux import LinuxProcfsBackend

__all__ = ["LinuxProcfsBackend"]
__version__ = "0.1.0"
