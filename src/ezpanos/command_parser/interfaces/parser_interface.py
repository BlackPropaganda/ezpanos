from __future__ import annotations

from abc import ABC, abstractmethod


class CommandParserInterface(ABC):
    """Stable command-parser contract used by service orchestration."""

    @abstractmethod
    def parse(self, command_str: str) -> str:
        """Convert a plaintext PAN-OS command into XML API command payload."""
