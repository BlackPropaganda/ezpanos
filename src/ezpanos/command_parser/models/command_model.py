from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TokenizedCommand:
    raw_command: str
    tokens: tuple[str, ...]


@dataclass(frozen=True)
class ParserKnowledge:
    value_key_paths: frozenset[tuple[str, ...]]
    root_value_keys: dict[str, frozenset[str]]
    root_ambiguous_keys: dict[str, frozenset[str]]
    root_literal_tokens: dict[str, frozenset[str]]
    known_roots: frozenset[str]
    source_path: Path | None = None
