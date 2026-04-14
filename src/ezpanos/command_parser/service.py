from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ezpanos.command_parser.providers.ops_provider import OpsCommandParser


class CommandParserService:
    """Orchestrates parser configuration and provider selection."""

    def __init__(
        self,
        config_path: Path | None = None,
        command_tree_path: Path | None = None,
    ):
        self._module_dir = Path(__file__).resolve().parent
        self._config = self._load_config(config_path)
        resolved_tree_path = self._resolve_command_tree_path(command_tree_path)

        knowledge = OpsCommandParser.build_knowledge(
            command_tree_path=resolved_tree_path,
            known_roots=self._config.get("known_root_commands", []),
        )

        compatibility = self._config.get("compatibility", {})
        infer_software_version = bool(
            compatibility.get("infer_request_system_software_version", True)
        )
        self._provider = OpsCommandParser(
            knowledge=knowledge,
            infer_request_system_software_version=infer_software_version,
        )

    def parse(self, command_str: str) -> str:
        return self._provider.parse(command_str)

    def _load_config(self, config_path: Path | None) -> dict[str, Any]:
        candidate = config_path or (self._module_dir / "config.json")
        if not candidate.exists():
            return {}

        with candidate.open("r", encoding="utf-8") as handle:
            parsed = json.load(handle)
            return parsed if isinstance(parsed, dict) else {}

    def _resolve_command_tree_path(self, command_tree_path: Path | None) -> Path | None:
        # Precedence: explicit arg -> env var -> component config -> None
        if command_tree_path:
            return command_tree_path

        env_path = os.getenv("EZPANOS_COMMAND_TREE_PATH", "").strip()
        if env_path:
            return Path(env_path)

        configured_path = str(self._config.get("command_tree_path", "")).strip()
        if not configured_path:
            return None

        configured = Path(configured_path)
        if configured.is_absolute():
            return configured

        # Resolve from repository root when available, otherwise current working directory.
        repo_root_candidate = self._module_dir.parents[2] / configured
        if repo_root_candidate.exists():
            return repo_root_candidate

        cwd_candidate = Path.cwd() / configured
        if cwd_candidate.exists():
            return cwd_candidate

        return repo_root_candidate


_DEFAULT_PARSER_SERVICE: CommandParserService | None = None


def _get_default_service() -> CommandParserService:
    global _DEFAULT_PARSER_SERVICE
    if _DEFAULT_PARSER_SERVICE is None:
        _DEFAULT_PARSER_SERVICE = CommandParserService()
    return _DEFAULT_PARSER_SERVICE


def parse_command_to_xml(command_str: str) -> str:
    return _get_default_service().parse(command_str)
