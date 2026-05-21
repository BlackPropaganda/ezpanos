from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
from typing import Iterable
from xml.sax.saxutils import escape as xml_escape

from ezpanos.command_parser.models.command_model import ParserKnowledge
from ezpanos.command_parser.providers.base_provider import BaseCommandParser
from ezpanos.command_parser.validators.command_validator import is_xml_tag_name, tokenize_command

_PLACEHOLDER_TOKEN_RE = re.compile(r"<[^>]+>")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9_.-]+)?$")


class OpsCommandParser(BaseCommandParser):
    """Command parser for PAN-OS operational command strings."""
    _TERMINAL_LEAF_VALUE_HINTS: dict[str, frozenset[str]] = {
        "interface": frozenset({"all", "management", "hardware", "logical"}),
    }

    def __init__(
        self,
        knowledge: ParserKnowledge,
        infer_request_system_software_version: bool = True,
    ):
        super().__init__(knowledge)
        self.infer_request_system_software_version = bool(infer_request_system_software_version)
        self._root_handlers = {
            "clear": self._parse_clear,
            "show": self._parse_show,
            "set": self._parse_set,
            "delete": self._parse_delete,
            "schedule": self._parse_schedule,
            "target": self._parse_target,
            "request": self._parse_request,
            "debug": self._parse_debug,
            "find": self._parse_find,
        }

    @classmethod
    def build_knowledge(
        cls,
        command_tree_path: Path | None,
        known_roots: Iterable[str] | None = None,
    ) -> ParserKnowledge:
        value_key_paths: set[tuple[str, ...]] = set()
        root_value_keys: dict[str, set[str]] = defaultdict(set)
        root_branch_keys: dict[str, set[str]] = defaultdict(set)
        root_literal_tokens: dict[str, set[str]] = defaultdict(set)
        roots = {str(root).strip().lower() for root in (known_roots or []) if str(root).strip()}

        if command_tree_path and command_tree_path.exists():
            for line in command_tree_path.read_text(encoding="utf-8").splitlines():
                tokens = cls._tokenize_template_line(line)
                if not tokens:
                    continue

                literal_path: list[str] = []
                for index, token in enumerate(tokens):
                    if cls._is_template_placeholder(token):
                        continue

                    literal = cls._normalize_literal_token(token)
                    if not literal:
                        continue

                    current_path = tuple(literal_path + [literal])
                    if not literal_path:
                        roots.add(literal)
                    root_literal_tokens[current_path[0]].add(literal)

                    next_token = tokens[index + 1] if index + 1 < len(tokens) else ""
                    if cls._is_template_placeholder(next_token):
                        value_key_paths.add(current_path)
                        root_value_keys[current_path[0]].add(literal)
                    else:
                        root_branch_keys[current_path[0]].add(literal)

                    literal_path.append(literal)

        ambiguous_by_root: dict[str, set[str]] = {}
        for root_name, key_tokens in root_value_keys.items():
            ambiguous_by_root[root_name] = set(key_tokens).intersection(root_branch_keys.get(root_name, set()))

        normalized_root_value_keys: dict[str, frozenset[str]] = {}
        normalized_ambiguous: dict[str, frozenset[str]] = {}
        normalized_root_literals: dict[str, frozenset[str]] = {}
        all_roots = set(roots).union(root_value_keys).union(root_branch_keys).union(root_literal_tokens)
        for root_name in all_roots:
            normalized_root_value_keys[root_name] = frozenset(root_value_keys.get(root_name, set()))
            normalized_ambiguous[root_name] = frozenset(ambiguous_by_root.get(root_name, set()))
            normalized_root_literals[root_name] = frozenset(root_literal_tokens.get(root_name, set()))

        return ParserKnowledge(
            value_key_paths=frozenset(value_key_paths),
            root_value_keys=normalized_root_value_keys,
            root_ambiguous_keys=normalized_ambiguous,
            root_literal_tokens=normalized_root_literals,
            known_roots=frozenset(sorted(roots)),
            source_path=command_tree_path if command_tree_path and command_tree_path.exists() else None,
        )

    @staticmethod
    def _tokenize_template_line(line: str) -> list[str]:
        stripped = str(line or "").strip()
        if not stripped or stripped.startswith("#"):
            return []

        tokens = []
        in_placeholder = False
        placeholder_parts: list[str] = []

        for token in stripped.split():
            if token in {"[", "]"}:
                continue
            if in_placeholder:
                placeholder_parts.append(token)
                if ">" in token:
                    tokens.append(" ".join(placeholder_parts))
                    placeholder_parts = []
                    in_placeholder = False
                continue

            if token.startswith("<") and ">" not in token:
                in_placeholder = True
                placeholder_parts = [token]
                continue

            tokens.append(token)

        if placeholder_parts:
            tokens.append(" ".join(placeholder_parts))
        return tokens

    @staticmethod
    def _is_template_placeholder(token: str) -> bool:
        candidate = str(token or "")
        return bool(_PLACEHOLDER_TOKEN_RE.search(candidate))

    @staticmethod
    def _normalize_literal_token(token: str) -> str:
        value = str(token or "").strip()
        if not value:
            return ""
        if value.endswith(":") and len(value) > 1:
            value = value[:-1]
        return value.lower()

    def parse(self, command_str: str) -> str:
        tokenized = tokenize_command(command_str)
        if not tokenized.tokens:
            return ""

        tokens = self._normalize_input_tokens(list(tokenized.tokens))
        if not tokens:
            return ""

        root = tokens[0].lower()
        handler = self._root_handlers.get(root, self._parse_generic)
        return handler(tokens)

    @staticmethod
    def _normalize_input_tokens(tokens: list[str]) -> list[str]:
        normalized: list[str] = []
        for idx, token in enumerate(tokens):
            current = str(token)
            if current.endswith(":") and len(current) > 1 and idx < len(tokens) - 1:
                normalized.append(current[:-1])
                continue
            normalized.append(current)
        return normalized

    def _parse_target(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_schedule(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_clear(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_show(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_set(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_delete(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_debug(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_find(self, tokens: list[str]) -> str:
        return self._parse_generic(tokens)

    def _parse_request(self, tokens: list[str]) -> str:
        tokens = self._normalize_request_tokens(tokens)
        return self._parse_generic(tokens)

    def _normalize_request_tokens(self, tokens: list[str]) -> list[str]:
        if not self.infer_request_system_software_version:
            return tokens

        lowered = [token.lower() for token in tokens]
        if len(tokens) == 5 and lowered[:4] in (
            ["request", "system", "software", "download"],
            ["request", "system", "software", "install"],
        ):
            if _VERSION_RE.match(tokens[4]):
                return tokens[:4] + ["version", tokens[4]]
        return tokens

    def _parse_generic(self, tokens: list[str]) -> str:
        xml_parts: list[str] = []
        stack: list[str] = []
        path: list[str] = []
        root = tokens[0].lower() if tokens else ""

        idx = 0
        while idx < len(tokens):
            token = tokens[idx]
            token_lower = token.lower()
            xml_token = self._resolve_runtime_xml_tag(token=token, root=root)

            if xml_token is None:
                xml_parts.append(xml_escape(token))
                idx += 1
                continue

            if self._should_emit_leaf(tokens=tokens, index=idx, path=path, root=root):
                value = tokens[idx + 1]
                xml_parts.append(self._xml_leaf(xml_token, value))
                path.append(token_lower)
                idx += 2
                continue

            xml_parts.append(self._xml_open(xml_token))
            stack.append(xml_token)
            path.append(token_lower)
            idx += 1

        while stack:
            xml_parts.append(self._xml_close(stack.pop()))

        return "".join(xml_parts)

    def _should_emit_leaf(
        self,
        tokens: list[str],
        index: int,
        path: list[str],
        root: str,
    ) -> bool:
        if index + 1 >= len(tokens):
            return False

        token = tokens[index]
        token_lower = token.lower()
        next_token = tokens[index + 1]

        if next_token.startswith("$"):
            return True
        if not is_xml_tag_name(next_token):
            return True

        candidate_path = tuple(path + [token_lower])
        if candidate_path in self.knowledge.value_key_paths:
            return True

        # Fallback for environments where command-tree knowledge is unavailable
        # (for example package/runtime path mismatch): preserve common PAN-OS
        # leaf-value forms such as `show interface all`.
        is_terminal_value = (index + 2) == len(tokens)
        if is_terminal_value:
            hinted_values = self._TERMINAL_LEAF_VALUE_HINTS.get(token_lower, frozenset())
            if next_token.lower() in hinted_values:
                return True

        # Fallback for incomplete/partial path matches: use root-level key statistics
        # only when token is not ambiguous for that root.
        if index == 0:
            return False

        root_value_keys = self.knowledge.root_value_keys.get(root, frozenset())
        root_ambiguous_keys = self.knowledge.root_ambiguous_keys.get(root, frozenset())
        if token_lower in root_value_keys and token_lower not in root_ambiguous_keys:
            return True

        return False

    def _resolve_runtime_xml_tag(self, token: str, root: str) -> str | None:
        if is_xml_tag_name(token):
            return token

        token_lower = token.lower()
        root_literals = self.knowledge.root_literal_tokens.get(root, frozenset())
        if token_lower not in root_literals:
            return None

        return self._normalize_to_xml_tag_name(token)

    @staticmethod
    def _normalize_to_xml_tag_name(token: str) -> str:
        candidate = str(token).replace("+", "-plus-")
        candidate = re.sub(r"[^A-Za-z0-9_.-]+", "-", candidate).strip("-")
        if not candidate:
            return "item"
        if re.match(r"^[A-Za-z_]", candidate):
            return candidate
        return f"item-{candidate}"
