from __future__ import annotations

import re
import shlex

from ezpanos.command_parser.models.command_model import TokenizedCommand

_XML_TAG_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


def is_xml_tag_name(token: str) -> bool:
    return bool(_XML_TAG_RE.match(str(token)))


def tokenize_command(command_str: str) -> TokenizedCommand:
    raw = str(command_str or "")
    trimmed = raw.strip()
    if not trimmed:
        return TokenizedCommand(raw_command=raw, tokens=tuple())

    try:
        pieces = shlex.split(trimmed)
    except ValueError:
        pieces = trimmed.split()

    tokens = tuple(str(piece).strip() for piece in pieces if str(piece).strip())
    return TokenizedCommand(raw_command=raw, tokens=tokens)
