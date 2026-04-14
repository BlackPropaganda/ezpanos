from __future__ import annotations

from xml.sax.saxutils import escape as xml_escape

from ezpanos.command_parser.interfaces.parser_interface import CommandParserInterface
from ezpanos.command_parser.models.command_model import ParserKnowledge


class BaseCommandParser(CommandParserInterface):
    def __init__(self, knowledge: ParserKnowledge):
        self.knowledge = knowledge

    @staticmethod
    def _xml_leaf(tag: str, value: str) -> str:
        return f"<{tag}>{xml_escape(str(value))}</{tag}>"

    @staticmethod
    def _xml_open(tag: str) -> str:
        return f"<{tag}>"

    @staticmethod
    def _xml_close(tag: str) -> str:
        return f"</{tag}>"
