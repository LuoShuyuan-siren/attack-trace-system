from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import NormalizedEvent


class ParserService:
    """统一管理和调用原始数据解析器"""

    def __init__(self) -> None:
        self._parsers: dict[str, BaseParser] = {}

    def register(self, parser: BaseParser) -> None:
        """注册解析器"""
        self._parsers[parser.name] = parser

    def get_parser(self, name: str) -> BaseParser:
        """根据名称获取解析器"""

        parser = self._parsers.get(name)

        if parser is None:
            raise ValueError(f"Parser not found: {name}")

        return parser

    def parse(
        self,
        parser_name: str,
        source: Path,
    ) -> list[NormalizedEvent]:
        """调用指定解析器处理原始数据"""

        parser = self.get_parser(parser_name)

        return parser.parse(source)