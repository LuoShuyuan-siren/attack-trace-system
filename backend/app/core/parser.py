from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal

from app.schemas.event import NormalizedEvent


SourceType = Literal[
    "host_log",
    "host_behavior",
    "network_traffic",
]


class BaseParser(ABC):
    """所有原始安全数据解析器的统一接口"""

    @property
    @abstractmethod
    def name(self) -> str:
        """解析器名称"""
        raise NotImplementedError

    @property
    @abstractmethod
    def source_type(self) -> SourceType:
        """解析器所属的数据源类型"""
        raise NotImplementedError

    @abstractmethod
    def parse(
        self,
        source: Path,
    ) -> list[NormalizedEvent]:
        """
        将原始数据解析并转换为统一安全事件。

        Args:
            source: 原始数据文件或目录路径。

        Returns:
            标准化安全事件列表。
        """
        raise NotImplementedError