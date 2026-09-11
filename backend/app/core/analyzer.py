from abc import ABC, abstractmethod

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class BaseAnalyzer(ABC):
    """所有安全分析模块的统一接口"""

    @property
    @abstractmethod
    def name(self) -> str:
        """分析器名称"""
        raise NotImplementedError

    @abstractmethod
    def analyze(
        self,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """
        分析标准化安全事件并返回检测结果。

        Args:
            events: 统一格式的安全事件列表。

        Returns:
            检测结果列表。
        """
        raise NotImplementedError