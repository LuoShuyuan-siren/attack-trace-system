from app.core.analyzer import BaseAnalyzer
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class AnalyzerService:
    """统一管理和调用安全分析器"""

    def __init__(self) -> None:
        self._analyzers: list[BaseAnalyzer] = []

    def register(self, analyzer: BaseAnalyzer) -> None:
        """注册分析器"""
        self._analyzers.append(analyzer)

    def analyze(
        self,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """依次调用所有已注册分析器"""

        results: list[DetectionResult] = []

        for analyzer in self._analyzers:
            analyzer_results = analyzer.analyze(events)
            results.extend(analyzer_results)

        return results