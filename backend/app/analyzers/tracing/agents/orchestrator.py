from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Callable

from app.analyzers.tracing.agents.attribution_agent import AttributionAgent
from app.analyzers.tracing.agents.base_agent import LLMClient
from app.analyzers.tracing.agents.chain_review_agent import ChainReviewAgent
from app.analyzers.tracing.agents.evidence_agent import EvidenceAgent
from app.analyzers.tracing.agents.models import AgentStatus, TraceContext
from app.analyzers.tracing.agents.report_agent import ReportAgent
from app.analyzers.tracing.trace_service import AttackTraceService
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class TraceAgentOrchestrator:
    def __init__(
        self, llm: LLMClient | None = None, *, enabled: bool = True,
        top_k_paths: int = 5, max_edges: int = 100, max_nodes: int = 100,
        trace_service: AttackTraceService | None = None,
    ) -> None:
        self.enabled = enabled
        self.top_k_paths = max(1, top_k_paths)
        self.max_edges = max(1, max_edges)
        self.max_nodes = max(1, max_nodes)
        self.trace_service = trace_service or AttackTraceService()
        self.evidence_agent = EvidenceAgent(llm)
        self.chain_agent = ChainReviewAgent(llm)
        self.attribution_agent = AttributionAgent(llm)
        self.report_agent = ReportAgent(llm)

    def analyze(
        self, events: Iterable[NormalizedEvent],
        detections: Iterable[DetectionResult] = (), *, graph_id: str = "graph-current",
    ) -> dict[str, Any]:
        event_list = list(events)
        detection_list = list(detections)
        trace = self.trace_service.analyze(event_list, detection_list, graph_id=graph_id)
        trace_payload = {
            "graph": trace["graph"], "stages": trace["stages"],
            "paths": trace["paths"], "diagnostics": dict(self.trace_service.last_diagnostics),
        }
        if not self.enabled:
            return {
                "trace": trace_payload,
                "agent_analysis": {},
                "agent_status": AgentStatus(enabled=False, degraded=False).model_dump(),
            }
        context = self._context(
            trace_payload,
            valid_event_ids={event.event_id for event in event_list},
            valid_detection_ids={item.detection_id for item in detection_list},
        )
        errors: list[str] = []
        evidence = self._safe("evidence_agent", self.evidence_agent.analyze, self.evidence_agent.fallback, context, errors)
        chain = self._safe("chain_review_agent", self.chain_agent.analyze, self.chain_agent.fallback, context, errors)
        attribution = self._safe("attribution_agent", self.attribution_agent.analyze, self.attribution_agent.fallback, context, errors)
        try:
            report = self.report_agent.analyze(context, evidence, chain, attribution)
        except Exception as exc:
            errors.append(f"report_agent: {type(exc).__name__}: {exc}")
            report = self.report_agent.fallback(context, evidence, chain, attribution)
        return {
            "trace": trace_payload,
            "agent_analysis": {
                "evidence": evidence.model_dump(mode="json"),
                "chain_review": chain.model_dump(mode="json"),
                "attribution": attribution.model_dump(mode="json"),
                "report": report.model_dump(mode="json"),
            },
            "agent_status": AgentStatus(
                enabled=True, degraded=bool(errors), errors=errors
            ).model_dump(),
        }

    @staticmethod
    def _safe(name: str, call: Callable, fallback: Callable, context, errors):
        try:
            return call(context)
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            return fallback(context)

    def _context(
        self,
        trace: dict[str, Any],
        *,
        valid_event_ids: set[str] | None = None,
        valid_detection_ids: set[str] | None = None,
    ) -> TraceContext:
        graph = trace["graph"]
        valid_event_ids = valid_event_ids or set()
        valid_detection_ids = valid_detection_ids or set()
        paths = []
        for candidate in trace["paths"][: self.top_k_paths]:
            path = dict(candidate)
            path["related_event_ids"] = [
                item for item in candidate.get("related_event_ids", [])
                if item in valid_event_ids
            ]
            path["related_detection_ids"] = [
                item for item in candidate.get("related_detection_ids", [])
                if item in valid_detection_ids
            ]
            paths.append(path)
        path_edge_ids = {edge_id for path in paths for edge_id in path.get("edges", [])}
        ordered_edges = sorted(
            graph.edges, key=lambda edge: (edge.edge_id not in path_edge_ids, -edge.confidence)
        )[: self.max_edges]
        referenced_nodes = {value for edge in ordered_edges for value in (edge.source, edge.target)}
        ordered_nodes = sorted(
            graph.nodes, key=lambda node: (node.node_id not in referenced_nodes, node.node_id)
        )[: self.max_nodes]
        event_ids = list(dict.fromkeys(
            item for edge in ordered_edges for item in edge.related_event_ids
            if item in valid_event_ids
        ))
        detection_ids = list(dict.fromkeys(
            item for edge in ordered_edges for item in edge.related_detection_ids
            if item in valid_detection_ids
        ))
        techniques = list(dict.fromkeys(
            edge.attack_technique_id for edge in ordered_edges if edge.attack_technique_id
        ))
        indicators = [
            node.node_id for node in ordered_nodes if node.node_type in {"ip", "domain"}
        ]
        stages = [
            {
                **stage,
                "related_event_ids": [
                    item for item in stage.get("related_event_ids", [])
                    if item in valid_event_ids
                ],
                "related_detection_ids": [
                    item for item in stage.get("related_detection_ids", [])
                    if item in valid_detection_ids
                ],
            }
            for stage in trace["stages"]
        ]
        return TraceContext(
            graph_summary={
                "graph_id": graph.graph_id,
                "nodes": [node.model_dump(mode="json") for node in ordered_nodes],
                "edges": [
                    {
                        **edge.model_dump(mode="json"),
                        "related_event_ids": [
                            item for item in edge.related_event_ids
                            if item in valid_event_ids
                        ],
                        "related_detection_ids": [
                            item for item in edge.related_detection_ids
                            if item in valid_detection_ids
                        ],
                    }
                    for edge in ordered_edges
                ],
                "truncated": len(graph.nodes) > len(ordered_nodes) or len(graph.edges) > len(ordered_edges),
            },
            attack_stages=stages, candidate_paths=paths,
            diagnostics=trace["diagnostics"], related_event_ids=event_ids,
            related_detection_ids=detection_ids,
            edge_ids=[edge.edge_id for edge in ordered_edges],
            attack_technique_ids=techniques,
            tags=sorted({tag for node in ordered_nodes for tag in node.tags}),
            indicators=indicators,
        )
