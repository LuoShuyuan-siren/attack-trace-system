"""Run tracing against sanitized normalized JSON arrays."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.analyzers.tracing import AttackTraceService
from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.llm import create_llm_client
from tests.fixtures.load_tracing_data import load_detections, load_events


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", action="append", required=True)
    parser.add_argument("--detections", action="append", default=[])
    parser.add_argument("--agents", action="store_true")
    args = parser.parse_args()
    events = [item for path in args.events for item in load_events(path)]
    detections = [
        item for path in args.detections for item in load_detections(path)
    ]
    service = AttackTraceService()
    result = service.analyze(events, detections, graph_id="graph-integration")
    graph = result["graph"]
    summary = {
        "input_events": len(events),
        "input_detections": len(detections),
        **service.last_diagnostics,
        "node_count": len(graph.nodes),
        "edge_count": len(graph.edges),
        "stage_count": len(result["stages"]),
        "candidate_path_count": len(result["paths"]),
        "top_path_score": result["paths"][0]["score"] if result["paths"] else None,
    }
    for key, value in summary.items():
        print(f"{key}={value}")
    if args.agents:
        agent_result = TraceAgentOrchestrator(
            llm=create_llm_client(), enabled=True, trace_service=service
        ).analyze(events, detections, graph_id="graph-integration")
        status = agent_result["agent_status"]
        analysis = agent_result["agent_analysis"]
        print(f"agent_enabled={status['enabled']}")
        print(f"agent_degraded={status['degraded']}")
        print(f"chain_status={analysis['chain_review']['status']}")
        print(f"evidence_confidence={analysis['evidence']['overall_confidence']}")
        print(f"attribution_confidence={analysis['attribution']['confidence']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
