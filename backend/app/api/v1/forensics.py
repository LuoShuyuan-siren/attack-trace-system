from fastapi import APIRouter, Query, Response

from app.services.forensics_enrichment import (
    build_c2_infrastructure,
    build_process_tree,
    build_report,
    extract_attacker_fingerprint,
    match_apt_profiles,
)
from app.services.runtime_store import DETECTIONS, EVENTS
from app.services.report_export import render_report_markdown
from app.services.tracing_service import build_trace_result
from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.llm import create_llm_client

router = APIRouter()


@router.get("/agent-analysis")
def get_agent_analysis(enabled: bool = Query(True)) -> dict[str, object]:
    """Run the bounded multi-agent review over the current evidence graph."""
    orchestrator = TraceAgentOrchestrator(
        llm=create_llm_client(),
        enabled=enabled,
    )
    return orchestrator.analyze(EVENTS, DETECTIONS)


@router.get("/process-tree")
def get_process_tree() -> dict[str, object]:
    return build_process_tree(EVENTS)


@router.get("/attribution")
def get_attribution(
    enrich: bool = Query(False, description="查询 WHOIS/RDAP/Passive DNS 外部情报"),
) -> dict[str, object]:
    return {
        "apt_matches": match_apt_profiles(EVENTS, DETECTIONS),
        "attacker_fingerprint": extract_attacker_fingerprint(EVENTS, DETECTIONS),
        "c2_infrastructure": build_c2_infrastructure(EVENTS, enrich=enrich),
    }


@router.get("/report")
def get_report(
    enrich_c2: bool = Query(False, description="将外部 C2 情报写入报告"),
) -> dict[str, object]:
    trace = build_trace_result()
    return build_report(trace, EVENTS, DETECTIONS, enrich_c2=enrich_c2)


@router.get("/report/markdown")
def get_report_markdown(
    enrich_c2: bool = Query(False, description="将外部 C2 情报写入报告"),
) -> Response:
    trace = build_trace_result()
    report = build_report(trace, EVENTS, DETECTIONS, enrich_c2=enrich_c2)
    return Response(
        content=render_report_markdown(report),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=attack-trace-report.md"},
    )
