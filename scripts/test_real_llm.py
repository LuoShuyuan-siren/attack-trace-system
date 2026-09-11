"""Manual smoke test. This file is not part of the default pytest suite."""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.llm import create_llm_client
from app.schemas.detection import DetectionResult


def main() -> int:
    if os.getenv("LLM_ENABLED", "false").lower() not in {"1", "true", "yes", "on"}:
        print("Skipped: set LLM_ENABLED=true and configure the LLM environment variables.")
        return 0
    llm = create_llm_client()
    if llm is None:
        print("Skipped: LLM configuration is incomplete or unsupported.")
        return 0
    detections = [
        DetectionResult(
            detection_id="det-smoke-initial", timestamp="2026-09-08T10:00:00Z",
            analyzer="smoke", detection_type="malicious_behavior",
            title="Initial access", confidence=0.9,
            related_event_ids=["evt-smoke-initial"],
            related_entity_ids=["ip:203.0.113.8", "host:WEB01"],
            attack_technique_id="T1190", tags=["initial_access"],
        ),
        DetectionResult(
            detection_id="det-smoke-c2", timestamp="2026-09-08T10:05:00Z",
            analyzer="smoke", detection_type="malicious_behavior",
            title="C2", confidence=0.9,
            related_event_ids=["evt-smoke-c2"],
            related_entity_ids=["host:WEB01", "ip:8.8.8.8"],
            attack_technique_id="T1071.001", tags=["c2_communication"],
        ),
    ]
    result = TraceAgentOrchestrator(llm=llm, enabled=True).analyze([], detections)
    status = result["agent_status"]
    print(f"enabled={status['enabled']} degraded={status['degraded']}")
    if status["errors"]:
        print("errors:", *status["errors"], sep="\n- ")
        return 1
    print("Validated EvidenceAgent, ChainReviewAgent, AttributionAgent and ReportAgent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
