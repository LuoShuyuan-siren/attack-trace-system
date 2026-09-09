"""Validate Member 3 Linux normalized events against the shared schema."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from app.schemas.event import NormalizedEvent


EXAMPLES_DIR = Path(__file__).resolve().parent
INPUT_FILE = EXAMPLES_DIR / "member3_linux_tc003_normalized_events.json"
OUTPUT_FILE = EXAMPLES_DIR / "member3_linux_tc003_normalized_events_summary.json"


def main() -> None:
    raw_items = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    events = [NormalizedEvent.model_validate(item) for item in raw_items]

    summary = {
        "total_events": len(events),
        "source_type": "host_log",
        "sources": dict(Counter(event.source for event in events)),
        "event_types": dict(Counter(event.event_type for event in events)),
        "hosts": dict(Counter(event.host.hostname for event in events)),
        "severities": dict(Counter(event.severity for event in events)),
        "start_time": min(event.timestamp for event in events).isoformat(),
        "end_time": max(event.timestamp for event in events).isoformat(),
        "schema_valid": True,
        "ready_for_member7": True,
    }

    OUTPUT_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"total={len(events)} event_types={len(summary['event_types'])} hosts={len(summary['hosts'])}")


if __name__ == "__main__":
    main()
