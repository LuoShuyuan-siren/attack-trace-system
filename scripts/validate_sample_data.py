"""校验 docs/sample_data.json 与 docs/sample_data_array.*.json 数据完整性。

校验维度：
  1. Pydantic schema 校验（NormalizedEvent / DetectionResult）
  2. detection.related_event_ids 全部能在 normalized_events 中解析
  3. C2 / 外传 / 扫描场景事件必须带 host.hostname 和 subject.name
  4. 关键告警（含 C2 / 外传 / 扫描 / DNS 隧道 / ICMP 隧道 / HTTP 隐蔽信道）必须带
     related_entity_ids
  5. summary.total_events 与 normalized_events 实际数量一致

退出码：0 = 全部通过；1 = 存在失败。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.schemas.detection import DetectionResult  # noqa: E402
from app.schemas.event import NormalizedEvent  # noqa: E402


# C2 / 外传 / 扫描相关 src_ip（在 generate_samples.py 的多个 scenario 里用到）
ATTACK_SRC_IPS: set[str] = {
    "192.168.1.100",  # DNS 隧道 / HTTP Beacon / ICMP 隧道出站
    "192.168.1.50",   # HTTP 可疑 + 大上传（外传）
    "192.168.1.66",   # 端口扫描
    "203.0.113.20",   # C2 基础设施（ICMP 隧道入站）
}

# 关键告警关键词：这些告警必须带 related_entity_ids
CRITICAL_DETECTION_KEYWORDS: tuple[str, ...] = (
    "DNS 隧道",
    "HTTP Beacon",
    "HTTP 隐蔽信道",
    "ICMP 隧道",
    "端口扫描",
    "Beacon 通信",
)


def _schema_check(events: list[dict], detections: list[dict]) -> list[str]:
    errs: list[str] = []
    for e in events:
        try:
            NormalizedEvent.model_validate(e)
        except Exception as ex:
            errs.append(f"event schema fail {e.get('event_id')[:12]}: {ex}")
    for d in detections:
        try:
            DetectionResult.model_validate(d)
        except Exception as ex:
            errs.append(f"detection schema fail {d.get('detection_id')[:12]}: {ex}")
    return errs


def _reference_closure(events: list[dict], detections: list[dict]) -> list[str]:
    errs: list[str] = []
    ev_ids = {e["event_id"] for e in events}
    for d in detections:
        miss = [x for x in d.get("related_event_ids", []) if x not in ev_ids]
        if miss:
            errs.append(
                f"detection {d.get('detection_id')[:12]} ({d.get('analyzer')}) "
                f"unresolved related_event_ids: {len(miss)} (sample: {miss[:2]})"
            )
    return errs


def _c2_exfil_host_subject(events: list[dict]) -> list[str]:
    """C2 / 外传 / 扫描场景事件必须带 host.hostname 与 subject.name。"""
    errs: list[str] = []
    for e in events:
        net = e.get("network") or {}
        if net.get("src_ip") not in ATTACK_SRC_IPS:
            continue
        host = e.get("host") or {}
        subj = e.get("subject") or {}
        if not host.get("hostname"):
            errs.append(
                f"event {e['event_id'][:12]} src={net.get('src_ip')} "
                f"type={e.get('event_type')} 缺 host.hostname"
            )
        if not subj.get("name"):
            errs.append(
                f"event {e['event_id'][:12]} src={net.get('src_ip')} "
                f"type={e.get('event_type')} 缺 subject.name"
            )
    return errs


def _critical_entity_refs(detections: list[dict]) -> list[str]:
    """关键告警必须带 related_entity_ids（用于跨源关联）。"""
    errs: list[str] = []
    for d in detections:
        title = d.get("title", "")
        if not any(kw in title for kw in CRITICAL_DETECTION_KEYWORDS):
            continue
        if not d.get("related_entity_ids"):
            errs.append(
                f"detection {d.get('detection_id')[:12]} "
                f"[{d.get('analyzer')}] {title[:36]} 缺 related_entity_ids"
            )
    return errs


def _summary_consistency(data: dict, events: list[dict]) -> list[str]:
    errs: list[str] = []
    summary_total = data.get("summary", {}).get("total_events")
    if summary_total is not None and summary_total != len(events):
        errs.append(
            f"summary.total_events={summary_total} != len(normalized_events)={len(events)}"
        )
    return errs


def validate(doc: dict, *, label: str) -> list[str]:
    events = doc.get("normalized_events", [])
    detections = doc.get("detection_results", [])
    errs: list[str] = []
    errs += [f"[{label}] " + x for x in _schema_check(events, detections)]
    errs += [f"[{label}] " + x for x in _reference_closure(events, detections)]
    errs += [f"[{label}] " + x for x in _c2_exfil_host_subject(events)]
    errs += [f"[{label}] " + x for x in _critical_entity_refs(detections)]
    errs += [f"[{label}] " + x for x in _summary_consistency(doc, events)]
    return errs


def validate_array_files(
    events_path: Path,
    detections_path: Path,
    *,
    label: str,
) -> list[str]:
    events = json.loads(events_path.read_text(encoding="utf-8"))
    detections = json.loads(detections_path.read_text(encoding="utf-8"))
    if not isinstance(events, list) or not isinstance(detections, list):
        return [f"[{label}] 顶层必须是数组 (events={type(events).__name__}, detections={type(detections).__name__})"]
    # 拼成 {"normalized_events": ..., "detection_results": ...} 复用 validate
    synthetic = {
        "normalized_events": events,
        "detection_results": detections,
        "summary": {},  # array 模式无 summary，跳过 summary 一致性
    }
    errs: list[str] = []
    errs += [f"[{label}] " + x for x in _schema_check(events, detections)]
    errs += [f"[{label}] " + x for x in _reference_closure(events, detections)]
    errs += [f"[{label}] " + x for x in _c2_exfil_host_subject(events)]
    errs += [f"[{label}] " + x for x in _critical_entity_refs(detections)]
    return errs


def main() -> int:
    docs = ROOT / "docs"
    wrapped = json.loads((docs / "sample_data.json").read_text(encoding="utf-8"))
    ev_array_path = docs / "sample_data_array.normalized_events.json"
    det_array_path = docs / "sample_data_array.detection_results.json"

    print("=" * 60)
    print("VALIDATE: docs/sample_data.json (wrapper)")
    print("=" * 60)
    errs_wrapped = validate(wrapped, label="wrapped")
    if errs_wrapped:
        for e in errs_wrapped:
            print("  FAIL:", e)
    else:
        print("  OK")

    print()
    print("=" * 60)
    print(f"VALIDATE: {ev_array_path.name} + {det_array_path.name} (array)")
    print("=" * 60)
    errs_array = validate_array_files(
        ev_array_path, det_array_path, label="array"
    )
    if errs_array:
        for e in errs_array:
            print("  FAIL:", e)
    else:
        print("  OK")

    all_errs = errs_wrapped + errs_array
    print()
    print(f"汇总: {len(all_errs)} 项失败")
    return 1 if all_errs else 0


if __name__ == "__main__":
    sys.exit(main())
