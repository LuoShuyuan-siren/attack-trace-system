import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from backend.app.parsers.windows_parser import WindowsLogParser


def serialize_event(e):
    """安全序列化事件对象为 dict"""
    if hasattr(e, "model_dump"):
        return e.model_dump(mode="json")
    elif isinstance(e, dict):
        return dict(e)
    return getattr(e, "__dict__", str(e))


def main():
    evtx_file_path = Path("C:/Users/pulin/Desktop/en/work/test_data/test.evtx")
    parser = WindowsLogParser()

    print(f"正在测试解析器: {parser.name}")

    try:
        results = parser.parse(evtx_file_path)
        total_count = len(results)

        known_events = [e for e in results if e.action != "unknown"]
        known_count = len(known_events)
        coverage_rate = (known_count / total_count * 100) if total_count > 0 else 0

        event_type_counter = Counter(e.event_type for e in results)

        print("\n================== 组长重构标准验收报告 ==================")
        print(f"日志总数: {total_count} 条")
        print(f"精准识别行为日志: {known_count} 条")
        print(f"规则覆盖率: {coverage_rate:.2f}%")
        print("\n【 事件类型Top分布 】")
        for event_type, count in event_type_counter.most_common(8):
            print(f"  - {event_type}: {count} 条 ({count/total_count*100:.1f}%)")
        print("==================================================")

        assert coverage_rate > 90, f"覆盖率未达到合格要求 (>90%)，当前为 {coverage_rate:.2f}%"
        print("\n[Pass] 覆盖率测试通过！")

        system_sessions = [e for e in results if e.event_type == "system_session_start"]
        if system_sessions:
            print(f"[Pass] 成功分离出系统服务后台会话 {len(system_sessions)} 条！")

        # ---------------------------------------------------------
        # 1. 生成给陈艺丹的数据 (20条)
        # ---------------------------------------------------------
        yidan_samples = []
        seen_types = set()

        for e in known_events:
            has_detail = (e.get("object") is not None) or (e.get("network") is not None)
            if has_detail and e.event_type not in seen_types:
                yidan_samples.append(e)
                seen_types.add(e.event_type)

        for e in known_events:
            if e.event_type not in seen_types:
                yidan_samples.append(e)
                seen_types.add(e.event_type)
            if len(yidan_samples) >= 20:
                break

        if len(yidan_samples) < 20:
            for e in known_events:
                if e not in yidan_samples:
                    yidan_samples.append(e)
                if len(yidan_samples) >= 20:
                    break

        yidan_data = [serialize_event(e) for e in yidan_samples]
        yidan_file = PROJECT_ROOT / "for_yidan_member2.json"
        with open(yidan_file, "w", encoding="utf-8") as f:
            json.dump(yidan_data, f, ensure_ascii=False, indent=2)

        # ---------------------------------------------------------
        # 2. 生成给张梓桐的数据 (5条)
        # ---------------------------------------------------------
        zitong_samples = []
        priority_types = [
            "process_create",
            "credential_read",
            "user_login",
            "privilege_assigned",
            "group_enumeration",
        ]

        for p_type in priority_types:
            for e in known_events:
                if e.event_type == p_type and e not in zitong_samples:
                    zitong_samples.append(e)
                    break
            if len(zitong_samples) >= 5:
                break

        if len(zitong_samples) < 5:
            for e in known_events:
                if e not in zitong_samples:
                    zitong_samples.append(e)
                if len(zitong_samples) >= 5:
                    break

        zitong_data = [serialize_event(e) for e in zitong_samples]
        zitong_file = PROJECT_ROOT / "for_zitong_member2.json"
        with open(zitong_file, "w", encoding="utf-8") as f:
            json.dump(zitong_data, f, ensure_ascii=False, indent=2)

        # 格式化输出最终路径
        print(f"\n[数据生成成功] 给陈艺丹的数据 ({len(yidan_samples)}条): {yidan_file.resolve()}")
        print(f"[数据生成成功] 给张梓桐的数据 ({len(zitong_samples)}条): {zitong_file.resolve()}")

    except Exception as e:
        print(f"\n测试失败: {e}")


if __name__ == "__main__":
    main()