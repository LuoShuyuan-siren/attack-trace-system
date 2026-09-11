from __future__ import annotations

import argparse

from app.collectors.agent import CollectorAgent


def main() -> None:
    parser = argparse.ArgumentParser(description="Attack Trace System collector agent")
    parser.add_argument("--backend-url", default="http://127.0.0.1:8000/api/v1/agent/events")
    parser.add_argument("--agent-id")
    parser.add_argument("--cache", default="collector-events.jsonl")
    parser.add_argument("--watch-path", action="append", default=[])
    parser.add_argument("--linux-system-log")
    parser.add_argument("--ebpf-jsonl", help="增量读取 eBPF JSONL 传感器输出")
    parser.add_argument("--windows-realtime", action="store_true", help="轮询 Sysmon/Security ETW-backed event channels")
    parser.add_argument("--windows-state", help="持久化 Windows EventRecordID 游标")
    parser.add_argument("--windows-native", action="store_true", help="使用 pywin32 EvtSubscribe 原生事件订阅")
    parser.add_argument("--packet-interface", help="启用网卡实时抓包，例如 Ethernet")
    parser.add_argument("--packet-timeout", type=int, default=2)
    parser.add_argument("--no-clock-calibration", action="store_true", help="不采集本机时间同步状态")
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--replay-cache", action="store_true")
    args = parser.parse_args()

    agent = CollectorAgent(
        agent_id=args.agent_id,
        backend_url=args.backend_url,
        cache_path=args.cache,
        watch_paths=args.watch_path,
        linux_system_log=args.linux_system_log,
        ebpf_jsonl=args.ebpf_jsonl,
        enable_windows_realtime=args.windows_realtime,
        windows_state_path=args.windows_state,
        enable_windows_native_subscription=args.windows_native,
        packet_interface=args.packet_interface,
        packet_timeout=args.packet_timeout,
        enable_clock_calibration=not args.no_clock_calibration,
    )
    if args.replay_cache:
        print(f"replayed_events={agent.replay_cache()}")
        return
    if args.once:
        events = agent.collect_once()
        agent.append_cache(events)
        accepted = agent.send(events)
        print(f"collected_events={len(events)} sent={accepted}")
        return
    agent.run(interval_seconds=args.interval)


if __name__ == "__main__":
    main()
