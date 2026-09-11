"""Minimal BCC tracepoint sensor for Linux syscall telemetry.

Run as root on a Linux host with python3-bcc installed. The output is JSONL
and is intentionally compatible with LinuxRealtimeCollector.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct event_t {
    u32 pid;
    u32 uid;
    u64 syscall_id;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    char comm[16];
    char text[128];
    u16 peer_family;
    u16 peer_port;
    u8 peer_addr[16];
};

BPF_PERF_OUTPUT(events);

static int emit_event(void *ctx, u64 syscall_id, u64 a0, u64 a1, u64 a2, u64 a3) {
    struct event_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.syscall_id = syscall_id;
    event.arg0 = a0;
    event.arg1 = a1;
    event.arg2 = a2;
    event.arg3 = a3;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    // The argument positions are shared, syscall IDs differ by architecture.
#ifdef ATTACK_TRACE_ARM64
    if (syscall_id == 221) {
        bpf_probe_read_user_str(&event.text, sizeof(event.text), (void *)a0);
    } else if (syscall_id == 56) {
        bpf_probe_read_user_str(&event.text, sizeof(event.text), (void *)a1);
    } else if (syscall_id == 203) {
        bpf_probe_read_user(&event.peer_family, sizeof(event.peer_family), (void *)a1);
        bpf_probe_read_user(&event.peer_port, sizeof(event.peer_port), (void *)(a1 + 2));
        bpf_probe_read_user(&event.peer_addr, sizeof(event.peer_addr), (void *)(a1 + 4));
#else
    if (syscall_id == 59) {
        bpf_probe_read_user_str(&event.text, sizeof(event.text), (void *)a0);
    } else if (syscall_id == 257) {
        bpf_probe_read_user_str(&event.text, sizeof(event.text), (void *)a1);
    } else if (syscall_id == 42) {
        bpf_probe_read_user(&event.peer_family, sizeof(event.peer_family), (void *)a1);
        bpf_probe_read_user(&event.peer_port, sizeof(event.peer_port), (void *)(a1 + 2));
        bpf_probe_read_user(&event.peer_addr, sizeof(event.peer_addr), (void *)(a1 + 4));
#endif
    }
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    return emit_event(args, args->id, args->args[0], args->args[1], args->args[2], args->args[3]);
}
"""

# Common x86_64 syscall IDs. Unknown IDs remain numeric in output.
SYSCALL_NAMES_BY_ARCH = {
    "x86_64": {
    9: "mmap",
    10: "mprotect",
    42: "connect",
    56: "clone",
    57: "fork",
    59: "execve",
    257: "openat",
    319: "memfd_create",
    310: "process_vm_writev",
    101: "ptrace",
    },
    "aarch64": {
        56: "openat",
        63: "read",
        64: "write",
        93: "exit",
        117: "ptrace",
        203: "connect",
        220: "clone",
        221: "execve",
        222: "mmap",
        226: "mprotect",
        270: "process_vm_writev",
        279: "memfd_create",
    },
}


def normalize_arch(value: str | None = None) -> str:
    value = (value or platform.machine()).lower()
    if value in {"aarch64", "arm64"}:
        return "aarch64"
    return "x86_64"


class Sensor:
    def __init__(self, output: Path, *, include_all: bool = False, arch: str | None = None) -> None:
        self.output = output
        self.include_all = include_all
        self.arch = normalize_arch(arch)
        self.running = True

    def run(self) -> None:
        try:
            from bcc import BPF
        except ImportError as exc:
            raise RuntimeError("python3-bcc is required to run the eBPF sensor") from exc

        self.output.parent.mkdir(parents=True, exist_ok=True)
        cflags = ["-DATTACK_TRACE_ARM64"] if self.arch == "aarch64" else []
        bpf = BPF(text=BPF_PROGRAM, cflags=cflags)

        def stop(_signum: int, _frame: Any) -> None:
            self.running = False

        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
        with self.output.open("a", encoding="utf-8", buffering=1) as stream:
            bpf["events"].open_perf_buffer(
                lambda cpu, data, size: self._handle_event(bpf["events"].event(data), stream)
            )
            while self.running:
                bpf.perf_buffer_poll(timeout=1000)

    def _handle_event(self, event: Any, stream: Any) -> None:
        syscall_names = SYSCALL_NAMES_BY_ARCH[self.arch]
        syscall = syscall_names.get(int(event.syscall_id), f"syscall_{int(event.syscall_id)}")
        if not self.include_all and syscall.startswith("syscall_"):
            return
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": socket.gethostname(),
            "arch": self.arch,
            "pid": int(event.pid),
            "uid": int(event.uid),
            "comm": bytes(event.comm).split(b"\0", 1)[0].decode(errors="replace"),
            "syscall": syscall,
            "syscall_id": int(event.syscall_id),
            "arguments": {
                "arg0": int(event.arg0),
                "arg1": int(event.arg1),
                "arg2": int(event.arg2),
                "arg3": int(event.arg3),
            },
            "action": syscall,
        }
        record.update(_process_context(int(event.pid)))
        path = bytes(event.text).split(b"\0", 1)[0].decode(errors="replace")
        if path:
            record["path"] = path
            record["arguments"]["path"] = path
        if syscall == "process_vm_writev":
            record["target_pid"] = int(event.arg0)
        elif syscall == "ptrace":
            record["target_pid"] = int(event.arg1)
        if syscall == "connect" and int(event.peer_family) in (2, 10):
            record["remote_ip"] = _decode_peer_ip(event)
            record["remote_port"] = socket.ntohs(int(event.peer_port))
        stream.write(json.dumps(record, ensure_ascii=True) + "\n")


def _decode_peer_ip(event: Any) -> str:
    family = int(event.peer_family)
    length = 4 if family == 2 else 16
    return socket.inet_ntop(family, bytes(event.peer_addr)[:length])


def _process_context(pid: int) -> dict[str, Any]:
    """Best-effort userspace enrichment for the short-lived syscall event."""
    proc = Path("/proc") / str(pid)
    context: dict[str, Any] = {}
    try:
        stat = (proc / "stat").read_text(encoding="utf-8").split()
        if len(stat) > 3:
            context["ppid"] = int(stat[3])
    except (OSError, ValueError, IndexError):
        pass
    try:
        context["exe"] = str((proc / "exe").resolve())
    except OSError:
        pass
    try:
        command_line = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
        if command_line:
            context["command_line"] = command_line
    except OSError:
        pass
    return context


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BCC eBPF syscall sensor")
    parser.add_argument("--output", default="/var/run/attack-trace/events.jsonl")
    parser.add_argument("--include-all", action="store_true", help="保留未知 syscall 编号")
    parser.add_argument("--arch", choices=("x86_64", "aarch64"), help="覆盖自动识别的 syscall 架构")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        Sensor(Path(args.output), include_all=args.include_all, arch=args.arch).run()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
